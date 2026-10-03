"""Private signed manifests and fsynced, crash-recoverable per-item journals."""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat

from .safety import SafetyError, ancestor_identity, canonical, directory_fd, json_bytes

SCHEMA = "mactrim.plan.v1"
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
JOURNAL_COMPLETION_RESERVE = 64 * 1024


class State:
    def __init__(self, path):
        self.path = canonical(path)
        self.key = None

    def prepare(self):
        # Each existing ancestor must already be a real directory. Create missing
        # components with a private mode without altering pre-existing directories.
        missing = []
        cursor = self.path
        while not cursor.exists() and not cursor.is_symlink():
            missing.append(cursor)
            cursor = cursor.parent
        ancestor_identity(cursor)
        for item in reversed(missing):
            with directory_fd(item.parent) as fd:
                os.mkdir(item.name, 0o700, dir_fd=fd)
                os.fsync(fd)
        self.verify()
        with directory_fd(self.path) as fd:
            try:
                key_fd = os.open("key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            except FileExistsError:
                key_fd = None
            if key_fd is not None:
                try:
                    os.write(key_fd, secrets.token_bytes(32))
                    os.fsync(key_fd)
                finally:
                    os.close(key_fd)
                os.fsync(fd)
            for name in ("journal", "quarantine"):
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
        self._private(self.path / "key", directory=False)
        for name in ("journal", "quarantine"):
            self._private(self.path / name, directory=True)
        with directory_fd(self.path) as fd:
            key_fd = os.open("key", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                self.key = os.read(key_fd, 33)
            finally:
                os.close(key_fd)
        if len(self.key) != 32:
            raise SafetyError("State signing key is invalid")
        return self

    def _private(self, path, directory):
        st = os.lstat(path)
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
            raise SafetyError("State must be owned by you with private 0700 directories / 0600 files: %s" % path)
        if not directory and st.st_nlink != 1:
            raise SafetyError("State files cannot be hard links")

    def verify(self):
        ancestor_identity(self.path)
        self._private(self.path, True)
        for name in ("journal", "quarantine"):
            if (self.path / name).exists() or (self.path / name).is_symlink():
                self._private(self.path / name, True)

    @contextlib.contextmanager
    def lock(self):
        self.verify()
        with directory_fd(self.path) as fd:
            lock_fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                self._private(self.path / "lock", False)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise SafetyError("Another MacTrim scan or mutation holds the state lock") from exc
                self.verify()
                yield
            finally:
                os.close(lock_fd)

    def sign(self, body):
        return {"body": body, "signature": hmac.new(self.key, json_bytes(body), hashlib.sha256).hexdigest()}

    def verify_signed(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
            raise SafetyError("Malformed signed document")
        signature = envelope["signature"]
        if not isinstance(signature, str) or not hmac.compare_digest(self.sign(envelope["body"])["signature"], signature):
            raise SafetyError("Document was altered, or belongs to a different MacTrim state")
        return envelope["body"]

    def journal_payload(self, record):
        payload = json_bytes(self.sign(record))
        reserve = JOURNAL_COMPLETION_RESERVE if record.get("status") == "pending" else 0
        if len(payload) + reserve > MAX_JOURNAL_BYTES:
            raise SafetyError("Journal exceeds recoverable size bound; no move is authorized")
        return payload

    def write_journal(self, record):
        self.verify()
        identifier = record["id"]
        if not isinstance(identifier, str) or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
            raise SafetyError("Invalid journal identity")
        payload = self.journal_payload(record)
        with directory_fd(self.path / "journal") as fd:
            temporary = ".%s.%s" % (identifier, secrets.token_hex(8))
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                offset = 0
                while offset < len(payload):
                    offset += os.write(out, payload[offset:])
                os.fsync(out)
            finally:
                os.close(out)
            os.replace(temporary, identifier + ".json", src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)

    def journals(self):
        self.verify()
        records = []
        with directory_fd(self.path / "journal") as fd:
            for name in sorted(os.listdir(fd)):
                if name.startswith("."):
                    continue  # interrupted temporary write; old committed state survives
                if not name.endswith(".json"):
                    raise SafetyError("Unexpected entry in journal directory")
                self._private(self.path / "journal" / name, False)
                record_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    with os.fdopen(record_fd, "rb") as stream:
                        payload = stream.read(MAX_JOURNAL_BYTES + 1)
                    if len(payload) > MAX_JOURNAL_BYTES:
                        raise SafetyError("Oversized journal")
                    record = self.verify_signed(json.loads(payload))
                except (ValueError, UnicodeError) as exc:
                    raise SafetyError("Malformed journal") from exc
                if record.get("id", "") + ".json" != name or record.get("schema") != "mactrim.journal.v1":
                    raise SafetyError("Journal identity/schema mismatch")
                records.append(record)
        return records


def load_manifest(path, state):
    try:
        with open(path, "rb") as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise SafetyError("Manifest exceeds 32 MiB")
        body = state.verify_signed(json.loads(data))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise SafetyError("Malformed manifest") from exc
    if not isinstance(body, dict) or body.get("schema") != SCHEMA or body.get("state") != str(state.path):
        raise SafetyError("Unsupported plan schema or state")
    if not isinstance(body.get("candidates"), list) or not isinstance(body.get("config"), dict):
        raise SafetyError("Manifest candidates/config are invalid")
    ids = set()
    for item in body["candidates"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in ids:
            raise SafetyError("Malformed or repeated candidate ID")
        ids.add(item["id"])
        if not isinstance(item.get("path"), str) or not Path(item["path"]).is_absolute():
            raise SafetyError("Candidate path is invalid")
    return body
