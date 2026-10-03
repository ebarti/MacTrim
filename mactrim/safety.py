"""Filesystem primitives. No shell, symlink traversal, or overwrite fallback."""
import contextlib
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unicodedata


class SafetyError(Exception):
    pass


def clean(value):
    """Escape terminal controls, newlines, bidi formatting and surrogate names."""
    out = []
    for char in str(value):
        if unicodedata.category(char).startswith("C"):
            code = ord(char)
            out.append("\\u%04x" % code if code <= 65535 else "\\U%08x" % code)
        else:
            out.append(char)
    return "".join(out)


def canonical(path):
    # abspath deliberately does not follow symlinks. Check every ancestor separately.
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def within(path, root):
    try:
        canonical(path).relative_to(canonical(root))
        return True
    except ValueError:
        return False


def overlap(a, b):
    return within(a, b) or within(b, a)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(json_bytes(value)).hexdigest()


# These exclusions apply anywhere in a scoped tree, including explicit roots.
PROTECTED_NAMES = {
    ".git", ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".config",
    "keychains", "mobile documents", "cloudstorage", "backups.backupdb",
    ".timemachine", "photos library.photoslibrary", "docker.raw", "docker.qcow2",
    ".env", "auth.json", ".netrc", "netrc", ".npmrc", ".pypirc", "credentials",
    "credentials.json", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "kubeconfig",
}
PROTECTED_SUFFIXES = (".app", ".photoslibrary", ".photolibrary", ".backupbundle",
                      ".sparsebundle", ".sparseimage", ".dmg", ".vmdk", ".vdi", ".qcow2",
                      ".pvm", ".vmwarevm", ".sqlite", ".sqlite3", ".db", ".keychain",
                      ".keychain-db", ".pem", ".key", ".p12", ".pfx", ".kdbx")


def protected(path, state=None):
    path = canonical(path)
    if state is not None and overlap(path, state):
        return "MacTrim state is protected"
    system = ["/System", "/Library", "/bin", "/sbin", "/usr", "/etc", "/private", "/var", "/dev", "/Volumes"]
    # /private/tmp is allowed only when explicitly scoped; /tmp is a symlink on macOS.
    if any(within(path, root) for root in system) and not within(path, "/private/tmp"):
        return "System, update, mount or privileged scope is report-only"
    for part in path.parts:
        lower = part.lower()
        if lower in PROTECTED_NAMES or lower.startswith(".env.") or lower.endswith(PROTECTED_SUFFIXES):
            return "Protected data, application, credentials, database, backup or library bundle"
        if any(token in lower for token in ("dropbox", "onedrive", "google drive", "icloud")):
            return "Cloud-managed scope is protected"
    if path == Path.home() or path == Path("/"):
        return "Home and filesystem roots are protected"
    if "Library" in path.parts and any(part in path.parts for part in ("Preferences", "Application Support", "Containers", "Group Containers", "Photos", "Mail", "Messages")):
        return "Unique application data is report-only"
    return None


@contextlib.contextmanager
def directory_fd(path):
    """Open each component with O_NOFOLLOW; hold the actual directory inode."""
    path = canonical(path)
    cwd = canonical(os.getcwd())
    if within(path, cwd):
        # macOS TCC can authorize the task directory while refusing an open of
        # Documents itself. Start from the OS-held cwd, then openat each child.
        before = ancestor_identity(cwd)
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if list((os.fstat(fd).st_dev, os.fstat(fd).st_ino)) != before[-1][1:] or ancestor_identity(cwd) != before:
            os.close(fd)
            raise SafetyError("Current working directory identity changed")
        parts = path.relative_to(cwd).parts
    else:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        parts = path.parts[1:]
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError as exc:
        raise SafetyError("Unsafe or inaccessible directory ancestor: %s (%s)" % (clean(path), exc.strerror)) from exc
    finally:
        os.close(fd)


def ancestor_identity(path):
    path = canonical(path)
    identities = []
    for item in reversed([path] + list(path.parents)):
        st = os.lstat(item)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise SafetyError("Symlink or non-directory ancestor: %s" % clean(item))
        identities.append([str(item), st.st_dev, st.st_ino])
    return identities


def stat_record(st, root=False):
    record = [st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode),
              st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns, 0 if root else st.st_ctime_ns, st.st_nlink]
    return record


class Budget:
    def __init__(self, maximum=100000, depth=24):
        self.maximum = maximum
        self.depth = depth
        self.used = 0

    def consume(self, depth):
        self.used += 1
        if self.used > self.maximum or depth > self.depth:
            raise SafetyError("Traversal budget exhausted (files=%s; depth=%s)" % (self.maximum, self.depth))


def fingerprint(path, budget=None, inspect_protected=True, state=None):
    """Stable no-follow descendant inventory and identity; inaccessible entries block."""
    path = canonical(path)
    budget = budget or Budget()
    records = []
    logical = allocated = 0
    seen = set()
    device = os.lstat(path).st_dev
    newest_ns = 0
    with directory_fd(path.parent) as parent_fd:
        def visit(fd, name, relative, level):
            nonlocal logical, allocated, newest_ns
            budget.consume(level)
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if st.st_dev != device:
                raise SafetyError("Mount boundary inside candidate")
            if st.st_uid != os.getuid():
                raise SafetyError("Candidate contains data owned by another user")
            if getattr(st, "st_flags", 0) & 0x40000000:  # SF_DATALESS: do not hydrate placeholders.
                raise SafetyError("Cloud placeholder is protected")
            absolute = path / relative if relative else path
            if inspect_protected and protected(absolute, state):
                raise SafetyError(protected(absolute, state))
            newest_ns = max(newest_ns, st.st_mtime_ns)
            record = [relative, stat_record(st, root=not relative)]
            if stat.S_ISLNK(st.st_mode):
                record.append(os.readlink(name, dir_fd=fd))
            elif stat.S_ISDIR(st.st_mode):
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if stat_record(os.fstat(child_fd)) != stat_record(st):
                        raise SafetyError("Directory changed during enumeration")
                    # Directory mode checks make failure explicit even under privileged tests.
                    if not st.st_mode & 0o444 or not st.st_mode & 0o111:
                        raise SafetyError("Inaccessible directory inside candidate")
                    names = sorted(os.listdir(child_fd))
                    records.append(record)
                    for child in names:
                        visit(child_fd, child, str(Path(relative) / child), level + 1)
                    if stat_record(os.fstat(child_fd)) != stat_record(st):
                        raise SafetyError("Directory changed during enumeration")
                finally:
                    os.close(child_fd)
                return
            elif stat.S_ISREG(st.st_mode):
                if not st.st_mode & 0o444:
                    raise SafetyError("Unreadable file inside candidate")
                if st.st_nlink > 1:
                    raise SafetyError("Hard-linked data is protected")
                if not relative:
                    # Rename changes root ctime. A root regular file instead binds
                    # exact bytes so same-size/mtime rewrites cannot evade validation.
                    record.append(file_hash(path))
                    if stat_record(os.stat(name, dir_fd=fd, follow_symlinks=False)) != stat_record(st):
                        raise SafetyError("Root file changed during fingerprinting")
                inode = (st.st_dev, st.st_ino)
                if st.st_nlink > 1:
                    raise SafetyError("Hard-linked data is protected")
                if inode not in seen:
                    logical += st.st_size
                    allocated += getattr(st, "st_blocks", 0) * 512
                    seen.add(inode)
            else:
                raise SafetyError("Special filesystem object is protected")
            records.append(record)
        visit(parent_fd, path.name, "", 0)
    return {"digest": digest(records), "entries": len(records), "logical": logical,
            "allocated": allocated, "newest_ns": newest_ns,
            "identity": records[0][1][:2] if records else [], "records": records}


def file_hash(path):
    path = canonical(path)
    with directory_fd(path.parent) as fd:
        st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SafetyError("Duplicate must be a regular, non-hard-linked file")
        if getattr(st, "st_flags", 0) & 0x40000000:
            raise SafetyError("Cloud placeholder is protected")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if stat_record(os.fstat(file_fd)) != stat_record(st):
                raise SafetyError("File changed before hashing")
            sha = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                sha.update(chunk)
            if stat_record(os.fstat(file_fd)) != stat_record(st):
                raise SafetyError("File changed while hashing")
            return sha.hexdigest()
        finally:
            os.close(file_fd)


def rename_exclusive(source_fd, source_name, target_fd, target_name):
    """Atomic no-overwrite rename. Never emulate with check then os.rename."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        call = libc.renameatx_np
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        flags = 0x4  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        call = libc.renameat2
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        flags = 1  # RENAME_NOREPLACE
    else:
        raise SafetyError("Atomic no-overwrite rename is unavailable on this platform")
    call.restype = ctypes.c_int
    if call(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), flags) != 0:
        error = ctypes.get_errno()
        raise SafetyError("Atomic move refused: %s" % os.strerror(error))
    os.fsync(source_fd)
    os.fsync(target_fd)


def remove_tree_fd(parent_fd, name, approved, relative=""):
    """Delete only identity-verified entries in the immutable approved inventory.

    Newly created/replaced descendants are never adopted into this deletion scope.
    Interrupted deletion leaves an approved subset that requires another approval.
    """
    expected = {entry[0]: entry[1:] for entry in approved}

    def verify(fd, child, rel):
        previous = expected.get(rel)
        if previous is None:
            raise SafetyError("Unexpected descendant at purge boundary")
        st = os.stat(child, dir_fd=fd, follow_symlinks=False)
        before, *tail = previous
        current = stat_record(st, root=not rel)
        if stat.S_ISDIR(st.st_mode):
            if current[:6] != before[:6]:
                raise SafetyError("Directory replaced at purge boundary")
        elif current != before:
            raise SafetyError("File replaced or changed at purge boundary")
        if stat.S_ISLNK(st.st_mode):
            if [os.readlink(child, dir_fd=fd)] != tail:
                raise SafetyError("Symlink changed at purge boundary")
        elif stat.S_ISREG(st.st_mode) and not rel:
            file_fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if stat_record(os.fstat(file_fd)) != stat_record(st):
                    raise SafetyError("Root file replaced at purge boundary")
                sha = hashlib.sha256()
                while True:
                    chunk = os.read(file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    sha.update(chunk)
                if tail != [sha.hexdigest()] or stat_record(os.fstat(file_fd)) != stat_record(st):
                    raise SafetyError("Root file content changed at purge boundary")
            finally:
                os.close(file_fd)
        return st

    def remove(fd, child, rel):
        st = verify(fd, child, rel)
        if stat.S_ISDIR(st.st_mode):
            child_fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if os.fstat(child_fd).st_ino != st.st_ino:
                    raise SafetyError("Directory changed while purging")
                names = sorted(os.listdir(child_fd))
                # Validate the entire immediate scope before removing its first item.
                for nested in names:
                    nested_rel = str(Path(rel) / nested)
                    verify(child_fd, nested, nested_rel)
                for nested in names:
                    remove(child_fd, nested, str(Path(rel) / nested))
                if os.listdir(child_fd):
                    raise SafetyError("Unexpected new descendant during purge; retained")
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
            verify(fd, child, rel)
            os.rmdir(child, dir_fd=fd)
        else:
            verify(fd, child, rel)
            os.unlink(child, dir_fd=fd)
        os.fsync(fd)

    remove(parent_fd, name, relative)
