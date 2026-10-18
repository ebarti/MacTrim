//! Signed plans, fresh validation, atomic same-volume quarantine and guarded purge.
use super::{
    activity::{ActivityProvider, NativeActivity},
    discovery::{Candidate, classify},
};
use crate::store::{now, prepare_private, private_file};
use anyhow::{Context, Result, ensure};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};
use walkdir::WalkDir;
const MAGIC: &[u8] = b"MACTRIM-RUST-SIGNED-1\n";
type Hmac256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub relative: Vec<u8>,
    pub metadata: [u64; 8],
    pub kind: u8,
    pub link: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub digest: String,
    pub logical: u64,
    pub allocated: u64,
    pub newest: u64,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prepared {
    pub candidate: Candidate,
    pub snapshot: Snapshot,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub schema: String,
    pub id: String,
    pub state: PathBuf,
    pub created: u64,
    pub minimum_days: u64,
    pub items: Vec<Prepared>,
    pub approval: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Journal {
    pub schema: String,
    pub id: String,
    pub original: PathBuf,
    pub quarantine: PathBuf,
    pub status: String,
    pub created: u64,
    pub snapshot: Snapshot,
    pub approval: String,
}

fn metadata(m: &fs::Metadata, root: bool) -> [u64; 8] {
    [
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.uid() as u64,
        m.nlink(),
        m.len(),
        (m.mtime() as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(m.mtime_nsec() as u64),
        if root {
            0
        } else {
            (m.ctime() as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(m.ctime_nsec() as u64)
        },
    ]
}
fn protected(path: &Path) -> bool {
    path.parent().is_none()
        || path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some(
                    ".git"
                        | ".ssh"
                        | ".gnupg"
                        | "Keychains"
                        | "CloudStorage"
                        | "Mobile Documents"
                        | "Mail"
                        | "Messages"
                        | "Photos"
                        | "Backups.backupdb"
                )
            )
        })
}
fn secret(path: &Path) -> bool {
    let n = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    n == ".env"
        || n.starts_with(".env.")
        || n == "id_rsa"
        || n == "id_ed25519"
        || n.ends_with(".pem")
        || n.ends_with(".key")
        || n.ends_with(".sqlite")
        || n.ends_with(".sqlite3")
        || n.ends_with(".db")
}
fn snapshot(root: &Path) -> Result<Snapshot> {
    let original = fs::symlink_metadata(root)?;
    ensure!(
        original.is_dir() && !original.file_type().is_symlink() && !protected(root),
        "Protected or non-directory target"
    );
    let mut entries = Vec::new();
    let mut logical = 0u64;
    let mut allocated = 0u64;
    let mut newest = 0;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .max_open(16)
    {
        let entry = entry?;
        let path = entry.path();
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.dev() == original.dev(),
            "Unowned or cross-volume descendant: {}",
            path.display()
        );
        ensure!(
            !protected(path) && !secret(path),
            "Sensitive/unique data retained: {}",
            path.display()
        );
        #[cfg(target_os = "macos")]
        ensure!(
            std::os::macos::fs::MetadataExt::st_flags(&m) & 0x40000000 == 0,
            "Cloud placeholder retained"
        );
        ensure!(
            m.is_dir() || m.is_file() || m.file_type().is_symlink(),
            "Special object retained"
        );
        ensure!(!m.is_file() || m.nlink() == 1, "Hardlinked file retained");
        let kind = if m.is_dir() {
            0
        } else if m.is_file() {
            1
        } else {
            2
        };
        let relative = path.strip_prefix(root)?.as_os_str().as_bytes().to_vec();
        let link = if kind == 2 {
            Some(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
        } else {
            None
        };
        newest = newest.max(m.mtime().max(0) as u64);
        logical = logical
            .checked_add(if kind == 2 { 0 } else { m.len() })
            .context("Size overflow")?;
        allocated = allocated
            .checked_add(if kind == 2 { 0 } else { m.blocks() * 512 })
            .context("Size overflow")?;
        entries.push(Entry {
            relative,
            metadata: metadata(&m, path == root),
            kind,
            link,
        });
    }
    ensure!(
        metadata(&fs::symlink_metadata(root)?, true) == metadata(&original, true),
        "Target changed during validation"
    );
    let mut hash = Sha256::new();
    for entry in &entries {
        hash.update(serde_json::to_vec(entry)?);
        hash.update(b"\n");
    }
    Ok(Snapshot {
        digest: format!("{:x}", hash.finalize()),
        logical,
        allocated,
        newest,
        entries,
    })
}
struct Dir(File);
impl Dir {
    fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "Expected absolute directory");
        let root = CString::new("/")?;
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        ensure!(fd >= 0, "Cannot open filesystem root");
        let mut current = Self(unsafe { File::from_raw_fd(fd) });
        for part in path.components().skip(1) {
            ensure!(
                matches!(part, Component::Normal(_)),
                "Invalid directory component"
            );
            let name = CString::new(part.as_os_str().as_bytes())?;
            let child = unsafe {
                libc::openat(
                    current.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            ensure!(
                child >= 0,
                "Directory changed or is inaccessible: {}",
                path.display()
            );
            current = Self(unsafe { File::from_raw_fd(child) });
        }
        Ok(current)
    }
    fn same_path(&self, path: &Path) -> Result<()> {
        let fresh = Self::open(path)?;
        let a = self.0.metadata()?;
        let b = fresh.0.metadata()?;
        ensure!(
            (a.dev(), a.ino()) == (b.dev(), b.ino()),
            "Ancestor directory changed"
        );
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        self.0.sync_all().map_err(Into::into)
    }
}
fn exclusive_move(
    from: &Dir,
    name: &std::ffi::OsStr,
    to: &Dir,
    destination: &std::ffi::OsStr,
) -> Result<()> {
    let name = CString::new(name.as_bytes())?;
    let dest = CString::new(destination.as_bytes())?;
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            from.0.as_raw_fd(),
            name.as_ptr(),
            to.0.as_raw_fd(),
            dest.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let result = -1;
    ensure!(
        result == 0,
        "Exclusive move refused: {}",
        std::io::Error::last_os_error()
    );
    from.sync()?;
    to.sync()?;
    Ok(())
}
fn unlink_known(root: &Path, entry: &Entry) -> Result<()> {
    let relative = PathBuf::from(OsString::from_vec(entry.relative.clone()));
    ensure!(
        !relative.is_absolute()
            && !relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_))),
        "Invalid saved inventory path"
    );
    let target = if relative.as_os_str().is_empty() {
        root.to_owned()
    } else {
        root.join(relative)
    };
    let parent = Dir::open(target.parent().context("Missing purge parent")?)?;
    let m = fs::symlink_metadata(&target)?;
    let observed = metadata(&m, entry.relative.is_empty());
    if entry.kind == 0 {
        ensure!(
            observed[..4] == entry.metadata[..4] && m.is_dir(),
            "Quarantined directory replaced; preserved"
        );
    } else {
        ensure!(
            observed == entry.metadata,
            "Quarantined file changed; preserved"
        );
    }
    parent.same_path(target.parent().unwrap())?;
    let name = CString::new(target.file_name().unwrap().as_bytes())?;
    let flags = if entry.kind == 0 {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    ensure!(
        unsafe { libc::unlinkat(parent.0.as_raw_fd(), name.as_ptr(), flags) } == 0,
        "Purge stopped; unknown or changed entries preserved: {}",
        std::io::Error::last_os_error()
    );
    parent.sync()?;
    Ok(())
}

pub struct Actions<P: ActivityProvider = NativeActivity> {
    pub path: PathBuf,
    key: Vec<u8>,
    provider: P,
    _lock: File,
    state_dir: Dir,
}
impl Actions<NativeActivity> {
    pub fn open(state: &Path) -> Result<Self> {
        Self::with_provider(state, NativeActivity)
    }
}
impl<P: ActivityProvider> Actions<P> {
    pub fn with_provider(state: &Path, provider: P) -> Result<Self> {
        let path = state.join("cleanup");
        prepare_private(&path)?;
        let lock = private_file(&path.join("action.lock"), true)?;
        lock.try_lock_exclusive()
            .context("Another cleanup action owns the state")?;
        let keypath = path.join("key");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&keypath)
        {
            Ok(mut f) => {
                let mut key = [0; 32];
                getrandom::fill(&mut key)
                    .map_err(|e| anyhow::anyhow!("Random key unavailable: {e}"))?;
                f.write_all(&key)?;
                f.sync_all()?;
                File::open(&path)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let mut key = Vec::new();
        private_file(&keypath, false)?
            .take(33)
            .read_to_end(&mut key)?;
        ensure!(key.len() == 32, "Invalid cleanup signing key");
        for name in ["plans", "journals", "quarantine"] {
            prepare_private(&path.join(name))?;
        }
        let state_dir = Dir::open(&path)?;
        Ok(Self {
            path,
            key,
            provider,
            _lock: lock,
            state_dir,
        })
    }
    fn file(&self, group: &str, id: &str) -> Result<PathBuf> {
        ensure!(uuid::Uuid::parse_str(id).is_ok(), "Invalid plan/journal ID");
        Ok(self.path.join(group).join(format!("{id}.gz")))
    }
    fn write<T: Serialize>(&self, path: &Path, body: &T) -> Result<()> {
        self.state_dir.same_path(&self.path)?;
        if fs::symlink_metadata(path).is_ok() {
            self.authenticated_file(path)?;
        }
        let pending = path.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&pending)?;
        file.write_all(MAGIC)?;
        file.write_all(&[0; 32])?;
        {
            let mut zip = GzEncoder::new(&mut file, Compression::fast());
            serde_json::to_writer(&mut zip, body)?;
            zip.finish()?;
        }
        file.flush()?;
        file.seek(SeekFrom::Start((MAGIC.len() + 32) as u64))?;
        let mut mac = Hmac256::new_from_slice(&self.key)?;
        mac.update(MAGIC);
        let mut buffer = [0; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            mac.update(&buffer[..n]);
        }
        file.seek(SeekFrom::Start(MAGIC.len() as u64))?;
        file.write_all(&mac.finalize().into_bytes())?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
    fn authenticated_file(&self, path: &Path) -> Result<File> {
        self.state_dir.same_path(&self.path)?;
        let mut file = private_file(path, false)?;
        let before = metadata(&file.metadata()?, false);
        let mut magic = vec![0; MAGIC.len()];
        file.read_exact(&mut magic)?;
        ensure!(magic == MAGIC, "Unrecognized cleanup record preserved");
        let mut signature = [0; 32];
        file.read_exact(&mut signature)?;
        let mut mac = Hmac256::new_from_slice(&self.key)?;
        mac.update(MAGIC);
        let mut buffer = [0; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            mac.update(&buffer[..n]);
        }
        mac.verify_slice(&signature)
            .context("Cleanup record authentication failed; preserved")?;
        ensure!(
            metadata(&file.metadata()?, false) == before,
            "Cleanup record changed during authentication"
        );
        file.seek(SeekFrom::Start((MAGIC.len() + 32) as u64))?;
        Ok(file)
    }
    fn read<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let file = self.authenticated_file(path)?;
        let before = metadata(&file.metadata()?, false);
        let result = serde_json::from_reader(GzDecoder::new(&file))?;
        ensure!(
            metadata(&file.metadata()?, false) == before,
            "Cleanup record changed during decoding"
        );
        self.state_dir.same_path(&self.path)?;
        Ok(result)
    }
    fn validate(&self, candidate: &Candidate, minimum_days: u64) -> Result<Snapshot> {
        ensure!(
            !candidate.path.is_symlink(),
            "Symlink target cannot be selected"
        );
        let fresh = classify(&candidate.path)?;
        ensure!(
            fresh.eligible && fresh.id == candidate.id,
            "Fresh classification blocks this scope: {}",
            fresh.blockers.join("; ")
        );
        ensure!(
            !self.path.starts_with(&fresh.path) && !fresh.path.starts_with(&self.path),
            "Cleanup state cannot be a target"
        );
        let activity = self.provider.snapshot()?;
        let scope = fresh.repository.as_deref().unwrap_or(&fresh.path);
        let blockers = activity.blockers(scope);
        ensure!(
            blockers.is_empty(),
            "Activity blocks cleanup: {}",
            blockers.join("; ")
        );
        let fp = snapshot(&fresh.path)?;
        ensure!(
            now().saturating_sub(fp.newest) >= minimum_days.saturating_mul(86400),
            "Recently modified descendants retained"
        );
        ensure!(
            fp.entries[0].metadata[0] == fs::metadata(self.path.join("quarantine"))?.dev(),
            "Cross-volume move refused; place --state on the target volume"
        );
        Ok(fp)
    }
    pub fn prepare(&self, candidates: &[Candidate], minimum_days: u64) -> Result<Plan> {
        ensure!(!candidates.is_empty(), "Select at least one candidate");
        let mut items: Vec<Prepared> = Vec::new();
        for candidate in candidates {
            ensure!(
                !items
                    .iter()
                    .any(|i| candidate.path.starts_with(&i.candidate.path)
                        || i.candidate.path.starts_with(&candidate.path)),
                "Overlapping selections are not allowed"
            );
            items.push(Prepared {
                candidate: candidate.clone(),
                snapshot: self.validate(candidate, minimum_days)?,
            });
        }
        let id = uuid::Uuid::new_v4().to_string();
        let plan = Plan {
            schema: "mactrim.rust.plan.v1".into(),
            approval: format!("QUARANTINE {id}"),
            id,
            state: self.path.clone(),
            created: now(),
            minimum_days,
            items,
        };
        self.write(&self.file("plans", &plan.id)?, &plan)?;
        Ok(plan)
    }
    pub fn apply(&self, id: &str, approval: &str) -> Result<Vec<Journal>> {
        let plan: Plan = self.read(&self.file("plans", id)?)?;
        ensure!(
            plan.schema == "mactrim.rust.plan.v1" && plan.id == id && plan.state == self.path,
            "Plan identity mismatch"
        );
        ensure!(
            plan.approval == approval,
            "Exact approval required: {}",
            plan.approval
        );
        ensure!(
            plan.created <= now() && now() - plan.created <= 600,
            "Plan expired; validate again"
        );
        for item in &plan.items {
            ensure!(
                self.validate(&item.candidate, plan.minimum_days)?.digest == item.snapshot.digest,
                "Candidate changed since validation"
            );
        }
        let mut records = Vec::new();
        for item in plan.items {
            ensure!(
                self.validate(&item.candidate, plan.minimum_days)?.digest == item.snapshot.digest,
                "Candidate changed before move"
            );
            let parent = Dir::open(item.candidate.path.parent().unwrap())?;
            let destination = Dir::open(&self.path.join("quarantine"))?;
            let id = uuid::Uuid::new_v4().to_string();
            let mut record = Journal {
                schema: "mactrim.rust.journal.v1".into(),
                original: item.candidate.path.clone(),
                quarantine: self.path.join("quarantine").join(&id),
                id,
                status: "prepared".into(),
                created: now(),
                snapshot: item.snapshot,
                approval: approval.into(),
            };
            let journal = self.file("journals", &record.id)?;
            self.write(&journal, &record)?;
            parent.same_path(item.candidate.path.parent().unwrap())?;
            ensure!(
                snapshot(&record.original)?.digest == record.snapshot.digest,
                "Candidate changed immediately before move"
            );
            exclusive_move(
                &parent,
                record.original.file_name().unwrap(),
                &destination,
                record.quarantine.file_name().unwrap(),
            )?;
            if snapshot(&record.quarantine)?.digest != record.snapshot.digest {
                record.status = "conflicted".into();
                self.write(&journal, &record)?;
                anyhow::bail!("Moved item changed; retained in quarantine for recovery");
            }
            record.status = "quarantined".into();
            self.write(&journal, &record)?;
            records.push(record);
        }
        self.read::<Plan>(&self.file("plans", id)?)?;
        fs::remove_file(self.file("plans", id)?)?;
        File::open(self.path.join("plans"))?.sync_all()?;
        Ok(records)
    }
    pub fn plan(&self, id: &str) -> Result<Plan> {
        self.read(&self.file("plans", id)?)
    }
    fn journal(&self, id: &str) -> Result<Journal> {
        let record: Journal = self.read(&self.file("journals", id)?)?;
        ensure!(
            record.schema == "mactrim.rust.journal.v1"
                && record.id == id
                && record.quarantine == self.path.join("quarantine").join(id),
            "Journal identity mismatch"
        );
        Ok(record)
    }
    pub fn journals(&self) -> Result<Vec<Journal>> {
        let mut result = vec![];
        for entry in fs::read_dir(self.path.join("journals"))? {
            let e = entry?;
            if e.path().extension().is_some_and(|s| s == "gz") {
                let id = e.path().file_stem().unwrap().to_string_lossy().into_owned();
                result.push(self.journal(&id)?);
            }
        }
        Ok(result)
    }
    pub fn recover(&self) -> Result<Vec<Journal>> {
        let mut records = self.journals()?;
        for record in &mut records {
            let original = fs::symlink_metadata(&record.original).is_ok();
            let quarantined = fs::symlink_metadata(&record.quarantine).is_ok();
            let status = match record.status.as_str() {
                "prepared"
                    if quarantined
                        && !original
                        && snapshot(&record.quarantine)
                            .is_ok_and(|s| s.digest == record.snapshot.digest) =>
                {
                    Some("quarantined")
                }
                "prepared"
                    if original
                        && !quarantined
                        && snapshot(&record.original)
                            .is_ok_and(|s| s.digest == record.snapshot.digest) =>
                {
                    Some("not-moved")
                }
                "restoring"
                    if original
                        && !quarantined
                        && snapshot(&record.original)
                            .is_ok_and(|s| s.digest == record.snapshot.digest) =>
                {
                    Some("restored")
                }
                "purging" => Some("purge-interrupted"),
                _ => None,
            };
            if let Some(status) = status {
                record.status = status.into();
                self.write(&self.file("journals", &record.id)?, record)?;
            }
        }
        Ok(records)
    }
    pub fn restore(&self, id: &str) -> Result<Journal> {
        let mut r = self.journal(id)?;
        ensure!(
            ["prepared", "quarantined", "restoring", "conflicted"].contains(&r.status.as_str()),
            "Journal cannot be restored in this state"
        );
        ensure!(
            snapshot(&r.quarantine)?.digest == r.snapshot.digest,
            "Quarantined item changed; preserve for manual recovery"
        );
        let parent = Dir::open(r.original.parent().context("Missing original parent")?)?;
        let source = Dir::open(r.quarantine.parent().unwrap())?;
        r.status = "restoring".into();
        self.write(&self.file("journals", id)?, &r)?;
        exclusive_move(
            &source,
            r.quarantine.file_name().unwrap(),
            &parent,
            r.original.file_name().unwrap(),
        )?;
        ensure!(
            snapshot(&r.original)?.digest == r.snapshot.digest,
            "Restored item changed; preserve for manual review"
        );
        r.status = "restored".into();
        r.snapshot.entries.clear();
        self.write(&self.file("journals", id)?, &r)?;
        Ok(r)
    }
    pub fn purge(&self, id: &str, approval: &str) -> Result<Journal> {
        let mut r = self.journal(id)?;
        ensure!(
            approval == format!("PURGE {id}"),
            "Exact approval required: PURGE {id}"
        );
        ensure!(
            r.status == "quarantined",
            "Only a committed quarantine may be purged"
        );
        let blockers = self.provider.snapshot()?.blockers(&r.quarantine);
        ensure!(
            blockers.is_empty(),
            "Quarantine is active or process coverage is incomplete"
        );
        ensure!(
            snapshot(&r.quarantine)?.digest == r.snapshot.digest,
            "Quarantine changed; no deletion authorized"
        );
        r.status = "purging".into();
        self.write(&self.file("journals", id)?, &r)?;
        // Delete only captured identities. A newly introduced entry is never
        // enumerated for deletion; it makes removal of its parent fail closed.
        let result = (|| {
            for entry in r.snapshot.entries.iter().rev() {
                unlink_known(&r.quarantine, entry)?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = result {
            r.status = "purge-interrupted".into();
            self.write(&self.file("journals", id)?, &r)?;
            return Err(error);
        }
        r.status = "purged".into();
        r.snapshot.entries.clear();
        self.write(&self.file("journals", id)?, &r)?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::activity::Activity;
    use super::*;
    #[derive(Clone)]
    struct Quiet;
    impl ActivityProvider for Quiet {
        fn snapshot(&self) -> Result<Activity> {
            Ok(Activity {
                complete: true,
                ..Activity::default()
            })
        }
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let repo = base.join("repo");
        fs::create_dir(&repo).unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"]);
        fs::write(repo.join(".gitignore"), "node_modules/\n").unwrap();
        fs::write(
            repo.join("package.json"),
            "{\"name\":\"fixture\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        fs::write(repo.join("package-lock.json"), "{\"lockfileVersion\":3}").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ]);
        fs::create_dir_all(repo.join("node_modules/pkg")).unwrap();
        fs::write(
            repo.join("node_modules/.package-lock.json"),
            "{\"lockfileVersion\":3,\"packages\":{\"node_modules/pkg\":{\"version\":\"1.0.0\"}}}",
        )
        .unwrap();
        fs::write(repo.join("node_modules/pkg/data"), "recreatable bytes").unwrap();
        (temp, repo, base.join("state"))
    }
    #[test]
    fn quarantine_restore_and_separate_purge_approval() {
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let path = repo.join("node_modules");
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        assert!(actions.apply(&plan.id, "yes").is_err());
        assert!(path.exists());
        let records = actions.apply(&plan.id, &plan.approval).unwrap();
        assert!(!path.exists());
        assert!(records[0].quarantine.join("pkg/data").exists());
        assert!(actions.purge(&records[0].id, &plan.approval).is_err());
        actions.restore(&records[0].id).unwrap();
        assert_eq!(
            fs::read_to_string(path.join("pkg/data")).unwrap(),
            "recreatable bytes"
        );
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        let record = actions.apply(&plan.id, &plan.approval).unwrap().remove(0);
        actions
            .purge(&record.id, &format!("PURGE {}", record.id))
            .unwrap();
        assert!(!record.quarantine.exists());
        assert!(!path.exists());
    }
    #[test]
    fn modified_candidate_and_tampered_plan_never_move() {
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let path = repo.join("node_modules");
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        fs::write(path.join("pkg/data"), "edited unique bytes").unwrap();
        assert!(actions.apply(&plan.id, &plan.approval).is_err());
        assert!(path.exists());
        let file = actions.file("plans", &plan.id).unwrap();
        let mut raw = fs::read(&file).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(file, raw).unwrap();
        assert!(actions.plan(&plan.id).is_err());
        assert!(path.exists());
    }
    #[test]
    fn new_quarantine_data_and_restore_collision_are_preserved() {
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let path = repo.join("node_modules");
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        let record = actions.apply(&plan.id, &plan.approval).unwrap().remove(0);
        fs::write(record.quarantine.join("new-user-data"), "keep").unwrap();
        assert!(
            actions
                .purge(&record.id, &format!("PURGE {}", record.id))
                .is_err()
        );
        assert!(record.quarantine.join("pkg/data").exists());
        fs::remove_file(record.quarantine.join("new-user-data")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), "new tree").unwrap();
        assert!(actions.restore(&record.id).is_err());
        assert!(path.join("keep").exists());
        assert!(record.quarantine.exists());
    }
    #[test]
    fn hardlinks_and_sensitive_files_block_validation() {
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let path = repo.join("node_modules");
        fs::hard_link(path.join("pkg/data"), repo.join(".git/linked-data")).unwrap();
        assert!(actions.prepare(&[classify(&path).unwrap()], 0).is_err());
        fs::remove_file(repo.join(".git/linked-data")).unwrap();
        fs::write(path.join(".env"), "SECRET").unwrap();
        assert!(actions.prepare(&[classify(&path).unwrap()], 0).is_err());
    }
    #[test]
    fn purge_unlinks_captured_symlinks_without_following_them() {
        let (_temp, repo, state) = fixture();
        let outside = state.with_file_name("outside");
        fs::write(&outside, "keep").unwrap();
        let path = repo.join("node_modules");
        std::os::unix::fs::symlink(&outside, path.join("link")).unwrap();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        let record = actions.apply(&plan.id, &plan.approval).unwrap().remove(0);
        actions
            .purge(&record.id, &format!("PURGE {}", record.id))
            .unwrap();
        assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
    }
    #[test]
    fn interrupted_move_intent_is_recovered_from_saved_identities() {
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Quiet).unwrap();
        let path = repo.join("node_modules");
        let plan = actions.prepare(&[classify(&path).unwrap()], 0).unwrap();
        let mut record = actions.apply(&plan.id, &plan.approval).unwrap().remove(0);
        record.status = "prepared".into();
        actions
            .write(&actions.file("journals", &record.id).unwrap(), &record)
            .unwrap();
        assert_eq!(actions.recover().unwrap()[0].status, "quarantined");
        actions.restore(&record.id).unwrap();
        assert!(path.exists());
    }
    #[test]
    fn incomplete_process_coverage_blocks_mutations() {
        struct Unknown;
        impl ActivityProvider for Unknown {
            fn snapshot(&self) -> Result<Activity> {
                Ok(Activity {
                    issues: vec!["Coverage unavailable".into()],
                    ..Activity::default()
                })
            }
        }
        let (_temp, repo, state) = fixture();
        let actions = Actions::with_provider(&state, Unknown).unwrap();
        assert!(
            actions
                .prepare(&[classify(&repo.join("node_modules")).unwrap()], 0)
                .is_err()
        );
    }
}
