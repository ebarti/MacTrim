//! Immutable completed scans. Each scan has its own compressed directory tree.
use crate::{
    filesystem,
    history::{Change, Counts},
    model::{COLLAPSED, Index},
    scan,
    store::{self, Generation, bytes, prepare_private, private_file},
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: u64,
    #[serde(with = "crate::paths")]
    pub root: PathBuf,
    pub started: u64,
    pub finished: u64,
    pub identity: filesystem::Identity,
    pub logical: u64,
    pub allocated: u64,
    pub coverage: u32,
    pub directories: usize,
    pub visited: u64,
    pub filesystem_used: u64,
    pub filesystem_available: u64,
    pub imported: bool,
    pub generation: Generation,
}
impl Snapshot {
    pub fn coverage_name(&self) -> &'static str {
        match self.coverage {
            0 => "MEASURED",
            3 => "DENIED",
            _ => "PARTIAL",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub from: Snapshot,
    pub to: Snapshot,
    pub same_filesystem: bool,
    pub changes: Vec<Change>,
}

pub struct Capture {
    pub started: u64,
    pub identity: filesystem::Identity,
}
impl Capture {
    pub fn begin(root: &Path) -> Result<Self> {
        Ok(Self {
            started: store::now(),
            identity: filesystem::identity(root)?,
        })
    }
}

pub struct Snapshots {
    db: Connection,
    pub state: PathBuf,
    writer: Option<File>,
}
impl Snapshots {
    pub fn open(state: &Path) -> Result<Self> {
        prepare_private(state)?;
        let lock = private_file(&state.join("writer.lock"), true)?;
        lock.try_lock_exclusive()
            .context("Another terminal scan owns this state")?;
        let db = Self::database(state, true)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT,root BLOB NOT NULL,finished INTEGER NOT NULL,data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS snapshots_root ON snapshots(root,id);
            CREATE TABLE IF NOT EXISTS scan_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
        let mut result = Self {
            db,
            state: state.to_owned(),
            writer: Some(lock),
        };
        if let Err(error) = result.import_legacy() {
            // Preserve an unreadable legacy store and allow independent new scans.
            let tx = result.db.transaction()?;
            tx.execute(
                "INSERT OR REPLACE INTO scan_meta VALUES('import_warning',?)",
                [format!(
                    "Earlier saved data retained but could not be imported: {error:#}"
                )],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO scan_meta VALUES('legacy_checked','true')",
                [],
            )?;
            tx.commit()?;
        }
        Ok(result)
    }
    pub fn read_only(state: &Path) -> Result<Option<Self>> {
        if !state.join("scans.sqlite3").try_exists()? {
            return Ok(None);
        }
        Ok(Some(Self {
            db: Self::database(state, false)?,
            state: state.to_owned(),
            writer: None,
        }))
    }
    fn database(state: &Path, write: bool) -> Result<Connection> {
        let path = state.join("scans.sqlite3");
        let held = private_file(&path, write)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let companion = state.join(format!("scans.sqlite3{suffix}"));
            if companion.try_exists()? {
                private_file(&companion, false)?;
            }
        }
        let db = Connection::open_with_flags(
            &path,
            if write {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            },
        )?;
        db.busy_timeout(std::time::Duration::from_secs(3))?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(path)?.ino(),
            "Scan database replaced during open"
        );
        Ok(db)
    }
    pub fn import_warning(&self) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT value FROM scan_meta WHERE key='import_warning'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
    fn import_legacy(&mut self) -> Result<()> {
        let checked: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan_meta WHERE key='legacy_checked')",
            [],
            |r| r.get(0),
        )?;
        if checked {
            return Ok(());
        }
        if self.state.join("service.sqlite3").try_exists()?
            && let Some(index) = store::load_legacy(&self.state)?
        {
            let old = Connection::open_with_flags(
                self.state.join("service.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let raw: String =
                old.query_row("SELECT value FROM meta WHERE key='generation'", [], |r| {
                    r.get(0)
                })?;
            let old_generation: Generation = serde_json::from_str(&raw)?;
            let node = index.root_node().context("Legacy root missing")?;
            let generation = if old_generation.patches == 0 {
                old_generation.clone()
            } else {
                Generation::write(&self.state, &index)?
            };
            let snapshot = Snapshot {
                id: 0,
                root: index.root.clone(),
                started: old_generation.created,
                finished: old_generation.created,
                identity: filesystem::Identity {
                    device: node.signature[0],
                    inode: node.signature[1],
                    volume_uuid: None,
                },
                logical: node.logical,
                allocated: node.allocated,
                coverage: node.status,
                directories: index.nodes.len(),
                visited: node.entries,
                filesystem_used: 0,
                filesystem_available: 0,
                imported: true,
                generation,
            };
            self.insert(snapshot)?;
        }
        self.db.execute(
            "INSERT OR IGNORE INTO scan_meta VALUES('legacy_checked','true')",
            [],
        )?;
        Ok(())
    }
    pub fn save(
        &mut self,
        index: &Index,
        capture: &Capture,
        cancel: &AtomicBool,
    ) -> Result<Snapshot> {
        ensure!(self.writer.is_some(), "Snapshot store is read-only");
        ensure!(
            index.full_scan,
            "Only a completed full scan can create a snapshot"
        );
        scan::check_cancelled(cancel)?;
        ensure!(
            capture
                .identity
                .same_root(&filesystem::identity(&index.root)?),
            "Scan root was replaced; earlier scans preserved"
        );
        let node = index
            .root_node()
            .context("A completed scan must contain its root")?;
        ensure!(
            index.nodes.values().all(|n| n.status != 4),
            "A running measurement cannot be saved as a completed scan"
        );
        let generation = Generation::write_cancellable(&self.state, index, cancel)?;
        let result = (|| {
            scan::check_cancelled(cancel)?;
            ensure!(
                capture
                    .identity
                    .same_root(&filesystem::identity(&index.root)?),
                "Scan root was replaced before save"
            );
            let (used, available) = filesystem::capacity(&index.root)?;
            let snapshot = Snapshot {
                id: 0,
                root: index.root.clone(),
                started: capture.started,
                finished: store::now(),
                identity: capture.identity.clone(),
                logical: node.logical,
                allocated: node.allocated,
                coverage: node.status,
                directories: index.nodes.len(),
                visited: index.visited,
                filesystem_used: used,
                filesystem_available: available,
                imported: false,
                generation: generation.clone(),
            };
            self.insert(snapshot)
        })();
        if result.is_err() {
            let _ = fs::remove_file(self.state.join(generation.name));
        }
        result
    }
    fn insert(&mut self, mut snapshot: Snapshot) -> Result<Snapshot> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO snapshots(root,finished,data) VALUES(?,?,?)",
            params![bytes(&snapshot.root), i64::try_from(snapshot.finished)?, ""],
        )?;
        snapshot.id = u64::try_from(tx.last_insert_rowid())?;
        tx.execute(
            "UPDATE snapshots SET data=? WHERE id=?",
            params![
                serde_json::to_string(&snapshot)?,
                i64::try_from(snapshot.id)?
            ],
        )?;
        if snapshot.imported {
            tx.execute(
                "INSERT OR IGNORE INTO scan_meta VALUES('legacy_checked','true')",
                [],
            )?;
        }
        tx.commit()?;
        Ok(snapshot)
    }
    pub fn list(&self, root: Option<&Path>) -> Result<Vec<Snapshot>> {
        let mut q = self
            .db
            .prepare("SELECT data FROM snapshots WHERE (? IS NULL OR root=?) ORDER BY id DESC")?;
        let raw = root.map(bytes);
        let rows = q.query_map(params![raw, raw], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    pub fn latest(&self, root: &Path) -> Result<Option<Snapshot>> {
        let raw: Option<String> = self
            .db
            .query_row(
                "SELECT data FROM snapshots WHERE root=? ORDER BY id DESC LIMIT 1",
                [bytes(root)],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
            .transpose()
    }
    pub fn get(&self, id: u64) -> Result<Snapshot> {
        let raw: Option<String> = self
            .db
            .query_row(
                "SELECT data FROM snapshots WHERE id=?",
                [i64::try_from(id)?],
                |r| r.get(0),
            )
            .optional()?;
        serde_json::from_str(&raw.with_context(|| format!("Scan #{id} not found"))?)
            .map_err(Into::into)
    }
    pub fn load(&self, snapshot: &Snapshot) -> Result<Index> {
        let index = snapshot.generation.read_checkpoint(&self.state)?;
        ensure!(
            index.root == snapshot.root,
            "Snapshot root and saved tree differ"
        );
        Ok(index)
    }
    pub fn endpoints(
        &self,
        scope: &Path,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Option<(Snapshot, Snapshot)>> {
        let to = match to {
            Some(id) => self.get(id)?,
            None => match self
                .list(None)?
                .into_iter()
                .find(|s| scope.starts_with(&s.root))
            {
                Some(s) => s,
                None => return Ok(None),
            },
        };
        ensure!(
            scope.starts_with(&to.root),
            "Comparison path is outside scan #{}",
            to.id
        );
        let from = match from {
            Some(id) => self.get(id)?,
            None => match self
                .list(Some(&to.root))?
                .into_iter()
                .find(|s| s.id < to.id)
            {
                Some(s) => s,
                None => return Ok(None),
            },
        };
        ensure!(
            from.root == to.root && from.id != to.id,
            "Choose two different scans of the same root"
        );
        Ok(Some((from, to)))
    }
    pub fn compare(&self, scope: &Path, from: &Snapshot, to: &Snapshot) -> Result<Comparison> {
        ensure!(
            from.root == to.root && scope.starts_with(&from.root),
            "Scans and comparison path must share a root"
        );
        let before = self.load(from)?;
        let after = self.load(to)?;
        let same_filesystem = from.identity.same_root(&to.identity);
        let mut changes = differences(&before, &after, to.finished, same_filesystem);
        changes.retain(|c| c.path.starts_with(scope));
        changes.sort_unstable_by(|a, b| {
            b.growth()
                .map(i128::unsigned_abs)
                .cmp(&a.growth().map(i128::unsigned_abs))
                .then_with(|| a.path.cmp(&b.path))
        });
        Ok(Comparison {
            from: from.clone(),
            to: to.clone(),
            same_filesystem,
            changes,
        })
    }
    pub fn footprint(&self) -> Result<u64> {
        let mut total = 0;
        for entry in fs::read_dir(&self.state)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() {
                total += meta.blocks() * 512;
            }
        }
        Ok(total)
    }
}

fn absent_is_known(index: &Index, path: &Path) -> bool {
    path.parent()
        .and_then(|p| p.ancestors().find_map(|p| index.nodes.get(p)))
        .is_some_and(|n| n.measured() && n.flags & COLLAPSED == 0)
}
fn missing(index: &Index, path: &Path) -> Option<Counts> {
    absent_is_known(index, path).then_some(Counts {
        logical: 0,
        allocated: 0,
        complete: true,
    })
}
pub fn differences(before: &Index, after: &Index, at: u64, same_filesystem: bool) -> Vec<Change> {
    let mut result = vec![];
    for delta in before.nodes.diff(&after.nodes) {
        let (path, mut a, mut b) = match delta {
            im::ordmap::DiffItem::Add(p, n) => (p, missing(before, p), Some(Counts::from(n))),
            im::ordmap::DiffItem::Update {
                old: (_, a),
                new: (p, b),
            } => (p, Some(Counts::from(a)), Some(Counts::from(b))),
            im::ordmap::DiffItem::Remove(p, n) => (p, Some(Counts::from(n)), missing(after, p)),
        };
        if !same_filesystem {
            if let Some(n) = a.as_mut() {
                n.complete = false;
            }
            if let Some(n) = b.as_mut() {
                n.complete = false;
            }
        }
        if a != b {
            result.push(Change {
                path: path.clone(),
                before: a,
                after: b,
                at,
            });
        }
    }
    result
}
