//! Durable invalidations plus a streaming compressed tree; no per-file database.
use crate::{model::*, regions::Regions};
use anyhow::{Context, Result, ensure};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}
fn from_bytes(value: Vec<u8>) -> PathBuf {
    std::ffi::OsString::from_vec(value).into()
}

pub fn prepare_private(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "State path must be absolute");
    let mut components = PathBuf::from("/");
    for component in path.components().skip(1) {
        components.push(component);
        match fs::symlink_metadata(&components) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "Unsafe state ancestor: {}",
                components.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&components)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o700,
        "State directory must be owned by you with mode 0700: {}",
        path.display()
    );
    Ok(())
}

pub fn private_file(path: &Path, create: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600
            && m.nlink() == 1,
        "Unsafe state file preserved: {}",
        path.display()
    );
    Ok(f)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Header {
    schema: String,
    policy: String,
    root: Vec<u8>,
    created: u64,
}
#[derive(Serialize, Deserialize)]
struct DiskRow {
    parent: i64,
    name: Vec<u8>,
    node: Node,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Generation {
    pub name: String,
    pub digest: String,
    pub directories: usize,
    pub created: u64,
}

impl Generation {
    pub fn write(state: &Path, index: &Index) -> Result<Self> {
        ensure!(
            !index.nodes.is_empty() && index.root_node().is_some(),
            "Refusing an empty directory tree"
        );
        let name = format!("tree-{}.gz", uuid::Uuid::new_v4());
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join(&name))?;
        let mut encoded = GzEncoder::new(BufWriter::new(file), Compression::fast());
        let created = now();
        serde_json::to_writer(
            &mut encoded,
            &Header {
                schema: "mactrim.rust.tree.v1".into(),
                policy: POLICY.into(),
                root: bytes(&index.root).to_vec(),
                created,
            },
        )?;
        encoded.write_all(b"\n")?;
        let mut ordinals: HashMap<&Path, usize> = HashMap::with_capacity(index.nodes.len());
        for (ordinal, (path, node)) in index.nodes.iter().enumerate() {
            let parent = if path == &index.root {
                -1
            } else {
                *ordinals
                    .get(path.parent().context("Missing parent")?)
                    .context("Disconnected directory tree")? as i64
            };
            let name = if parent == -1 {
                vec![]
            } else {
                path.file_name().unwrap().as_bytes().to_vec()
            };
            serde_json::to_writer(
                &mut encoded,
                &DiskRow {
                    parent,
                    name,
                    node: node.clone(),
                },
            )?;
            encoded.write_all(b"\n")?;
            ordinals.insert(path, ordinal);
        }
        let mut output = encoded.finish()?;
        output.flush()?;
        output.get_ref().sync_all()?;
        File::open(state)?.sync_all()?;
        let mut input = private_file(&state.join(&name), false)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(Self {
            name,
            digest: format!("{:x}", hash.finalize()),
            directories: index.nodes.len(),
            created,
        })
    }
    pub fn read(&self, state: &Path) -> Result<Index> {
        ensure!(valid_generation_name(&self.name), "Invalid generation path");
        let mut file = private_file(&state.join(&self.name), false)?;
        let before = file.metadata()?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == self.digest,
            "Index checksum mismatch; original preserved"
        );
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut stream = BufReader::new(GzDecoder::new(&file));
        let mut line = String::new();
        stream.read_line(&mut line)?;
        let header: Header = serde_json::from_str(&line)?;
        ensure!(
            header.schema == "mactrim.rust.tree.v1" && header.policy == POLICY,
            "Unsupported tree policy"
        );
        let mut index = Index::new(from_bytes(header.root));
        let mut paths: Vec<PathBuf> = Vec::new();
        loop {
            line.clear();
            if stream.read_line(&mut line)? == 0 {
                break;
            }
            let row: DiskRow = serde_json::from_str(&line)?;
            let path = if paths.is_empty() {
                ensure!(row.parent == -1, "Root record missing");
                index.root.clone()
            } else {
                ensure!(
                    row.parent >= 0 && (row.parent as usize) < paths.len(),
                    "Invalid parent link"
                );
                let name = from_bytes(row.name);
                ensure!(
                    name.components().count() == 1
                        && name.file_name().is_some()
                        && !bytes(&name).contains(&0),
                    "Invalid directory name"
                );
                paths[row.parent as usize].join(name)
            };
            ensure!(
                !index.nodes.contains_key(&path) && path.starts_with(&index.root),
                "Escaped or duplicate directory"
            );
            index.insert(path.clone(), row.node);
            paths.push(path);
        }
        ensure!(
            index.nodes.len() == self.directories && index.root_node().is_some(),
            "Incomplete directory generation"
        );
        let after = file.metadata()?;
        ensure!(
            before.len() == after.len()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.mtime() == after.mtime()
                && before.ctime_nsec() == after.ctime_nsec()
                && before.ctime() == after.ctime(),
            "Index changed during read"
        );
        Ok(index)
    }
}

fn valid_generation_name(name: &str) -> bool {
    name.strip_prefix("tree-")
        .and_then(|s| s.strip_suffix(".gz"))
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Work {
    pub revision: u64,
    pub cursor: u64,
    pub paths: Vec<PathBuf>,
    pub reason: String,
    pub identity: Identity,
}

pub struct Store {
    db: Connection,
    pub path: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        prepare_private(path)?;
        let lock = private_file(&path.join("writer.lock"), true)?;
        lock.try_lock_exclusive()
            .context("Another Rust storage service owns this state")?;
        let database = path.join("service.sqlite3");
        let held = private_file(&database, true)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let p = path.join(format!("service.sqlite3{suffix}"));
            if fs::symlink_metadata(&p).is_ok() {
                private_file(&p, false)?;
            }
        }
        let db = Connection::open(&database)?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(&database)?.ino(),
            "Database replaced during open"
        );
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pending(path BLOB PRIMARY KEY, revision INTEGER NOT NULL, reason TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(at INTEGER NOT NULL, logical INTEGER NOT NULL, allocated INTEGER NOT NULL, status INTEGER NOT NULL);")?;
        Ok(Self {
            db,
            path: path.to_owned(),
            _lock: lock,
        })
    }
    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let raw: Option<String> = self
            .db
            .query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0))
            .optional()?;
        raw.map(|s| serde_json::from_str(&s).context("Invalid service metadata"))
            .transpose()
    }
    pub fn bind(&mut self, root: &Path, identity: &Identity, checkpoint: u64) -> Result<bool> {
        let old_root: Option<Vec<u8>> = self.get("root")?;
        if let Some(old) = old_root {
            ensure!(
                old == bytes(root),
                "This state belongs to another scan root"
            );
        }
        let old: Option<Identity> = self.get("identity")?;
        let changed = old.as_ref() != Some(identity);
        let cursor: u64 = self.get("cursor")?.unwrap_or(checkpoint);
        let tx = self.db.transaction()?;
        set(&tx, "root", &bytes(root))?;
        set(&tx, "identity", identity)?;
        if changed || cursor > checkpoint {
            set(&tx, "cursor", &checkpoint)?;
            set(&tx, "applied", &0u64)?;
            set(&tx, "active", &Option::<Work>::None)?;
            let revision = meta_u64(&tx, "revision")? + 1;
            set(&tx, "revision", &revision)?;
            tx.execute("DELETE FROM pending", [])?;
            tx.execute(
                "INSERT INTO pending VALUES(?,?,?)",
                params![
                    bytes(root),
                    sql_int(revision)?,
                    "Initial baseline or changed volume history; full reconciliation"
                ],
            )?;
        }
        tx.commit()?;
        Ok(changed)
    }
    pub fn generation(&self) -> Result<Option<Generation>> {
        self.get("generation")
    }
    pub fn load(&self) -> Result<Option<Index>> {
        self.generation()?.map(|g| g.read(&self.path)).transpose()
    }
    pub fn cursor(&self) -> Result<u64> {
        Ok(self.get("cursor")?.unwrap_or(0))
    }
    pub fn applied(&self) -> Result<u64> {
        Ok(self.get("applied")?.unwrap_or(0))
    }
    pub fn set_paused(&mut self, paused: bool) -> Result<()> {
        let tx = self.db.transaction()?;
        set(&tx, "paused", &paused)?;
        tx.commit()?;
        Ok(())
    }
    pub fn set_full_at(&mut self, at: u64) -> Result<()> {
        let tx = self.db.transaction()?;
        set(&tx, "full_at", &at)?;
        tx.commit()?;
        Ok(())
    }
    pub fn full_at(&self) -> Result<u64> {
        Ok(self.get("full_at")?.unwrap_or(0))
    }
    pub fn ingest(
        &mut self,
        cursor: u64,
        paths: impl IntoIterator<Item = PathBuf>,
        reason: &str,
    ) -> Result<()> {
        let root = from_bytes(self.get("root")?.context("Unbound service state")?);
        let tx = self.db.transaction()?;
        let previous_cursor = meta_u64(&tx, "cursor")?;
        ensure!(
            cursor >= previous_cursor,
            "Refusing a backwards event cursor"
        );
        let revision = meta_u64(&tx, "revision")? + 1;
        let mut pending: BTreeMap<PathBuf, (u64, String)> = {
            let mut stmt = tx.prepare("SELECT path,revision,reason FROM pending")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    from_bytes(r.get(0)?),
                    (r.get::<_, i64>(1)? as u64, r.get(2)?),
                ))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        for path in paths {
            ensure!(
                path.is_absolute()
                    && path.starts_with(&root)
                    && !path
                        .components()
                        .any(|c| c == std::path::Component::ParentDir),
                "Invalid dirty path"
            );
            if let Some(ancestor) = path
                .ancestors()
                .find(|p| pending.contains_key(*p))
                .map(Path::to_owned)
            {
                pending.insert(ancestor, (revision, reason.into()));
            } else {
                let descendants: Vec<_> = pending
                    .range(path.clone()..)
                    .take_while(|(p, _)| p.starts_with(&path))
                    .map(|(p, _)| p.clone())
                    .collect();
                for p in descendants {
                    pending.remove(&p);
                }
                pending.insert(path, (revision, reason.into()));
            }
        }
        // This bounds only the invalidation queue. Coarsening preserves every
        // affected path by invalidating the root, never by dropping an entry.
        if pending.keys().map(|p| bytes(p).len() + 96).sum::<usize>() > 1024 * 1024 {
            pending = BTreeMap::from([(
                root,
                (
                    revision,
                    "Pending regions coarsened; full reconciliation".into(),
                ),
            )]);
        }
        tx.execute("DELETE FROM pending", [])?;
        {
            let mut stmt = tx.prepare("INSERT INTO pending VALUES(?,?,?)")?;
            for (p, (rev, why)) in pending {
                stmt.execute(params![bytes(&p), sql_int(rev)?, why])?;
            }
        }
        set(&tx, "cursor", &cursor)?;
        set(&tx, "revision", &revision)?;
        tx.commit()?;
        Ok(())
    }
    pub fn work(&self) -> Result<Work> {
        let mut stmt = self
            .db
            .prepare("SELECT path,reason FROM pending ORDER BY path")?;
        let rows = stmt.query_map([], |r| Ok((from_bytes(r.get(0)?), r.get::<_, String>(1)?)))?;
        let mut paths = Vec::new();
        let mut reason = String::new();
        for row in rows {
            let (p, why) = row?;
            paths.push(p);
            if reason.is_empty() {
                reason = why;
            }
        }
        if let Some(active) = self.get::<Option<Work>>("active")?.flatten() {
            paths.extend(active.paths);
            if reason.is_empty() {
                reason = active.reason;
            }
        }
        let paths: Regions = paths.into_iter().collect();
        Ok(Work {
            revision: self.get("revision")?.unwrap_or(0),
            cursor: self.cursor()?,
            paths: paths.paths().cloned().collect(),
            reason,
            identity: self.get("identity")?.context("Missing volume identity")?,
        })
    }
    pub fn claim(&mut self) -> Result<Work> {
        // Freeze work durably and empty the intake queue. New changes during a
        // whole-root baseline must remain small changed regions, rather than
        // being merged into the in-flight root and forcing another full walk.
        let work = self.work()?;
        let tx = self.db.transaction()?;
        set(&tx, "active", &work)?;
        tx.execute("DELETE FROM pending", [])?;
        tx.commit()?;
        Ok(work)
    }
    pub fn commit(&mut self, generation: &Generation, work: &Work, index: &Index) -> Result<()> {
        ensure!(
            self.get::<Identity>("identity")?.as_ref() == Some(&work.identity),
            "Volume identity changed while measuring; candidate not committed"
        );
        ensure!(
            generation.directories == index.nodes.len(),
            "Generation does not match candidate"
        );
        ensure!(
            self.path.join(&generation.name).is_file() && valid_generation_name(&generation.name),
            "Missing generation"
        );
        let old = self.generation()?;
        let tx = self.db.transaction()?;
        set(&tx, "generation", generation)?;
        set(&tx, "applied", &work.cursor)?;
        set(&tx, "active", &Option::<Work>::None)?;
        tx.execute(
            "DELETE FROM pending WHERE revision<=?",
            [sql_int(work.revision)?],
        )?;
        if let Some(n) = index.root_node() {
            // Hourly root observations are small; detailed history remains in
            // the existing app until the History migration is complete.
            let last: Option<i64> =
                tx.query_row("SELECT MAX(at) FROM observations", [], |r| r.get(0))?;
            if last.is_none_or(|t| generation.created.saturating_sub(t as u64) >= 3600) {
                tx.execute(
                    "INSERT INTO observations VALUES(?,?,?,?)",
                    params![
                        sql_int(generation.created)?,
                        sql_int(n.logical)?,
                        sql_int(n.allocated)?,
                        n.status
                    ],
                )?;
                tx.execute(
                    "DELETE FROM observations WHERE at<?",
                    [sql_int(generation.created.saturating_sub(60 * 86400))?],
                )?;
            }
        }
        tx.commit()?;
        if let Some(old) = old.filter(|old| old.name != generation.name)
            && valid_generation_name(&old.name)
            && private_file(&self.path.join(&old.name), false).is_ok()
        {
            fs::remove_file(self.path.join(old.name))?;
            File::open(&self.path)?.sync_all()?;
        }
        Ok(())
    }
    pub fn footprint(&self) -> Result<u64> {
        let mut size = fs::metadata(&self.path)?.blocks() * 512;
        for entry in fs::read_dir(&self.path)? {
            size += entry?.metadata()?.blocks() * 512;
        }
        Ok(size)
    }
    pub fn reap_orphans(&self) -> Result<()> {
        let current = self.generation()?.map(|g| g.name);
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if valid_generation_name(&name) && current.as_ref() != Some(&name) {
                private_file(&entry.path(), false)?;
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

fn set<T: Serialize + ?Sized>(tx: &rusqlite::Transaction<'_>, key: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn meta_u64(tx: &rusqlite::Transaction<'_>, key: &str) -> Result<u64> {
    let value: Option<String> = tx
        .query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0))
        .optional()?;
    Ok(value
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or(0))
}
fn sql_int(value: u64) -> Result<i64> {
    i64::try_from(value).context("Database integer overflow")
}
