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
    #[serde(default)]
    pub base_directories: usize,
    #[serde(default)]
    pub patches: u64,
    #[serde(default)]
    pub patch_bytes: u64,
    #[serde(skip)]
    pending: Option<PendingPatch>,
}
#[derive(Clone, Debug)]
struct PendingPatch {
    compressed: Vec<u8>,
    digest: String,
}
#[derive(Serialize, Deserialize)]
struct DeltaRow {
    path: Vec<u8>,
    node: Option<Node>,
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
            base_directories: index.nodes.len(),
            patches: 0,
            patch_bytes: 0,
            pending: None,
        })
    }
    pub fn update(state: &Path, index: &Index, previous: Option<(&Self, &Index)>) -> Result<Self> {
        let Some((generation, old)) = previous.filter(|_| !index.full_scan) else {
            return Self::write(state, index);
        };
        let mut encoded = GzEncoder::new(Vec::new(), Compression::fast());
        serde_json::to_writer(
            &mut encoded,
            &Header {
                schema: "mactrim.rust.delta.v1".into(),
                policy: POLICY.into(),
                root: bytes(&index.root).to_vec(),
                created: now(),
            },
        )?;
        encoded.write_all(b"\n")?;
        for delta in old.nodes.diff(&index.nodes) {
            let (path, node) = match delta {
                im::ordmap::DiffItem::Add(p, n)
                | im::ordmap::DiffItem::Update { new: (p, n), .. } => (p, Some(n.clone())),
                im::ordmap::DiffItem::Remove(p, _) => (p, None),
            };
            serde_json::to_writer(
                &mut encoded,
                &DeltaRow {
                    path: bytes(path.strip_prefix(&index.root)?).to_vec(),
                    node,
                },
            )?;
            encoded.write_all(b"\n")?;
        }
        let compressed = encoded.finish()?;
        let base_bytes = private_file(&state.join(&generation.name), false)?
            .metadata()?
            .len();
        // Compact when retained delta bytes reach the measured checkpoint size.
        // This changes the representation, never the directories retained.
        if generation
            .patch_bytes
            .saturating_add(compressed.len() as u64)
            >= base_bytes
        {
            return Self::write(state, index);
        }
        let mut result = generation.clone();
        result.patches += 1;
        result.patch_bytes += compressed.len() as u64;
        result.created = now();
        result.directories = index.nodes.len();
        result.pending = Some(PendingPatch {
            digest: format!("{:x}", Sha256::digest(&compressed)),
            compressed,
        });
        Ok(result)
    }
    fn read_checkpoint(&self, state: &Path) -> Result<Index> {
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
            index.nodes.len()
                == if self.base_directories == 0 {
                    self.directories
                } else {
                    self.base_directories
                }
                && index.root_node().is_some(),
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
    #[serde(with = "crate::paths::list")]
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
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pending(path BLOB PRIMARY KEY, revision INTEGER NOT NULL, reason TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS observations(at INTEGER NOT NULL, logical INTEGER NOT NULL, allocated INTEGER NOT NULL, status INTEGER NOT NULL);")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS directory_history(bucket INTEGER NOT NULL,path BLOB NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(bucket,path));")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS tree_deltas(base TEXT NOT NULL,ordinal INTEGER NOT NULL,digest TEXT NOT NULL,compressed BLOB NOT NULL,PRIMARY KEY(base,ordinal));")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS capacity_history(bucket INTEGER PRIMARY KEY,at INTEGER NOT NULL,used INTEGER NOT NULL,available INTEGER NOT NULL);")?;
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
    pub fn configured_root(state: &Path) -> Result<Option<PathBuf>> {
        let database = state.join("service.sqlite3");
        if !database.exists() {
            return Ok(None);
        }
        let held = private_file(&database, false)?;
        let db =
            Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(database)?.ino(),
            "Database replaced while checking root"
        );
        let raw: Option<String> = db
            .query_row("SELECT value FROM meta WHERE key='root'", [], |r| r.get(0))
            .optional()?;
        raw.map(|s| {
            serde_json::from_str::<Vec<u8>>(&s)
                .map(from_bytes)
                .map_err(Into::into)
        })
        .transpose()
    }
    pub fn load(&self) -> Result<Option<Index>> {
        Self::load_database(&self.path, &self.db)
    }
    pub fn load_readonly(state: &Path) -> Result<Option<Index>> {
        let held = private_file(&state.join("service.sqlite3"), false)?;
        let db = Connection::open_with_flags(
            state.join("service.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(state.join("service.sqlite3"))?.ino(),
            "Database replaced while opening saved tree"
        );
        Self::load_database(state, &db)
    }
    fn load_database(state: &Path, db: &Connection) -> Result<Option<Index>> {
        let raw: Option<String> = db
            .query_row("SELECT value FROM meta WHERE key='generation'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(generation) = raw
            .map(|s| serde_json::from_str::<Generation>(&s))
            .transpose()?
        else {
            return Ok(None);
        };
        let mut index = generation.read_checkpoint(state)?;
        let mut query = db.prepare("SELECT ordinal,digest,compressed FROM tree_deltas WHERE base=? AND ordinal<=? ORDER BY ordinal")?;
        let mut rows = query.query(params![generation.name, sql_int(generation.patches)?])?;
        let mut expected = 1;
        while let Some(row) = rows.next()? {
            let ordinal: i64 = row.get(0)?;
            let digest: String = row.get(1)?;
            let data: Vec<u8> = row.get(2)?;
            ensure!(
                ordinal as u64 == expected && format!("{:x}", Sha256::digest(&data)) == digest,
                "Missing or corrupt tree delta; original preserved"
            );
            expected += 1;
            let mut decoded = BufReader::new(GzDecoder::new(data.as_slice()));
            let mut line = String::new();
            decoded.read_line(&mut line)?;
            let header: Header = serde_json::from_str(&line)?;
            ensure!(
                header.schema == "mactrim.rust.delta.v1"
                    && header.policy == POLICY
                    && header.root == bytes(&index.root),
                "Delta identity mismatch"
            );
            loop {
                line.clear();
                if decoded.read_line(&mut line)? == 0 {
                    break;
                }
                let delta: DeltaRow = serde_json::from_str(&line)?;
                let relative = from_bytes(delta.path);
                ensure!(
                    !relative.is_absolute()
                        && !relative
                            .components()
                            .any(|c| c == std::path::Component::ParentDir)
                        && !bytes(&relative).contains(&0),
                    "Escaped tree delta"
                );
                let path = index.root.join(relative);
                if let Some(node) = delta.node {
                    index.insert(path, node);
                } else {
                    index.remove_subtree(&path);
                }
            }
        }
        ensure!(
            expected == generation.patches + 1 && index.nodes.len() == generation.directories,
            "Incomplete tree delta chain"
        );
        for path in index.nodes.keys().filter(|p| *p != &index.root) {
            ensure!(
                path.parent().is_some_and(|p| index.nodes.contains_key(p)),
                "Disconnected delta tree"
            );
        }
        Ok(Some(index))
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
    pub fn record_interruption(&mut self, interruption: &Interruption) -> Result<()> {
        let tx = self.db.transaction()?;
        // Retain the latest cause across restarts without an unbounded event log.
        set(&tx, "last_interruption", interruption)?;
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
    pub fn history_days(&self) -> Result<u64> {
        Ok(self.get("history_days")?.unwrap_or(60))
    }
    pub fn set_history_days(&mut self, days: u64) -> Result<()> {
        ensure!(
            days > 0 && days.checked_mul(86400).is_some(),
            "Retention must be a positive number of days within the timestamp range"
        );
        let cutoff = now().saturating_sub(days * 86400);
        let tx = self.db.transaction()?;
        set(&tx, "history_days", &days)?;
        tx.execute(
            "DELETE FROM directory_history WHERE bucket<?",
            [sql_int(cutoff / 3600)?],
        )?;
        tx.execute("DELETE FROM observations WHERE at<?", [sql_int(cutoff)?])?;
        tx.execute(
            "DELETE FROM capacity_history WHERE at<?",
            [sql_int(cutoff)?],
        )?;
        tx.commit()?;
        Ok(())
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
        self.commit_changes(generation, work, index, &[])
    }
    pub fn commit_changes(
        &mut self,
        generation: &Generation,
        work: &Work,
        index: &Index,
        changes: &[crate::history::Change],
    ) -> Result<()> {
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
        if let Some(patch) = &generation.pending {
            ensure!(
                old.as_ref().is_some_and(
                    |o| o.name == generation.name && o.patches + 1 == generation.patches
                ),
                "Delta candidate no longer follows committed tree"
            );
            tx.execute(
                "INSERT INTO tree_deltas VALUES(?,?,?,?)",
                params![
                    generation.name,
                    sql_int(generation.patches)?,
                    patch.digest,
                    patch.compressed
                ],
            )?;
        } else {
            ensure!(generation.patches == 0, "Missing candidate delta");
            tx.execute("DELETE FROM tree_deltas", [])?;
        }
        set(&tx, "generation", generation)?;
        set(&tx, "applied", &work.cursor)?;
        set(&tx, "active", &Option::<Work>::None)?;
        {
            let unsettled: Regions = {
                let mut pending = tx.prepare("SELECT path FROM pending")?;
                let rows = pending.query_map([], |r| r.get::<_, Vec<u8>>(0).map(from_bytes))?;
                rows.collect::<Result<Vec<_>, _>>()?.into_iter().collect()
            };
            let mut statement=tx.prepare("INSERT INTO directory_history VALUES(?,?,?,?,?) ON CONFLICT(bucket,path) DO UPDATE SET after_json=excluded.after_json,at=excluded.at")?;
            for change in changes {
                let mut after = change.after.clone();
                if unsettled.intersects(&change.path)
                    && let Some(counts) = after.as_mut()
                {
                    counts.complete = false;
                }
                statement.execute(params![
                    sql_int(change.at / 3600)?,
                    bytes(&change.path),
                    serde_json::to_string(&change.before)?,
                    serde_json::to_string(&after)?,
                    sql_int(change.at)?
                ])?;
            }
        }
        let days = meta_u64(&tx, "history_days")?;
        let days = if days == 0 { 60 } else { days };
        tx.execute(
            "DELETE FROM directory_history WHERE bucket<?",
            [sql_int(
                generation.created.saturating_sub(days * 86400) / 3600,
            )?],
        )?;
        tx.execute(
            "DELETE FROM pending WHERE revision<=?",
            [sql_int(work.revision)?],
        )?;
        if let Some(n) = index.root_node() {
            // Hourly root observations supplement sparse directory deltas.
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
                    [sql_int(generation.created.saturating_sub(days * 86400))?],
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
    pub fn history(&self, scope: &Path, since: u64) -> Result<Vec<crate::history::Change>> {
        let mut statement=self.db.prepare("SELECT path,before_json,after_json,at FROM directory_history WHERE bucket>=? ORDER BY bucket,path")?;
        let rows = statement.query_map([sql_int(since / 3600)?], |r| {
            Ok((
                from_bytes(r.get(0)?),
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut combined: BTreeMap<PathBuf, crate::history::Change> = BTreeMap::new();
        for row in rows {
            let (path, before, after, at) = row?;
            if !path.starts_with(scope) {
                continue;
            }
            let after = serde_json::from_str(&after)?;
            if let Some(existing) = combined.get_mut(&path) {
                existing.after = after;
                existing.at = at as u64;
            } else {
                combined.insert(
                    path.clone(),
                    crate::history::Change {
                        path,
                        before: serde_json::from_str(&before)?,
                        after,
                        at: at as u64,
                    },
                );
            }
        }
        let mut result: Vec<_> = combined.into_values().collect();
        result.sort_unstable_by_key(|r| std::cmp::Reverse(r.growth().unwrap_or(i128::MIN)));
        Ok(result)
    }
    pub fn history_page(
        state: &Path,
        scope: &Path,
        since: u64,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<crate::history::Change>, bool)> {
        let database = state.join("service.sqlite3");
        let held = private_file(&database, false)?;
        let db =
            Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(&database)?.ino(),
            "History database replaced while opening"
        );
        let prefix = if scope == Path::new("/") {
            b"/".to_vec()
        } else {
            [bytes(scope), b"/"].concat()
        };
        let mut end = prefix.clone();
        *end.last_mut().unwrap() += 1;
        let mut statement = db.prepare("WITH scoped AS (
            SELECT path,before_json,after_json,at,
              ROW_NUMBER() OVER(PARTITION BY path ORDER BY bucket) AS first,
              ROW_NUMBER() OVER(PARTITION BY path ORDER BY bucket DESC) AS last
            FROM directory_history WHERE bucket>=?1 AND (path=?2 OR (path>=?3 AND path<?4))
          ), combined AS (
            SELECT path,MAX(CASE WHEN first=1 THEN before_json END) AS before_json,
              MAX(CASE WHEN last=1 THEN after_json END) AS after_json,MAX(at) AS at
            FROM scoped GROUP BY path
          ) SELECT path,before_json,after_json,at FROM combined
          ORDER BY CASE WHEN json_extract(before_json,'$.complete')=1 AND json_extract(after_json,'$.complete')=1 THEN 1 ELSE 0 END DESC,
            CASE WHEN json_extract(before_json,'$.complete')=1 AND json_extract(after_json,'$.complete')=1
              THEN json_extract(after_json,'$.allocated')-json_extract(before_json,'$.allocated') END DESC,path
          LIMIT ?5 OFFSET ?6")?;
        let mut rows = statement.query(params![
            sql_int(since / 3600)?,
            bytes(scope),
            prefix,
            end,
            sql_int(limit as u64 + 1)?,
            sql_int(offset as u64)?
        ])?;
        let mut changes = Vec::new();
        while let Some(row) = rows.next()? {
            let before: String = row.get(1)?;
            let after: String = row.get(2)?;
            changes.push(crate::history::Change {
                path: from_bytes(row.get(0)?),
                before: serde_json::from_str(&before)?,
                after: serde_json::from_str(&after)?,
                at: row.get::<_, i64>(3)? as u64,
            });
        }
        let more = changes.len() > limit;
        changes.truncate(limit);
        Ok((changes, more))
    }
    pub fn record_capacity(&mut self, at: u64, used: u64, available: u64) -> Result<()> {
        let days = self.history_days()?;
        let tx = self.db.transaction()?;
        tx.execute("INSERT INTO capacity_history VALUES(?,?,?,?) ON CONFLICT(bucket) DO UPDATE SET at=excluded.at,used=excluded.used,available=excluded.available",params![sql_int(at/3600)?,sql_int(at)?,sql_int(used)?,sql_int(available)?])?;
        tx.execute(
            "DELETE FROM capacity_history WHERE at<?",
            [sql_int(at.saturating_sub(days.saturating_mul(86400)))?],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn capacity_history(
        state: &Path,
        since: u64,
    ) -> Result<Vec<crate::history::CapacityPoint>> {
        let database = state.join("service.sqlite3");
        let held = private_file(&database, false)?;
        let db =
            Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        ensure!(
            held.metadata()?.ino() == fs::symlink_metadata(database)?.ino(),
            "Capacity database replaced while opening"
        );
        let (first, last): (Option<i64>, Option<i64>) = db.query_row(
            "SELECT MIN(at),MAX(at) FROM capacity_history WHERE at>=?",
            [sql_int(since)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (Some(first), Some(last)) = (first, last) else {
            return Ok(vec![]);
        };
        // At most one point per chart bin. The full hourly series remains in
        // SQLite; this is display downsampling, not a retention ceiling.
        let stride = ((last - first) / 120).max(3600);
        let mut query=db.prepare("SELECT at,used,available FROM capacity_history WHERE at IN (SELECT MAX(at) FROM capacity_history WHERE at>=?1 GROUP BY (at-?2)/?3 UNION SELECT MIN(at) FROM capacity_history WHERE at>=?1) ORDER BY at")?;
        let rows = query.query_map(params![sql_int(since)?, first, stride], |r| {
            Ok(crate::history::CapacityPoint {
                at: r.get::<_, i64>(0)? as u64,
                used: r.get::<_, i64>(1)? as u64,
                available: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
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
