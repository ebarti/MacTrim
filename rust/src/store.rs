//! Atomic compressed directory snapshots and read-only import of legacy trees.
use crate::model::*;
use anyhow::{Context, Result, ensure};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
}
#[derive(Serialize, Deserialize)]
struct DeltaRow {
    path: Vec<u8>,
    node: Option<Node>,
}
impl Generation {
    pub fn write(state: &Path, index: &Index) -> Result<Self> {
        Self::write_cancellable(state, index, &std::sync::atomic::AtomicBool::new(false))
    }
    pub fn write_cancellable(
        state: &Path,
        index: &Index,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        ensure!(
            !index.nodes.is_empty() && index.root_node().is_some(),
            "Refusing an empty directory tree"
        );
        let name = format!("tree-{}.gz", uuid::Uuid::new_v4());
        let pending = tempfile::NamedTempFile::new_in(state)?;
        pending
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let file = pending.reopen()?;
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
            crate::scan::check_cancelled(cancel)?;
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
        drop(output);
        let mut input = pending.reopen()?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            crate::scan::check_cancelled(cancel)?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        drop(input);
        crate::scan::check_cancelled(cancel)?;
        pending
            .persist_noclobber(state.join(&name))
            .map_err(|e| e.error)?;
        File::open(state)?.sync_all()?;
        Ok(Self {
            name,
            digest: format!("{:x}", hash.finalize()),
            directories: index.nodes.len(),
            created,
            base_directories: index.nodes.len(),
            patches: 0,
            patch_bytes: 0,
        })
    }
    pub(crate) fn read_checkpoint(&self, state: &Path) -> Result<Index> {
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

pub fn load_legacy(state: &Path) -> Result<Option<Index>> {
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
    load_database(state, &db)
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
    let mut rows = query.query(params![generation.name, i64::try_from(generation.patches)?])?;
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
