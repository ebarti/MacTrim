//! A terminal-owned scan worker. No sockets, detached processes or event input.
use crate::{
    filesystem,
    history::{CapacityPoint, Change},
    model::*,
    scan,
    snapshots::{Capture, Comparison, Snapshot, Snapshots},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

#[derive(Clone, Debug)]
pub enum Request {
    Status,
    List {
        path: PathBuf,
        offset: usize,
        limit: usize,
        logical: bool,
        anchor: Option<PathBuf>,
    },
    History {
        path: PathBuf,
        from: Option<u64>,
        to: Option<u64>,
        offset: usize,
        limit: usize,
    },
    Scan,
    Cancel,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    #[serde(with = "crate::paths")]
    pub root: PathBuf,
    pub phase: String,
    pub running: bool,
    pub loading: bool,
    pub directories: usize,
    pub index_bytes: u64,
    pub visited: u64,
    pub last_saved: u64,
    pub root_node: Option<Node>,
    pub filesystem_used: u64,
    pub filesystem_available: u64,
    pub observed_allocated: u64,
    pub observed_logical: u64,
    #[serde(with = "crate::paths")]
    pub current_path: PathBuf,
    pub error: Option<String>,
    pub warning: Option<String>,
    pub snapshot_id: Option<u64>,
    pub scan_count: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    #[serde(with = "crate::paths")]
    pub path: PathBuf,
    pub node: Node,
    pub directory: bool,
}
struct Ranked(u64, Row);
impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}
impl Eq for Ranked {}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .0
            .cmp(&self.0)
            .then_with(|| self.1.path.cmp(&other.1.path))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Reply {
    pub status: Status,
    pub rows: Vec<Row>,
    pub more: bool,
    pub message: String,
    pub history: Vec<Change>,
    pub capacity_history: Vec<CapacityPoint>,
    pub snapshots: Vec<Snapshot>,
    pub compare_from: Option<Snapshot>,
    pub compare_to: Option<Snapshot>,
    pub same_filesystem: Option<bool>,
    pub scope: Option<Node>,
    pub offset: usize,
}
struct Public {
    status: Status,
    index: Option<Arc<Index>>,
}
struct Worker {
    handle: Option<JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}
#[derive(PartialEq, Eq)]
struct ListingKey {
    path: PathBuf,
    logical: bool,
    offset: usize,
    limit: usize,
    anchor: Option<PathBuf>,
    scan: u64,
}
struct CachedListing {
    key: ListingKey,
    rows: Vec<Row>,
    more: bool,
    offset: usize,
}
struct CachedComparison {
    scope: PathBuf,
    from: u64,
    to: u64,
    value: Arc<Comparison>,
}
pub struct Session {
    pub root: PathBuf,
    pub state: PathBuf,
    public: Arc<RwLock<Public>>,
    progress: Arc<Mutex<Progress>>,
    worker: Mutex<Worker>,
    closed: AtomicBool,
    history: Mutex<Option<CachedComparison>>,
    listing: Mutex<Option<CachedListing>>,
}
impl Session {
    pub fn new(state: PathBuf, root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            state,
            root: root.clone(),
            public: Arc::new(RwLock::new(Public {
                status: Status {
                    root: root.clone(),
                    phase: "Ready to scan".into(),
                    ..Status::default()
                },
                index: None,
            })),
            progress: Arc::new(Mutex::new(Progress {
                view: root,
                ..Progress::default()
            })),
            worker: Mutex::new(Worker {
                handle: None,
                cancel: Arc::new(AtomicBool::new(false)),
            }),
            closed: AtomicBool::new(false),
            history: Mutex::new(None),
            listing: Mutex::new(None),
        })
    }
    pub fn start_scan(self: &Arc<Self>) -> Result<bool> {
        let mut worker = self.worker.lock().unwrap();
        ensure!(
            !self.closed.load(Ordering::Relaxed),
            "Terminal scan session is closing"
        );
        if worker.handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return Ok(false);
        }
        if let Some(old) = worker.handle.take() {
            let _ = old.join();
        }
        worker.cancel = Arc::new(AtomicBool::new(false));
        let cancel = worker.cancel.clone();
        {
            let mut live = self.progress.lock().unwrap();
            let view = live.view.clone();
            *live = Progress {
                view,
                phase: "Loading previous scan".into(),
                ..Progress::default()
            };
            let mut public = self.public.write().unwrap();
            public.status.running = true;
            public.status.loading = true;
            public.status.error = None;
            public.status.warning = None;
            public.status.phase = "Loading previous scan".into();
        }
        let (root, state, public, progress) = (
            self.root.clone(),
            self.state.clone(),
            self.public.clone(),
            self.progress.clone(),
        );
        worker.handle = Some(
            thread::Builder::new()
                .name("mactrim-terminal-scan".into())
                .spawn(move || {
                    let result = (|| -> Result<()> {
                        let mut catalog = Snapshots::open(&state)?;
                        scan::check_cancelled(&cancel)?;
                        let previous = catalog.latest(&root)?;
                        if let Some(previous) = previous {
                            let already_loaded =
                                public.read().unwrap().status.snapshot_id == Some(previous.id);
                            if !already_loaded {
                                match catalog.load(&previous) {
                                    Ok(index)=>{
                                        let index=Arc::new(index);
                                        let mut p=public.write().unwrap();
                                        p.index=Some(index.clone());
                                        apply_snapshot(&mut p.status,&previous,index.root_node().cloned());
                                    },
                                    Err(error)=>{public.write().unwrap().status.warning=Some(format!("Previous saved tree preserved but unavailable for browsing: {error:#}"));}
                                }

                            }
                        }
                        {
                            let mut p = public.write().unwrap();
                            if let Some(warning)=catalog.import_warning()? {p.status.warning=Some(warning);}
                            p.status.loading = false;
                            p.status.scan_count = catalog.list(Some(&root))?.len();
                        }
                        scan::check_cancelled(&cancel)?;
                        let capture = Capture::begin(&root)?;
                        if let Ok((used, available)) = filesystem::capacity(&root) {
                            let mut p = public.write().unwrap();
                            p.status.filesystem_used = used;
                            p.status.filesystem_available = available;
                        }
                        progress.lock().unwrap().phase =
                            "Full scan: measuring metadata at every depth".into();
                        let index = Arc::new(scan::full(
                            &root,
                            std::slice::from_ref(&state),
                            &cancel,
                            Some(&progress),
                        )?);
                        scan::check_cancelled(&cancel)?;
                        progress.lock().unwrap().phase = "Saving completed scan".into();
                        let saved = catalog.save(&index, &capture, &cancel)?;
                        let mut p = public.write().unwrap();
                        apply_snapshot(&mut p.status, &saved, index.root_node().cloned());
                        p.status.index_bytes = catalog.footprint()?;
                        p.status.scan_count = catalog.list(Some(&root))?.len();
                        p.status.phase =
                            format!("Scan #{} saved ({})", saved.id, saved.coverage_name());
                        p.index = Some(index);
                        Ok(())
                    })();
                    let mut p = public.write().unwrap();
                    p.status.running = false;
                    p.status.loading = false;
                    if let Err(error) = result {
                        if error.is::<scan::Cancelled>() {
                            p.status.phase = "Scan cancelled; completed scans preserved".into();
                        } else {
                            p.status.phase = "Scan failed; completed scans preserved".into();
                            p.status.error = Some(format!("{error:#}"));
                        }
                    }
                })?,
        );
        Ok(true)
    }
    pub fn cancel(&self) {
        self.worker
            .lock()
            .unwrap()
            .cancel
            .store(true, Ordering::Relaxed);
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let mut worker = self.worker.lock().unwrap();
        worker.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = worker.handle.take() {
            let _ = handle.join();
        }
    }
    pub fn status(&self) -> Status {
        let live = self.progress.lock().unwrap();
        let mut status = self.public.read().unwrap().status.clone();
        status.visited = live.visited;
        status.current_path = live.current.clone();
        status.observed_allocated = live.allocated;
        status.observed_logical = live.logical;
        if status.running && !status.loading && !live.phase.is_empty() {
            status.phase = live.phase.clone();
        }
        status
    }
    pub fn request(self: &Arc<Self>, request: &Request) -> Result<Reply> {
        match request {
            Request::Status => Ok(Reply {
                status: self.status(),
                ..Reply::default()
            }),
            Request::Scan => {
                let started = self.start_scan()?;
                Ok(Reply {
                    status: self.status(),
                    message: if started {
                        "Full scan started; completed scans save automatically"
                    } else {
                        "A full scan is already running; navigation keeps its progress"
                    }
                    .into(),
                    ..Reply::default()
                })
            }
            Request::Cancel => {
                self.cancel();
                Ok(Reply {
                    status: self.status(),
                    message: "Cancellation requested; earlier completed scans remain saved".into(),
                    ..Reply::default()
                })
            }
            Request::List {
                path,
                offset,
                limit,
                logical,
                anchor,
            } => {
                valid_path(&self.root, path)?;
                ensure!(*limit > 0 && *limit <= 500, "Page size must be 1..500");
                let status = self.status();
                {
                    let mut live = self.progress.lock().unwrap();
                    if live.view != *path {
                        live.view = path.clone();
                        live.rows.clear();
                    }
                }
                let index = self.public.read().unwrap().index.clone();
                let mut reply = Reply {
                    status,
                    scope: index.as_ref().and_then(|i| i.nodes.get(path)).cloned(),
                    ..Reply::default()
                };
                let live = self.progress.lock().unwrap().clone();
                let observed = if index.is_none() && reply.status.running && live.view == *path {
                    let mut i = Index::new(path.clone());
                    for (p, n) in live.rows {
                        i.insert(p, n);
                    }
                    Some(i)
                } else {
                    None
                };
                let selected = observed.as_ref().or(index.as_deref());
                let key = if !reply.status.running {
                    reply.status.snapshot_id.map(|scan| ListingKey {
                        path: path.clone(),
                        logical: *logical,
                        offset: *offset,
                        limit: *limit,
                        anchor: anchor.clone(),
                        scan,
                    })
                } else {
                    None
                };
                let mut listing = self.listing.lock().unwrap();
                if let (Some(key), Some(cached)) = (&key, listing.as_ref())
                    && *key == cached.key
                {
                    reply.rows = cached.rows.clone();
                    reply.more = cached.more;
                    reply.offset = cached.offset;
                } else {
                    (reply.rows, reply.more, reply.offset) = directory_rows(
                        selected,
                        path,
                        *logical,
                        *offset,
                        *limit,
                        anchor.as_deref(),
                    )?;
                    *listing = key.map(|key| CachedListing {
                        key,
                        rows: reply.rows.clone(),
                        more: reply.more,
                        offset: reply.offset,
                    });
                }
                Ok(reply)
            }
            Request::History {
                path,
                from,
                to,
                offset,
                limit,
            } => {
                valid_path(&self.root, path)?;
                let mut cached = self.history.lock().unwrap();
                history_reply(&self.state, path, *from, *to, *offset, *limit, &mut cached).map(
                    |mut r| {
                        r.status = self.status();
                        r
                    },
                )
            }
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}
fn apply_snapshot(status: &mut Status, snapshot: &Snapshot, node: Option<Node>) {
    status.snapshot_id = Some(snapshot.id);
    status.last_saved = snapshot.finished;
    status.directories = snapshot.directories;
    status.root_node = node;
    status.filesystem_used = snapshot.filesystem_used;
    status.filesystem_available = snapshot.filesystem_available;
}
fn valid_path(root: &Path, path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.starts_with(root)
            && !path.components().any(|c| c == Component::ParentDir),
        "Path outside scan scope"
    );
    Ok(())
}
pub fn history(
    state: &Path,
    path: &Path,
    from: Option<u64>,
    to: Option<u64>,
    offset: usize,
    limit: usize,
) -> Result<Reply> {
    history_reply(state, path, from, to, offset, limit, &mut None)
}
fn history_reply(
    state: &Path,
    path: &Path,
    from: Option<u64>,
    to: Option<u64>,
    offset: usize,
    limit: usize,
    cached: &mut Option<CachedComparison>,
) -> Result<Reply> {
    ensure!(
        limit > 0 && limit <= 500,
        "History page size must be 1..500"
    );
    let Some(catalog) = Snapshots::read_only(state)? else {
        return Ok(Reply {
            message: "No completed scans yet".into(),
            ..Reply::default()
        });
    };
    let all = catalog.list(None)?;
    let root = if let Some(id) = to {
        catalog.get(id)?.root
    } else {
        all.iter()
            .find(|s| path.starts_with(&s.root))
            .map(|s| s.root.clone())
            .unwrap_or_else(|| path.to_owned())
    };
    let snapshots: Vec<_> = all.into_iter().filter(|s| s.root == root).collect();
    let capacity_history = snapshots
        .iter()
        .rev()
        .filter(|s| !s.imported)
        .map(|s| CapacityPoint {
            at: s.finished,
            used: s.filesystem_used,
            available: s.filesystem_available,
        })
        .collect();
    let mut reply = Reply {
        snapshots,
        capacity_history,
        offset,
        ..Reply::default()
    };
    let Some((a, b)) = catalog.endpoints(path, from, to)? else {
        reply.message = "Complete two scans of this root to compare them".into();
        return Ok(reply);
    };
    let same = cached
        .as_ref()
        .is_some_and(|c| c.scope == path && c.from == a.id && c.to == b.id);
    if !same {
        *cached = Some(CachedComparison {
            scope: path.to_owned(),
            from: a.id,
            to: b.id,
            value: Arc::new(catalog.compare(path, &a, &b)?),
        });
    }
    let comparison = &cached.as_ref().unwrap().value;
    reply.history = comparison
        .changes
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();
    reply.more = comparison.changes.len() > offset.saturating_add(limit);
    reply.message =
        "Saved scan comparison; nested directory totals overlap; incomplete growth is unknown"
            .into();
    reply.compare_from = Some(a);
    reply.compare_to = Some(b);
    reply.same_filesystem = Some(comparison.same_filesystem);
    Ok(reply)
}

pub fn state_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute() && !path.components().any(|c| c == Component::ParentDir),
        "State path must be absolute without '..'"
    );
    if fs::symlink_metadata(path).is_ok() {
        ensure!(!path.is_symlink(), "State directory cannot be a symlink");
        return fs::canonicalize(path).map_err(Into::into);
    }
    let parent = state_path(path.parent().context("No state parent")?)?;
    Ok(parent.join(path.file_name().context("No state name")?))
}

pub fn directory_rows(
    index: Option<&Index>,
    path: &Path,
    logical: bool,
    offset: usize,
    limit: usize,
    anchor: Option<&Path>,
) -> Result<(Vec<Row>, bool, usize)> {
    ensure!(limit > 0, "Page size must be positive");
    let anchor = anchor.filter(|p| p.parent() == Some(path)).and_then(|p| {
        index
            .and_then(|i| i.nodes.get(p))
            .map(|n| Row {
                path: p.to_owned(),
                node: n.clone(),
                directory: true,
            })
            .or_else(|| {
                let m = fs::symlink_metadata(p).ok()?;
                if m.is_dir() {
                    return None;
                }
                Some(Row {
                    path: p.to_owned(),
                    directory: false,
                    node: Node {
                        logical: if m.is_file() { m.len() } else { 0 },
                        allocated: if m.is_file() { m.blocks() * 512 } else { 0 },
                        status: if m.is_file() { 0 } else { 1 },
                        ..Node::default()
                    },
                })
            })
    });
    let score = |r: &Row| {
        if logical {
            r.node.logical
        } else {
            r.node.allocated
        }
    };
    let mut heap = std::collections::BinaryHeap::new();
    let mut before = std::collections::BinaryHeap::new();
    let mut after = std::collections::BinaryHeap::new();
    let mut rank = 0usize;
    let mut total = 0usize;
    let cutoff = offset.saturating_add(limit);
    let mut keep = |row: Row| {
        total += 1;
        let item = Ranked(score(&row), row);
        if let Some(anchor) = &anchor {
            if item.1.path == anchor.path {
                return;
            }
            let ordering = item
                .0
                .cmp(&score(anchor))
                .reverse()
                .then_with(|| item.1.path.cmp(&anchor.path));
            if ordering.is_lt() {
                rank += 1;
                before.push(std::cmp::Reverse(item));
                if before.len() >= limit {
                    before.pop();
                }
            } else {
                after.push(item);
                if after.len() >= limit {
                    after.pop();
                }
            }
        } else {
            heap.push(item);
            if heap.len() > cutoff {
                heap.pop();
            }
        }
    };
    if let Some(index) = index {
        for p in index.children.get(path).into_iter().flatten() {
            if let Some(n) = index.nodes.get(p) {
                keep(Row {
                    path: p.clone(),
                    node: n.clone(),
                    directory: true,
                });
            }
        }
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                if index.is_none_or(|i| !i.nodes.contains_key(&entry.path())) {
                    keep(Row {
                        path: entry.path(),
                        directory: true,
                        node: Node {
                            status: 4,
                            ..Node::default()
                        },
                    });
                }
                continue;
            }
            let regular = meta.is_file() && !meta.file_type().is_symlink();
            keep(Row {
                path: entry.path(),
                directory: false,
                node: Node {
                    logical: if regular { meta.len() } else { 0 },
                    allocated: if regular { meta.blocks() * 512 } else { 0 },
                    status: if regular { 0 } else { 1 },
                    ..Node::default()
                },
            });
        }
    }
    let sort = |a: &Ranked, b: &Ranked| a.cmp(b);
    if let Some(anchor) = anchor {
        let actual_offset = rank / limit * limit;
        let pre = rank % limit;
        let mut before: Vec<_> = before.into_iter().map(|r| r.0).collect();
        before.sort_unstable_by(sort);
        let mut after: Vec<_> = after.into_iter().collect();
        after.sort_unstable_by(sort);
        let skip = before.len().saturating_sub(pre);
        let mut rows: Vec<_> = before.into_iter().skip(skip).map(|r| r.1).collect();
        rows.push(anchor);
        rows.extend(after.into_iter().take(limit - pre - 1).map(|r| r.1));
        return Ok((rows, total > actual_offset + limit, actual_offset));
    }
    let mut rows: Vec<_> = heap.into_iter().collect();
    rows.sort_unstable_by(sort);
    Ok((
        rows.into_iter()
            .skip(offset)
            .take(limit)
            .map(|r| r.1)
            .collect(),
        total > cutoff,
        offset,
    ))
}
