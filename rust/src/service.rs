use crate::{
    events,
    model::*,
    regions::Regions,
    scan,
    store::{self, Generation, Store, Work},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Status,
    History {
        #[serde(with = "crate::paths")]
        path: PathBuf,
        since: u64,
        offset: usize,
        limit: usize,
    },
    List {
        #[serde(with = "crate::paths")]
        path: PathBuf,
        offset: usize,
        limit: usize,
        logical: bool,
        #[serde(default)]
        #[serde(with = "crate::paths::optional")]
        anchor: Option<PathBuf>,
    },
    Refresh {
        full: bool,
    },
    Expand {
        #[serde(with = "crate::paths")]
        path: PathBuf,
    },
    Pause,
    Retention {
        days: u64,
    },
    Stop,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    #[serde(with = "crate::paths")]
    pub root: PathBuf,
    pub phase: String,
    pub running: bool,
    pub detail_running: bool,
    pub paused: bool,
    pub history_ready: bool,
    pub loading: bool,
    pub history_days: u64,
    pub received_cursor: u64,
    pub applied_cursor: u64,
    pub pending_regions: usize,
    pub directories: usize,
    pub index_bytes: u64,
    pub visited: u64,
    pub reused: u64,
    pub drop_signals: u64,
    pub recovered_replays: u64,
    pub last_saved: u64,
    pub root_node: Option<Node>,
    pub filesystem_used: u64,
    pub filesystem_available: u64,
    pub observed_allocated: u64,
    pub observed_logical: u64,
    #[serde(with = "crate::paths")]
    pub current_path: PathBuf,
    pub error: Option<String>,
    #[serde(default)]
    pub last_interruption: Option<Interruption>,
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
    pub history: Vec<crate::history::Change>,
    pub capacity_history: Vec<crate::history::CapacityPoint>,
    pub scope: Option<Node>,
    pub offset: usize,
}
struct Public {
    state: PathBuf,
    status: Status,
    index: Option<Arc<Index>>,
    detail: Option<Arc<Index>>,
}
type Command = (Request, mpsc::SyncSender<Result<Reply, String>>);
const USER_PAUSE: &str = "User requested Pause";

#[derive(Debug)]
pub struct ServiceUnavailable(io::Error);
impl std::fmt::Display for ServiceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Storage service is not running; use 'mactrim service start' (with the same --state for a custom service)")
    }
}
impl std::error::Error for ServiceUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
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
pub fn request(state: &Path, command: &Request) -> Result<Reply> {
    let socket = state.join("service.sock");
    let meta = match fs::symlink_metadata(&socket) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ServiceUnavailable(e).into()),
        Err(e) => return Err(e).context("Cannot inspect storage service socket"),
    };
    ensure!(
        meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() },
        "Unsafe service socket"
    );
    let mut stream = match UnixStream::connect(&socket) {
        Ok(stream) => stream,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(ServiceUnavailable(e).into());
        }
        Err(e) => return Err(e).context("Cannot connect to storage service"),
    };
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    serde_json::to_writer(&mut stream, command)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(16 * 1024 * 1024)
        .read_line(&mut line)?;
    let response: Result<Reply, String> = serde_json::from_str(&line)?;
    response.map_err(anyhow::Error::msg)
}

// The writer lock outlives socket removal during shutdown. Waiting for it keeps
// an immediately following Start from racing the previous service's database.
pub fn writer_active(state: &Path) -> Result<bool> {
    let file = match store::private_file(&state.join("writer.lock"), false) {
        Ok(file) => file,
        Err(e)
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(false);
        }
        Err(e) => return Err(e).context("Cannot inspect service writer lock"),
    };
    match fs2::FileExt::try_lock_shared(&file) {
        Ok(()) => Ok(false), // Dropping this descriptor releases the probe lock.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e).context("Cannot inspect service writer lock"),
    }
}

pub fn status(state: &Path) -> Result<Reply> {
    match request(state, &Request::Status) {
        Ok(reply) => Ok(reply),
        Err(e) if e.is::<ServiceUnavailable>() => {
            let transition = writer_active(state)?;
            Ok(Reply {
                status: Status {
                    phase: if transition {
                        "Starting or stopping"
                    } else {
                        "Stopped"
                    }
                    .into(),
                    ..Status::default()
                },
                message: if transition {
                    "Service is starting or stopping; retry shortly. Saved state is preserved."
                } else {
                    "Service is stopped; any saved index and pending work are preserved."
                }
                .into(),
                ..Reply::default()
            })
        }
        Err(e) => Err(e),
    }
}

pub fn stop(state: &Path) -> Result<Reply> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut acknowledged = None;
    loop {
        if acknowledged.is_none() {
            match request(state, &Request::Stop) {
                Ok(reply) => acknowledged = Some(reply),
                Err(e) if e.is::<ServiceUnavailable>() => {}
                Err(e) => return Err(e),
            }
        }
        if !writer_active(state)? {
            let message = if acknowledged.is_some() {
                "Service stopped; committed index and pending work preserved"
            } else {
                "Service is already stopped; saved index and pending work preserved"
            };
            let mut reply = acknowledged.unwrap_or_default();
            reply.status.pid = 0;
            reply.status.phase = "Stopped".into();
            reply.status.running = false;
            reply.status.detail_running = false;
            reply.message = message.into();
            return Ok(reply);
        }
        ensure!(
            Instant::now() < deadline,
            "Service has not stopped within 10 seconds; saved state preserved. Inspect {}",
            state.join("service.log").display()
        );
        thread::sleep(Duration::from_millis(50));
    }
}
fn directory_rows(
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

fn serve(
    stream: UnixStream,
    public: Arc<RwLock<Public>>,
    progress: Arc<Mutex<Progress>>,
    sender: mpsc::Sender<Command>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut input = BufReader::new(&stream).take(8193);
    let mut line = String::new();
    input.read_line(&mut line)?;
    ensure!(line.len() <= 8192, "Request too large");
    let request: Request = serde_json::from_str(&line)?;
    let reply = match request {
        Request::List {
            ref path,
            offset,
            limit,
            logical,
            anchor,
        } => {
            ensure!(
                path.is_absolute() && !path.components().any(|c| c == Component::ParentDir),
                "Invalid browsing path"
            );
            ensure!(limit > 0 && limit <= 500, "Page size must be 1..500");
            let (status, index, detail) = {
                let p = public.read().unwrap();
                ensure!(
                    path.starts_with(&p.status.root),
                    "Path outside service scope"
                );
                (p.status.clone(), p.index.clone(), p.detail.clone())
            };
            progress.lock().unwrap().view = path.clone();
            let selected = detail
                .as_deref()
                .filter(|d| path.starts_with(&d.root))
                .or(index.as_deref());
            let (mut rows, mut more, mut actual_offset) =
                directory_rows(selected, path, logical, offset, limit, anchor.as_deref())?;
            if status.running {
                let live = progress.lock().unwrap().clone();
                if live.view == *path && !live.rows.is_empty() && selected.is_none() {
                    let mut observed = Index::new(path.clone());
                    for (p, n) in live.rows {
                        observed.insert(p, n);
                    }
                    (rows, more, actual_offset) = directory_rows(
                        Some(&observed),
                        path,
                        logical,
                        offset,
                        limit,
                        anchor.as_deref(),
                    )?;
                }
            }
            Reply {
                status,
                rows,
                more,
                message: String::new(),
                history: vec![],
                capacity_history: vec![],
                scope: selected.and_then(|i| i.nodes.get(path)).cloned(),
                offset: actual_offset,
            }
        }
        Request::Status => Reply {
            status: public.read().unwrap().status.clone(),
            ..Reply::default()
        },
        Request::History {
            path,
            since,
            offset,
            limit,
        } => {
            let p = public.read().unwrap();
            let status = p.status.clone();
            let state = p.state.clone();
            drop(p);
            ensure!(
                path.starts_with(&status.root)
                    && !path.components().any(|c| c == Component::ParentDir),
                "History path outside scope"
            );
            ensure!(
                limit > 0 && limit <= 500,
                "History page size must be 1..500"
            );
            let (history, more) = Store::history_page(&state, &path, since, offset, limit)?;
            let capacity_history = Store::capacity_history(&state, since)?;
            Reply {
                status,
                history,
                capacity_history,
                more,
                offset,
                message: "Directory aggregates overlap; incomplete comparisons have unknown growth"
                    .into(),
                ..Reply::default()
            }
        }
        other => {
            let (tx, rx) = mpsc::sync_channel(1);
            sender.send((other, tx))?;
            rx.recv_timeout(Duration::from_secs(3))?
                .map_err(anyhow::Error::msg)?
        }
    };
    let mut stream = stream;
    serde_json::to_writer(&mut stream, &Ok::<_, String>(reply))?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn measurement_failed(
    store: &mut Store,
    paused: &mut bool,
    error: &mut Option<String>,
    phase: &mut String,
    failure: anyhow::Error,
) -> Result<()> {
    if failure.is::<scan::Cancelled>() {
        // Pause/Refresh already persisted the latest user intent. A late
        // cancellation must neither overwrite it nor become an error.
        *phase = if *paused {
            "Measurement paused; previous index preserved"
        } else {
            "Measurement interrupted; retrying pending work"
        }
        .into();
        return Ok(());
    }
    *error = Some(format!("{failure:#}"));
    *paused = true;
    store.set_paused(true)?;
    *phase = "Measurement paused after failure".into();
    Ok(())
}

fn interrupt_measurement(
    store: &mut Store,
    cancel: &AtomicBool,
    last: &mut Option<Interruption>,
    reason: &str,
) -> Result<()> {
    let already_interrupted = cancel.swap(true, Ordering::Relaxed);
    if !already_interrupted
        || (reason == USER_PAUSE && last.as_ref().is_none_or(|last| last.reason != reason))
    {
        let interruption = Interruption {
            at: store::now(),
            reason: reason.into(),
        };
        store.record_interruption(&interruption)?;
        *last = Some(interruption);
    }
    Ok(())
}

fn detail_finished(
    path: PathBuf,
    result: Result<Arc<Index>>,
    interrupted: bool,
    pending: &mut Option<PathBuf>,
    error: &mut Option<String>,
) -> Option<Arc<Index>> {
    match result {
        Ok(detail) if !interrupted => Some(detail),
        Ok(_) => {
            pending.get_or_insert(path);
            None
        }
        Err(e) if e.is::<scan::Cancelled>() => {
            pending.get_or_insert(path);
            None
        }
        Err(e) => {
            *error = Some(format!("{e:#}"));
            None
        }
    }
}

pub fn run(root: PathBuf, state: PathBuf, terminate: Arc<AtomicBool>) -> Result<()> {
    let root = fs::canonicalize(root)?;
    let state = state_path(&state)?;
    let mut store = Store::open(&state)?;
    let mut identity = events::identity(&root)?;
    store.bind(&root, &identity, events::current_id())?;
    let mut index = None;
    let mut loading = true;
    let (loaded_tx, loaded_rx) = mpsc::sync_channel(1);
    let load_state = state.clone();
    thread::Builder::new()
        .name("mactrim-index-loader".into())
        .spawn(move || {
            let _ = loaded_tx.send(Store::load_readonly(&load_state).map(|i| i.map(Arc::new)));
        })?;
    store.reap_orphans()?;
    if store.generation()?.is_none() && store.work()?.paths.is_empty() {
        store.ingest(store.cursor()?, [root.clone()], "Initial baseline")?;
    }
    let socket = state.join("service.sock");
    if let Ok(m) = fs::symlink_metadata(&socket) {
        ensure!(
            m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() },
            "Unexpected service socket path preserved"
        );
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut watch = events::watch(identity.clone(), store.cursor()?)?;
    let mut ready = false;
    let mut replay_failures = 0;
    let mut drop_signals = 0;
    let mut recovered_replays = 0;
    let progress = Arc::new(Mutex::new(Progress {
        view: root.clone(),
        ..Progress::default()
    }));
    let public = Arc::new(RwLock::new(Public {
        state: state.clone(),
        status: Status {
            root: root.clone(),
            pid: std::process::id(),
            ..Status::default()
        },
        index: index.clone(),
        detail: None,
    }));
    let (commands_tx, commands_rx) = mpsc::channel::<Command>();
    let clients = Arc::new(AtomicUsize::new(0));
    let (finished_tx, finished_rx) =
        mpsc::channel::<Result<(Arc<Index>, Generation, Work, Vec<crate::history::Change>)>>();
    let (details_tx, details_rx) = mpsc::channel::<(PathBuf, Identity, Result<Arc<Index>>)>();
    let mut cancel = Arc::new(AtomicBool::new(false));
    let mut running = false;
    let mut detail_running = false;
    let mut detail_pending: Option<PathBuf> = None;
    let mut paused: bool = store.get("paused")?.unwrap_or(false);
    let mut error = None;
    let mut last_interruption = store.get("last_interruption")?;
    let mut phase = "Replaying filesystem journal".to_string();
    let mut identity_check = Instant::now();
    let mut last_event = Instant::now();
    let mut queued_at = Instant::now();
    let mut last_retry = Instant::now();
    let mut last_saved = store.generation()?.map(|g| g.created).unwrap_or(0);
    let mut current_capacity = capacity(&root)?;
    let mut capacity_sample = Instant::now();
    let mut capacity_save = Instant::now();
    store.record_capacity(store::now(), current_capacity.0, current_capacity.1)?;
    loop {
        if terminate.load(Ordering::Relaxed) {
            if running || detail_running {
                interrupt_measurement(
                    &mut store,
                    &cancel,
                    &mut last_interruption,
                    "Service stopped",
                )?;
            }
            break;
        }
        if let Ok(loaded) = loaded_rx.try_recv() {
            loading = false;
            match loaded {
                Ok(saved) => {
                    index = saved;
                    if index.is_none() && store.work()?.paths.is_empty() {
                        store.ingest(store.cursor()?, [root.clone()], "Initial baseline")?;
                    }
                }
                Err(e) => {
                    error = Some(format!(
                        "Saved index unreadable: {e:#}; rebuilding accessible metadata"
                    ));
                    store.ingest(
                        store.cursor()?,
                        [root.clone()],
                        "Repairing unreadable saved index",
                    )?;
                }
            }
        }
        if capacity_sample.elapsed() >= Duration::from_secs(2) {
            if let Ok(c) = capacity(&root) {
                current_capacity = c;
            }
            capacity_sample = Instant::now();
        }
        if capacity_save.elapsed() >= Duration::from_secs(60) {
            store.record_capacity(store::now(), current_capacity.0, current_capacity.1)?;
            capacity_save = Instant::now();
        }
        for _ in 0..32 {
            let batch = match watch.receiver.try_recv() {
                Ok(b) => b,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    ready = false;
                    phase = "Filesystem receiver disconnected; replaying durable checkpoint".into();
                    drop(watch);
                    watch = events::watch(identity.clone(), store.cursor()?)?;
                    break;
                }
            };
            let change = events::changes(batch, &root, &identity, &state, store.cursor()?);
            if change.gap != 0 {
                drop_signals += 1;
                if replay_failures == 0 {
                    replay_failures = 1;
                    ready = false;
                    phase = format!("Replaying after delivery gap (flags {})", change.gap);
                    drop(watch);
                    watch = events::watch(identity.clone(), store.cursor()?)?;
                } else {
                    let anchor = events::current_id();
                    let current = events::identity(&root)?;
                    if current != identity || store.cursor()? > anchor {
                        let reason = if current != identity {
                            "Filesystem history changed; automatic reconciliation queued"
                        } else {
                            "Filesystem event cursor reset; automatic reconciliation queued"
                        };
                        interrupt_measurement(&mut store, &cancel, &mut last_interruption, reason)?;
                        identity = current;
                        store.bind(&root, &identity, anchor)?;
                    }
                    store.ingest(
                        anchor.max(store.cursor()?),
                        [root.clone()],
                        "Journal replay gap; full reconciliation",
                    )?;
                    ready = true; // Root invalidation covers history through the new anchor.
                    replay_failures = 0;
                    phase = "Reconciling reported journal gap".into();
                    drop(watch);
                    watch = events::watch(identity.clone(), store.cursor()?)?;
                }
                last_event = Instant::now();
                break;
            }
            let meaningful = !change.paths.is_empty();
            if meaningful && store.work()?.paths.is_empty() {
                queued_at = Instant::now();
            }
            // Persisting acknowledgements of our own excluded state writes
            // would generate another event forever. They need no pending work;
            // the next meaningful batch can safely cover them.
            if meaningful || change.history_done {
                store.ingest(change.latest, change.paths, "Filesystem changes")?;
            }
            if change.history_done {
                ready = true;
                if replay_failures != 0 {
                    recovered_replays += 1;
                    replay_failures = 0;
                }
            }
            if meaningful {
                last_event = Instant::now();
            }
        }
        if watch.overflow.swap(false, Ordering::AcqRel) {
            if replay_failures != 0 {
                store.ingest(
                    events::current_id().max(store.cursor()?),
                    [root.clone()],
                    "Receiver pressure; full reconciliation",
                )?;
                replay_failures = 0;
                ready = true;
            } else {
                replay_failures = 1;
                ready = false;
            }
            phase = "Replaying after receiver queue pressure".into();
            drop(watch);
            watch = events::watch(identity.clone(), store.cursor()?)?;
        }
        if identity_check.elapsed() > Duration::from_secs(10) {
            let current = events::identity(&root)?;
            if current != identity {
                interrupt_measurement(
                    &mut store,
                    &cancel,
                    &mut last_interruption,
                    "Filesystem history changed; automatic reconciliation queued",
                )?;
                identity = current;
                store.bind(&root, &identity, events::current_id())?;
                ready = false;
                drop(watch);
                watch = events::watch(identity.clone(), store.cursor()?)?;
                phase = "Volume history changed; reconciling full scope".into();
            }
            identity_check = Instant::now();
        }
        while let Ok((command, tx)) = commands_rx.try_recv() {
            let reply = match command {
                Request::Retention { days } => {
                    let result=store.set_history_days(days).map(|_|Reply{status:public.read().unwrap().status.clone(),message:format!("History retention set to {days} days; older records removed, reusable database pages retained"),..Reply::default()}).map_err(|e|format!("{e:#}"));
                    let _ = tx.send(result);
                    continue;
                }
                Request::Stop => {
                    terminate.store(true, Ordering::Relaxed);
                    if running || detail_running {
                        interrupt_measurement(
                            &mut store,
                            &cancel,
                            &mut last_interruption,
                            "Service stopped",
                        )?;
                    }
                    "Service stopping; committed index and pending work preserved"
                }
                Request::Pause => {
                    paused = true;
                    store.set_paused(true)?;
                    interrupt_measurement(&mut store, &cancel, &mut last_interruption, USER_PAUSE)?;
                    "Scan paused; Refresh resumes it"
                }
                Request::Refresh { full } => {
                    paused = false;
                    store.set_paused(false)?;
                    error = None;
                    if full {
                        store.ingest(store.cursor()?, [root.clone()], "Explicit full rescan")?;
                    } else if !running {
                        let retry = index.as_deref().map(retry_regions).unwrap_or_default();
                        store.ingest(store.cursor()?, retry, "Retrying incomplete coverage")?;
                    }
                    "Refresh uses the received journal and pending regions; no automatic baseline reset"
                }
                Request::Expand { path } => {
                    if !path.starts_with(&root)
                        || path.components().any(|c| c == Component::ParentDir)
                    {
                        let _ = tx.send(Err("Path outside scope".into()));
                        continue;
                    }
                    detail_pending = Some(path);
                    "Browsing detail queued; current scan continues"
                }
                _ => "Unsupported control request",
            };
            let _ = tx.send(Ok(Reply {
                status: public.read().unwrap().status.clone(),
                message: reply.into(),
                ..Reply::default()
            }));
        }
        if let Ok(result) = finished_rx.try_recv() {
            running = false;
            if let Ok((_, _, work, _)) = &result {
                let current = events::identity(&root)?;
                if current != work.identity && !cancel.load(Ordering::Relaxed) {
                    interrupt_measurement(
                        &mut store,
                        &cancel,
                        &mut last_interruption,
                        "Filesystem history changed before commit; automatic reconciliation queued",
                    )?;
                    identity = current;
                    store.bind(&root, &identity, events::current_id())?;
                    ready = false;
                    drop(watch);
                    watch = events::watch(identity.clone(), store.cursor()?)?;
                }
            }
            match result {
                Ok((candidate, generation, work, changes)) if !cancel.load(Ordering::Relaxed) => {
                    store.commit_changes(&generation, &work, &candidate, &changes)?;
                    last_saved = generation.created;
                    if work.paths.iter().any(|p| p == &root) {
                        store.set_full_at(last_saved)?;
                    }
                    index = Some(candidate);
                    let mut p = public.write().unwrap();
                    let affected = p
                        .detail
                        .as_ref()
                        .filter(|d| {
                            work.paths
                                .iter()
                                .any(|c| c.starts_with(&d.root) || d.root.starts_with(c))
                        })
                        .map(|d| d.root.clone());
                    if let Some(path) = affected {
                        p.detail = None;
                        if progress.lock().unwrap().view.starts_with(&path) {
                            detail_pending = Some(path);
                        }
                    }
                    phase = "Index saved; incremental tracking active".into();
                    error = None;
                }
                Ok(_) => {
                    phase = "Candidate interrupted; pending work preserved for retry".into();
                    store.reap_orphans()?;
                }
                Err(e) => {
                    measurement_failed(&mut store, &mut paused, &mut error, &mut phase, e)?;
                }
            }
            last_retry = Instant::now();
        }
        if let Ok((path, measured_identity, result)) = details_rx.try_recv() {
            detail_running = false;
            let interrupted = cancel.load(Ordering::Relaxed)
                || (result.is_ok() && measured_identity != events::identity(&root)?);
            if let Some(detail) =
                detail_finished(path, result, interrupted, &mut detail_pending, &mut error)
            {
                public.write().unwrap().detail = Some(detail);
            }
        }
        let work = store.work()?;
        if ready && !loading && !paused && !running && !detail_running && work.paths.is_empty() {
            phase = "Index saved; incremental tracking active".into();
        }
        if ready
            && !loading
            && !paused
            && !terminate.load(Ordering::Relaxed)
            && !running
            && !detail_running
            && (last_event.elapsed() >= Duration::from_millis(750)
                || queued_at.elapsed() >= Duration::from_secs(2))
            && !work.paths.is_empty()
        {
            let work = store.claim()?;
            queued_at = Instant::now();
            running = true;
            cancel = Arc::new(AtomicBool::new(false));
            phase = work.reason.clone();
            {
                let mut live = progress.lock().unwrap();
                let view = live.view.clone();
                *live = Progress {
                    view,
                    phase: phase.clone(),
                    ..Progress::default()
                };
            }
            let previous = index.clone();
            let previous_generation = store.generation()?;
            let root = root.clone();
            let state = state.clone();
            let cancel = cancel.clone();
            let progress = progress.clone();
            let tx = finished_tx.clone();
            thread::Builder::new()
                .name("mactrim-measurement".into())
                .spawn(move || {
                    let result = (|| {
                        let dirty: Regions = work.paths.iter().cloned().collect();
                        let measured = Arc::new(scan::measure(
                            &root,
                            std::slice::from_ref(&state),
                            previous.as_deref(),
                            &dirty,
                            &cancel,
                            Some(&progress),
                        )?);
                        scan::check_cancelled(&cancel)?;
                        progress.lock().unwrap().phase = "Saving compressed directory index".into();
                        let generation = Generation::update(
                            &state,
                            &measured,
                            previous_generation.as_ref().zip(previous.as_deref()),
                        )?;
                        let changes = crate::history::changes(
                            previous.as_deref(),
                            &measured,
                            generation.created,
                        );
                        Ok((measured, generation, work, changes))
                    })();
                    let _ = tx.send(result);
                })?;
        } else if ready
            && !loading
            && !paused
            && !terminate.load(Ordering::Relaxed)
            && !running
            && !detail_running
            && let Some(path) = detail_pending.take()
        {
            detail_running = true;
            cancel = Arc::new(AtomicBool::new(false));
            let cancel = cancel.clone();
            let tx = details_tx.clone();
            let state = state.clone();
            let measured_identity = identity.clone();
            thread::spawn(move || {
                let result =
                    scan::measure(&path, &[state], None, &Regions::default(), &cancel, None)
                        .map(Arc::new);
                let _ = tx.send((path, measured_identity, result));
            });
        }
        // A periodic audit covers advisory-event blind spots, not ordinary Refresh.
        if ready
            && !paused
            && !running
            && work.paths.is_empty()
            && last_retry.elapsed() > Duration::from_secs(3600)
        {
            if store::now().saturating_sub(store.full_at()?) >= 7 * 86400 {
                store.ingest(
                    store.cursor()?,
                    [root.clone()],
                    "Periodic reconciliation due",
                )?;
            }
            last_retry = Instant::now();
        }
        {
            let live = progress.lock().unwrap();
            let mut p = public.write().unwrap();
            p.index = index.clone();
            let (used, available) = current_capacity;
            p.status = Status {
                pid: std::process::id(),
                root: root.clone(),
                phase: if loading {
                    "Loading saved directory tree; event ingestion active".into()
                } else if paused {
                    if error.is_some() {
                        "Paused after measurement failure; Refresh retries".into()
                    } else if last_interruption
                        .as_ref()
                        .is_some_and(|i| i.reason == USER_PAUSE)
                    {
                        "Paused by user; Refresh resumes measurement".into()
                    } else {
                        "Paused; Refresh resumes measurement".into()
                    }
                } else if !ready {
                    "Replaying filesystem journal; event continuity is not settled yet".into()
                } else if running && !live.phase.is_empty() {
                    live.phase.clone()
                } else {
                    phase.clone()
                },
                running,
                detail_running,
                paused,
                history_ready: ready,
                loading,
                history_days: store.history_days()?,
                received_cursor: store.cursor()?,
                applied_cursor: store.applied()?,
                pending_regions: work.paths.len(),
                directories: index.as_ref().map(|i| i.nodes.len()).unwrap_or(0),
                index_bytes: store.footprint()?,
                visited: live.visited,
                reused: live.reused,
                drop_signals,
                recovered_replays,
                last_saved,
                root_node: index.as_ref().and_then(|i| i.root_node().cloned()),
                filesystem_used: used,
                filesystem_available: available,
                observed_allocated: live.allocated,
                observed_logical: live.logical,
                current_path: live.current.clone(),
                error: error.clone(),
                last_interruption: last_interruption.clone(),
            };
        }
        while let Ok((stream, _)) = listener.accept() {
            if clients.load(Ordering::Relaxed) >= 8 {
                drop(stream);
                continue;
            }
            clients.fetch_add(1, Ordering::Relaxed);
            let clients = clients.clone();
            let public = public.clone();
            let progress = progress.clone();
            let sender = commands_tx.clone();
            thread::spawn(move || {
                let error_stream = stream.try_clone().ok();
                if let Err(error) = serve(stream, public, progress, sender)
                    && let Some(mut out) = error_stream
                {
                    let _ = serde_json::to_writer(
                        &mut out,
                        &Err::<Reply, String>(format!("{error:#}")),
                    );
                    let _ = out.write_all(b"\n");
                }
                clients.fetch_sub(1, Ordering::Relaxed);
            });
        }
        thread::sleep(Duration::from_millis(50));
    }
    drop(watch);
    drop(listener);
    fs::remove_file(socket)?;
    Ok(())
}

pub fn capacity(path: &Path) -> Result<(u64, u64)> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), stat.as_mut_ptr()) } == 0,
        "Filesystem capacity unavailable"
    );
    let s = unsafe { stat.assume_init() };
    Ok((
        (s.f_blocks.saturating_sub(s.f_bfree) as u64) * s.f_frsize,
        (s.f_bavail as u64) * s.f_frsize,
    ))
}

pub fn retry_regions(index: &Index) -> Vec<PathBuf> {
    let mut paths = Regions::default();
    for node in index
        .nodes
        .values()
        .filter(|n| n.status > 1 && n.error != 0)
    {
        if let Some(path) = node
            .error_path
            .as_ref()
            .and_then(|p| p.ancestors().find(|p| index.nodes.contains_key(*p)))
        {
            paths.insert(path.to_owned());
        }
    }
    paths.paths().cloned().collect()
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[test]
    fn interrupted_worker_preserves_latest_pause_or_resume_intent() {
        for user_paused in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(fixture.path()).unwrap();
            let mut store = Store::open(&root.join("state")).unwrap();
            store.set_paused(user_paused).unwrap();
            let failure = scan::measure(
                &root,
                &[],
                None,
                &Regions::default(),
                &AtomicBool::new(true),
                None,
            )
            .expect_err("The interrupted scanner must reject its candidate");
            let mut paused = user_paused;
            let mut error = None;
            let mut phase = String::new();
            measurement_failed(&mut store, &mut paused, &mut error, &mut phase, failure).unwrap();
            assert_eq!(
                paused, user_paused,
                "Interruption changed the latest intent"
            );
            assert_eq!(store.get::<bool>("paused").unwrap(), Some(user_paused));
            assert!(
                error.is_none(),
                "Expected interruption became a failure: {error:?}"
            );
        }
    }
    #[test]
    fn refresh_before_cancelled_worker_finishes_is_not_undone() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(fixture.path()).unwrap();
        let mut store = Store::open(&root.join("state")).unwrap();
        let progress = Arc::new(Mutex::new(Progress::default()));
        let gate = progress.lock().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker = {
            let (root, cancel, progress) = (root.clone(), cancel.clone(), progress.clone());
            thread::spawn(move || {
                let result = scan::measure(
                    &root,
                    &[],
                    None,
                    &Regions::default(),
                    &cancel,
                    Some(&progress),
                );
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                tx.send(result).unwrap();
            })
        };
        let mut last = None;
        store.set_paused(true).unwrap();
        interrupt_measurement(&mut store, &cancel, &mut last, USER_PAUSE).unwrap();
        // Refresh is handled while the old worker is still unable to finish.
        store.set_paused(false).unwrap();
        let mut paused = false;
        let mut error = None;
        let mut phase = String::new();
        drop(gate);
        release_tx.send(()).unwrap();
        let failure = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        worker.join().unwrap();
        measurement_failed(
            &mut store,
            &mut paused,
            &mut error,
            &mut phase,
            failure.context("Worker completion"),
        )
        .unwrap();
        assert!(!paused);
        assert_eq!(store.get::<bool>("paused").unwrap(), Some(false));
        assert!(error.is_none());
    }

    #[test]
    fn automatic_history_interruption_preserves_index_and_can_commit_retry() {
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let root = base.join("files");
        let state = base.join("state");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("data"), b"saved observation").unwrap();
        let mut identity = Identity {
            namespace_device: 1,
            namespace_inode: 2,
            namespace_uuid: "initial".into(),
            device: 1,
            uuid: "initial".into(),
            mount: "/".into(),
            relative: "fixture".into(),
        };
        let mut store = Store::open(&state).unwrap();
        store.bind(&root, &identity, 100).unwrap();
        store.set_paused(false).unwrap();
        let saved = scan::measure(
            &root,
            &[],
            None,
            &Regions::default(),
            &AtomicBool::new(false),
            None,
        )
        .unwrap();
        let generation = Generation::write(&state, &saved).unwrap();
        let baseline = store.claim().unwrap();
        store.commit(&generation, &baseline, &saved).unwrap();
        store.ingest(120, [root.clone()], "New work").unwrap();
        let old_work = store.claim().unwrap();
        let cancel = AtomicBool::new(false);
        let mut last = None;
        interrupt_measurement(
            &mut store,
            &cancel,
            &mut last,
            "Filesystem history changed; automatic reconciliation queued",
        )
        .unwrap();
        identity.uuid = "replacement".into();
        store.bind(&root, &identity, 30).unwrap();
        let failure = scan::measure(&root, &[], Some(&saved), &Regions::default(), &cancel, None)
            .unwrap_err();
        let mut paused = false;
        let mut error = None;
        let mut phase = String::new();
        measurement_failed(&mut store, &mut paused, &mut error, &mut phase, failure).unwrap();
        assert!(!paused);
        assert!(error.is_none());
        assert_eq!(
            store.generation().unwrap().unwrap().digest,
            generation.digest
        );
        assert_eq!(store.load().unwrap().unwrap().nodes, saved.nodes);
        assert!(
            store.commit(&generation, &old_work, &saved).is_err(),
            "Stale identity committed"
        );
        assert_eq!(store.work().unwrap().paths, vec![root.clone()]);
        let retry = store.claim().unwrap();
        let next_cancel = AtomicBool::new(false);
        fs::write(root.join("data"), vec![1; 8192]).unwrap();
        let measured = scan::measure(
            &root,
            &[],
            Some(&saved),
            &retry.paths.iter().cloned().collect(),
            &next_cancel,
            None,
        )
        .unwrap();
        let next_generation = Generation::write(&state, &measured).unwrap();
        store.commit(&next_generation, &retry, &measured).unwrap();
        assert!(store.work().unwrap().paths.is_empty());
        assert_eq!(store.applied().unwrap(), 30);
        drop(store);
        let store = Store::open(&state).unwrap();
        assert_eq!(store.get::<bool>("paused").unwrap(), Some(false));
        assert_eq!(
            store
                .get::<Interruption>("last_interruption")
                .unwrap()
                .unwrap()
                .reason,
            last.unwrap().reason
        );
    }

    #[test]
    fn genuine_worker_failure_still_pauses_and_reports_problem() {
        let fixture = tempfile::tempdir().unwrap();
        let state = fs::canonicalize(fixture.path()).unwrap().join("state");
        let mut store = Store::open(&state).unwrap();
        let mut paused = false;
        let mut error = None;
        let mut phase = String::new();
        let failure = io::Error::new(io::ErrorKind::StorageFull, "fixture save failed");
        measurement_failed(
            &mut store,
            &mut paused,
            &mut error,
            &mut phase,
            failure.into(),
        )
        .unwrap();
        assert!(paused);
        assert_eq!(store.get::<bool>("paused").unwrap(), Some(true));
        assert!(error.unwrap().contains("fixture save failed"));
    }

    #[test]
    fn cancelled_detail_is_requeued_without_replacing_newer_navigation() {
        let path = PathBuf::from("/fixture/old");
        for newer in [None, Some(PathBuf::from("/fixture/new"))] {
            for completed in [false, true] {
                let mut pending = newer.clone();
                let mut error = None;
                let result = if completed {
                    Ok(Arc::new(Index::new(path.clone())))
                } else {
                    Err(scan::Cancelled.into())
                };
                assert!(
                    detail_finished(path.clone(), result, true, &mut pending, &mut error).is_none()
                );
                assert_eq!(pending, newer.clone().or_else(|| Some(path.clone())));
                assert!(error.is_none());
            }
        }
    }
    #[test]
    fn global_ranking_and_anchor_follow_a_directory_across_pages() {
        let fixture = tempfile::tempdir().unwrap();
        let mut index = Index::new(fixture.path().to_owned());
        for n in 0..600 {
            index.insert(
                fixture.path().join(format!("item-{n:03}")),
                Node {
                    allocated: n,
                    ..Node::default()
                },
            );
        }
        let (rows, more, offset) =
            directory_rows(Some(&index), fixture.path(), false, 0, 200, None).unwrap();
        assert_eq!(rows[0].path, fixture.path().join("item-599"));
        assert_eq!(offset, 0);
        assert!(more);
        let anchor = fixture.path().join("item-000");
        let (rows, more, offset) =
            directory_rows(Some(&index), fixture.path(), false, 0, 200, Some(&anchor)).unwrap();
        assert_eq!(offset, 400);
        assert_eq!(rows.last().unwrap().path, anchor);
        assert!(!more);
        index.nodes.get_mut(&anchor).unwrap().allocated = 1000;
        let (rows, more, offset) =
            directory_rows(Some(&index), fixture.path(), false, 400, 200, Some(&anchor)).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(rows[0].path, anchor);
        assert!(more);
        for n in [19, 210, 422, 577] {
            let anchor = fixture.path().join(format!("item-{n:03}"));
            let expected = index.rows(fixture.path(), false);
            let rank = expected.iter().position(|(p, _)| p == &anchor).unwrap();
            let (rows, _, offset) =
                directory_rows(Some(&index), fixture.path(), false, 0, 37, Some(&anchor)).unwrap();
            assert_eq!(offset, rank / 37 * 37);
            assert_eq!(
                rows.iter().map(|r| &r.path).collect::<Vec<_>>(),
                expected
                    .iter()
                    .skip(offset)
                    .take(37)
                    .map(|(p, _)| p)
                    .collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn inherited_permission_error_retries_only_the_denied_scope() {
        let mut index = Index::new("/fixture".into());
        for p in ["/fixture", "/fixture/parent", "/fixture/parent/denied"] {
            index.insert(
                p.into(),
                Node {
                    status: if p.ends_with("denied") { 3 } else { 2 },
                    error: libc::EACCES,
                    error_path: Some("/fixture/parent/denied".into()),
                    ..Node::default()
                },
            );
        }
        assert_eq!(
            retry_regions(&index),
            vec![PathBuf::from("/fixture/parent/denied")]
        );
    }
}
