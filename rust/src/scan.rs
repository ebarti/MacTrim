//! Metadata-only aggregation with bounded-depth working memory, using WalkDir.
//! Collapsed browsing nodes never prune byte measurement.
use crate::{model::*, regions::Regions};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use walkdir::WalkDir;

/// An expected worker interruption, distinct from a measurement or save failure.
#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scan interrupted; previous committed index preserved")
    }
}
impl std::error::Error for Cancelled {}

pub fn check_cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(Cancelled.into());
    }
    Ok(())
}

struct Frame {
    path: PathBuf,
    node: Node,
    depth: usize,
    retained: bool,
    reused: bool,
}

fn signature(m: &fs::Metadata) -> [u64; 6] {
    [
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.size(),
        (m.mtime() as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(m.mtime_nsec() as u64),
        (m.ctime() as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(m.ctime_nsec() as u64),
    ]
}
fn dataless(m: &fs::Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        std::os::macos::fs::MetadataExt::st_flags(m) & 0x40000000 != 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = m;
        false
    }
}
fn lazy(path: &Path, depth: usize) -> bool {
    depth > 8
        || path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            [
                "node_modules",
                ".venv",
                "venv",
                ".tox",
                ".nox",
                "__pypackages__",
            ]
            .contains(&n)
        })
}
fn excluded(
    root: &Path,
    path: &Path,
    meta: &fs::Metadata,
    parent: Option<&Frame>,
    exclusions: &[PathBuf],
) -> bool {
    exclusions.iter().any(|p| path.starts_with(p))
        || dataless(meta)
        || ["/dev", "/proc", "/sys", "/private/dev"]
            .iter()
            .any(|p| path == Path::new(p))
        || (root == Path::new("/") && path == Path::new("/System/Volumes/Data"))
        || parent.is_some_and(|p| {
            p.node.signature[0] != meta.dev()
                && !(root == Path::new("/")
                    && [
                        "/Users",
                        "/Applications",
                        "/Library",
                        "/private",
                        "/usr",
                        "/System",
                        "/bin",
                        "/sbin",
                        "/opt",
                    ]
                    .iter()
                    .any(|s| path == Path::new(s)))
        })
}
fn error(frame: &mut Frame, path: &Path, code: i32) {
    frame.node.status = if [libc::EACCES, libc::EPERM].contains(&code) {
        3
    } else {
        2
    };
    if frame.node.error_path.is_none() {
        frame.node.error = code;
        frame.node.error_path = Some(path.to_owned());
    }
}
fn add(parent: &mut Node, child: &Node) -> Result<()> {
    parent.logical = parent
        .logical
        .checked_add(child.logical)
        .context("Logical size overflow")?;
    parent.allocated = parent
        .allocated
        .checked_add(child.allocated)
        .context("Allocation overflow")?;
    parent.entries = parent
        .entries
        .checked_add(child.entries)
        .context("Entry count overflow")?;
    if child.status > 1 {
        parent.status = 2;
    }
    if parent.error == 0 && child.error != 0 {
        parent.error = child.error;
        parent.error_path.clone_from(&child.error_path);
    }
    Ok(())
}
fn finish(frames: &mut Vec<Frame>, index: &mut Index) -> Result<()> {
    let mut frame = frames.pop().unwrap();
    if !frame.reused && frame.node.status == 0 {
        match fs::symlink_metadata(&frame.path) {
            Ok(m) if signature(&m) == frame.node.signature => (),
            Ok(_) => {
                let p = frame.path.clone();
                error(&mut frame, &p, libc::ESTALE);
            }
            Err(e) => {
                let p = frame.path.clone();
                error(&mut frame, &p, e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }
    if let Some(parent) = frames.last_mut() {
        add(&mut parent.node, &frame.node)?;
    }
    if frame.retained {
        index.insert(frame.path, frame.node);
    }
    Ok(())
}
fn publish(
    index: &mut Index,
    frames: &[Frame],
    current: &Path,
    progress: Option<&Arc<Mutex<Progress>>>,
) -> Result<()> {
    let Some(progress) = progress else {
        return Ok(());
    };
    let mut below = Node::default();
    for frame in frames.iter().rev() {
        let mut n = frame.node.clone();
        add(&mut n, &below)?;
        if frame.retained {
            let mut running = n.clone();
            running.status = 4;
            index.insert(frame.path.clone(), running);
        }
        below = n;
    }
    let mut live = progress.lock().unwrap();
    live.current = current.to_owned();
    live.visited = index.visited;
    live.reused = index.reused;
    if let Some(n) = index.root_node() {
        live.logical = n.logical;
        live.allocated = n.allocated;
    }
    live.rows = index.rows(&live.view, false);
    Ok(())
}

fn walk(
    root: &Path,
    namespace: &Path,
    exclusions: &[PathBuf],
    cancel: &AtomicBool,
    progress: Option<&Arc<Mutex<Progress>>>,
) -> Result<Index> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("Scan root must be a real directory");
    }
    let depth_offset = root.strip_prefix(namespace)?.components().count();
    let mut index = Index::new(root.to_owned());
    index.full_scan = true;
    let mut frames: Vec<Frame> = vec![];
    let mut links = HashSet::new();
    let mut directories = HashSet::new();
    let mut aliased = false;
    let mut last = Instant::now() - Duration::from_secs(1);
    let mut walker = WalkDir::new(root)
        .follow_links(false)
        .max_open(32)
        .into_iter();
    while let Some(entry) = walker.next() {
        check_cancelled(cancel)?;
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if let Some(frame) = frames.last_mut() {
                    let p = e.path().unwrap_or(&frame.path).to_owned();
                    error(
                        frame,
                        &p,
                        e.io_error()
                            .and_then(|x| x.raw_os_error())
                            .unwrap_or(libc::EIO),
                    );
                } else {
                    return Err(e.into());
                }
                continue;
            }
        };
        while frames.last().is_some_and(|f| f.depth >= entry.depth()) {
            finish(&mut frames, &mut index)?;
        }
        let path = entry.path();
        index.visited += 1;
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                if let Some(f) = frames.last_mut() {
                    error(
                        f,
                        path,
                        e.io_error()
                            .and_then(|x| x.raw_os_error())
                            .unwrap_or(libc::EIO),
                    );
                } else {
                    return Err(e.into());
                }
                continue;
            }
        };
        if entry.file_type().is_dir() {
            let retained = frames
                .last()
                .is_none_or(|f| f.retained && f.node.flags & COLLAPSED == 0);
            let mut frame = Frame {
                path: path.to_owned(),
                depth: entry.depth(),
                retained,
                reused: false,
                node: Node {
                    signature: signature(&meta),
                    flags: if entry.depth() + depth_offset > 0
                        && lazy(path, entry.depth() + depth_offset)
                    {
                        COLLAPSED
                    } else {
                        0
                    },
                    ..Node::default()
                },
            };
            let alias = !directories.insert((meta.dev(), meta.ino()));
            aliased |= alias;
            let skip = excluded(namespace, path, &meta, frames.last(), exclusions) || alias;
            if skip {
                frame.node.status = 1;
                walker.skip_current_dir();
            } else {
                frame.node.logical = meta.size();
                frame.node.allocated = meta.blocks() * 512;
                frame.node.own_logical = meta.size();
                frame.node.own_allocated = meta.blocks() * 512;
                frame.node.entries = 1;
                frame.node.own_entries = 1;
            }
            if retained {
                let mut running = frame.node.clone();
                if !skip && !frame.reused {
                    running.status = 4;
                }
                index.insert(path.to_owned(), running);
            }
            frames.push(frame);
        } else if let Some(frame) = frames.last_mut() {
            frame.node.entries += 1;
            frame.node.own_entries += 1;
            if entry.file_type().is_file() && !dataless(&meta) {
                let linked = meta.nlink() > 1;
                let duplicate = linked && !links.insert((meta.dev(), meta.ino()));
                if !duplicate {
                    let n = Node {
                        logical: meta.size(),
                        allocated: meta.blocks() * 512,
                        ..Node::default()
                    };
                    add(&mut frame.node, &n)?;
                    frame.node.own_logical += n.logical;
                    frame.node.own_allocated += n.allocated;
                }
                if linked && let Some(owner) = frames.iter_mut().rev().find(|f| f.retained) {
                    owner.node.flags |= LINKED;
                }
            }
        }
        if last.elapsed() >= Duration::from_millis(150) {
            publish(&mut index, &frames, path, progress)?;
            last = Instant::now();
        }
    }
    while !frames.is_empty() {
        finish(&mut frames, &mut index)?;
    }
    if aliased && let Some(mut node) = index.root_node().cloned() {
        node.flags |= LINKED;
        index.insert(root.to_owned(), node);
    }
    publish(&mut index, &[], root, progress)?;
    Ok(index)
}

/// Replace invalidated subtrees in a persistent tree, then recompute their
/// ancestors. Unaffected subtrees share their map nodes with the saved view;
/// their files and directory metadata are not visited again.
pub fn measure(
    root: &Path,
    exclusions: &[PathBuf],
    previous: Option<&Index>,
    dirty: &Regions,
    cancel: &AtomicBool,
    progress: Option<&Arc<Mutex<Progress>>>,
) -> Result<Index> {
    check_cancelled(cancel)?;
    let full = |why: &str| -> Result<Index> {
        if let Some(progress) = progress {
            progress.lock().unwrap().phase = why.into();
        }
        walk(root, root, exclusions, cancel, progress)
    };
    let Some(old) = previous.filter(|i| i.root == root && i.root_node().is_some()) else {
        return full("Measuring full baseline");
    };
    let mut scopes = Regions::default();
    for changed in dirty.paths() {
        ensure_scope(root, changed)?;
        let scope = changed
            .ancestors()
            .find(|p| {
                old.nodes.contains_key(*p)
                    && fs::symlink_metadata(p)
                        .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            })
            .context("No surviving indexed ancestor")?;
        scopes.insert(scope.to_owned());
    }
    if scopes.paths().any(|p| p == root) {
        return full("Full scope reconciliation");
    }
    if scopes.paths().any(|p| old.linked_intersects(p)) {
        return full("Full reconciliation for shared hardlink or directory identities");
    }
    let mut candidate = old.clone();
    candidate.full_scan = false;
    candidate.visited = 0;
    candidate.reused = old.root_node().map_or(0, |n| n.entries);
    let mut ancestors = std::collections::BTreeSet::new();
    for scope in scopes.paths() {
        check_cancelled(cancel)?;
        let subtree = walk(scope, root, exclusions, cancel, progress)?;
        if !subtree.linked.is_empty() {
            return full("Full reconciliation for newly shared hardlink identities");
        }
        candidate.visited += subtree.visited;
        candidate.reused = candidate
            .reused
            .saturating_sub(old.nodes.get(scope).map_or(0, |n| n.entries));
        candidate.remove_subtree(scope);
        for (path, node) in subtree.nodes {
            candidate.insert(path, node);
        }
        for parent in scope
            .ancestors()
            .skip(1)
            .take_while(|p| p.starts_with(root))
        {
            ancestors.insert((
                std::cmp::Reverse(parent.components().count()),
                parent.to_owned(),
            ));
        }
    }
    for (_, path) in ancestors {
        check_cancelled(cancel)?;
        let before = old.nodes.get(&path).context("Missing aggregate ancestor")?;
        let meta = fs::symlink_metadata(&path)?;
        if meta.dev() != before.signature[0] || meta.ino() != before.signature[1] || !meta.is_dir()
        {
            return full("An indexed ancestor was replaced; full reconciliation");
        }
        let children = candidate.children.get(&path);
        let own_error = before
            .error_path
            .as_ref()
            .filter(|err| !children.into_iter().flatten().any(|p| err.starts_with(p)));
        let mut node = before.clone();
        node.signature = signature(&meta);
        node.own_logical = meta.size();
        node.own_allocated = meta.blocks() * 512;
        node.logical = node.own_logical;
        node.allocated = node.own_allocated;
        node.entries = node.own_entries;
        node.flags &= !REUSED;
        node.status = if own_error.is_some() {
            before.status
        } else {
            0
        };
        node.error = if own_error.is_some() { before.error } else { 0 };
        node.error_path = own_error.cloned();
        for child in children.into_iter().flatten() {
            add(
                &mut node,
                candidate.nodes.get(child).context("Disconnected child")?,
            )?;
        }
        candidate.insert(path, node);
    }
    publish(&mut candidate, &[], root, progress)?;
    check_cancelled(cancel)?;
    Ok(candidate)
}

fn ensure_scope(root: &Path, path: &Path) -> Result<()> {
    anyhow::ensure!(
        path.starts_with(root)
            && !path
                .components()
                .any(|c| c == std::path::Component::ParentDir),
        "Invalid changed region"
    );
    Ok(())
}
