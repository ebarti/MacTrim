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

pub fn measure(
    root: &Path,
    exclusions: &[PathBuf],
    previous: Option<&Index>,
    dirty: &Regions,
    cancel: &AtomicBool,
    progress: Option<&Arc<Mutex<Progress>>>,
) -> Result<Index> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        bail!("Scan root must be a real directory");
    }
    let reuse = previous.filter(|old| {
        !old.nodes
            .iter()
            .any(|(p, n)| n.flags & LINKED != 0 && dirty.intersects(p))
    });
    let mut index = Index::new(root.to_owned());
    let mut frames: Vec<Frame> = vec![];
    let mut links = HashSet::new();
    let mut directories = HashSet::new();
    let mut new_links = false;
    let mut last = Instant::now() - Duration::from_secs(1);
    let mut walker = WalkDir::new(root)
        .follow_links(false)
        .max_open(32)
        .into_iter();
    while let Some(entry) = walker.next() {
        if cancel.load(Ordering::Relaxed) {
            bail!("Scan cancelled; previous committed index preserved");
        }
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
                    flags: if entry.depth() > 0 && lazy(path, entry.depth()) {
                        COLLAPSED
                    } else {
                        0
                    },
                    ..Node::default()
                },
            };
            let skip = excluded(root, path, &meta, frames.last(), exclusions)
                || !directories.insert((meta.dev(), meta.ino()));
            if skip {
                frame.node.status = 1;
                walker.skip_current_dir();
            } else {
                frame.node.logical = meta.size();
                frame.node.allocated = meta.blocks() * 512;
                frame.node.own_logical = meta.size();
                frame.node.own_allocated = meta.blocks() * 512;
                frame.node.entries = 1;
                if retained
                    && !dirty.intersects(path)
                    && let Some(old) = reuse
                        .and_then(|i| i.nodes.get(path))
                        .filter(|n| n.measured() && n.signature == frame.node.signature)
                {
                    frame.node = old.clone();
                    frame.node.flags |= REUSED;
                    frame.reused = true;
                    index.reused += old.entries;
                    index.copy_subtree(reuse.unwrap(), path);
                    walker.skip_current_dir();
                }
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
                if linked {
                    new_links = true;
                    if let Some(owner) = frames.iter_mut().rev().find(|f| f.retained) {
                        owner.node.flags |= LINKED;
                    }
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
    if new_links && index.reused > 0 {
        return measure(root, exclusions, None, dirty, cancel, progress);
    }
    publish(&mut index, &[], root, progress)?;
    Ok(index)
}
