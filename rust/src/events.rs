//! A native run-loop thread only copies FSEvents callback data into a bounded
//! channel. Database writes, normalization and scanning happen elsewhere.
use crate::{model::Identity, regions::Regions};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub const MUST_SCAN: u32 = 1;
pub const USER_DROPPED: u32 = 2;
pub const KERNEL_DROPPED: u32 = 4;
pub const WRAPPED: u32 = 8;
pub const HISTORY_DONE: u32 = 16;
pub const ROOT_CHANGED: u32 = 32;
pub const GAP_FLAGS: u32 = USER_DROPPED | KERNEL_DROPPED | WRAPPED | ROOT_CHANGED;
pub const ITEM_IS_FILE: u32 = 0x10000;

#[derive(Clone, Debug)]
pub struct Event {
    pub path: PathBuf,
    pub flags: u32,
    pub id: u64,
}
#[derive(Debug)]
pub struct Batch {
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct Changes {
    pub paths: Vec<PathBuf>,
    pub latest: u64,
    pub gap: u32,
    pub history_done: bool,
}

pub fn changes(
    batch: Batch,
    root: &Path,
    identity: &Identity,
    excluded: &Path,
    cursor: u64,
) -> Changes {
    let mut regions = Regions::default();
    let mut broad_root = false;
    let mut invalidate = |path: PathBuf| {
        if path == root {
            broad_root = true;
        } else {
            regions.insert(path);
        }
    };
    let mut latest = cursor;
    let mut gap = 0;
    let mut history_done = false;
    for event in batch.events {
        latest = latest.max(event.id);
        gap |= event.flags & GAP_FLAGS;
        history_done |= event.flags & HISTORY_DONE != 0;
        if event.flags == HISTORY_DONE {
            continue;
        }
        // Paths are relative to the device, not relative to the watched folder.
        if event
            .path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            gap |= ROOT_CHANGED;
            continue;
        }
        let relative = event.path.strip_prefix("/").unwrap_or(&event.path);
        let path = identity.mount.join(relative);
        if path.starts_with(excluded) {
            continue;
        }
        if !path.starts_with(root) {
            if event.flags & (64 | 128) != 0 && root.starts_with(&path) {
                invalidate(root.to_owned());
            } else if event.flags & (64 | 128) == 0 {
                gap |= ROOT_CHANGED;
            }
            continue;
        }
        if event.flags & ITEM_IS_FILE != 0 {
            if let Some(parent) = path.parent().filter(|p| p.starts_with(root)) {
                invalidate(parent.to_owned());
            }
        } else {
            invalidate(path.clone());
        }
        if event.flags & (0x100 | 0x200 | 0x800 | 64 | 128) != 0
            && let Some(p) = path.parent().filter(|p| p.starts_with(root))
        {
            invalidate(p.to_owned());
        }
    }
    // Keep broad uncertainty alongside precise hints, through to durable
    // ingestion. A root row in this antichain would swallow the precise rows.
    let mut paths: Vec<_> = regions.paths().cloned().collect();
    if broad_root {
        paths.insert(0, root.to_owned());
    }
    Changes {
        paths,
        latest,
        gap,
        history_done,
    }
}

pub struct Watch {
    pub receiver: Receiver<Batch>,
    pub overflow: Arc<AtomicBool>,
    pub overflow_latest: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.join.take() {
            let _ = t.join();
        }
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use core_foundation_sys::{
        array::{CFArrayCreate, kCFTypeArrayCallBacks},
        base::{CFRelease, CFTypeRef},
        runloop::{CFRunLoopGetCurrent, CFRunLoopRunInMode, kCFRunLoopDefaultMode},
        string::{CFStringCreateWithBytes, kCFStringEncodingUTF8},
        uuid::CFUUIDGetUUIDBytes,
    };

    #[repr(C)]
    struct StreamContext {
        version: isize,
        info: *mut c_void,
        retain: *const c_void,
        release: *const c_void,
        description: *const c_void,
    }
    type Stream = *const c_void;
    type Callback =
        unsafe extern "C" fn(Stream, *mut c_void, usize, *mut c_void, *const u32, *const u64);
    #[link(name = "CoreServices", kind = "framework")]
    unsafe extern "C" {
        fn FSEventStreamCreateRelativeToDevice(
            allocator: *const c_void,
            callback: Callback,
            context: *mut StreamContext,
            device: i32,
            paths: *const c_void,
            since: u64,
            latency: f64,
            flags: u32,
        ) -> Stream;
        fn FSEventStreamScheduleWithRunLoop(
            stream: Stream,
            loop_ref: *mut c_void,
            mode: *const c_void,
        );
        fn FSEventStreamStart(stream: Stream) -> u8;
        fn FSEventStreamStop(stream: Stream);
        fn FSEventStreamInvalidate(stream: Stream);
        fn FSEventStreamRelease(stream: Stream);
        fn FSEventStreamFlushAsync(stream: Stream) -> u64;
        fn FSEventsCopyUUIDForDevice(device: i32) -> *const c_void;
        fn FSEventsGetCurrentEventId() -> u64;
    }
    pub fn current_id() -> u64 {
        unsafe { FSEventsGetCurrentEventId() }
    }
    fn uuid(device: u64) -> Result<String> {
        let raw = unsafe { FSEventsCopyUUIDForDevice(device as i32) };
        ensure!(
            !raw.is_null(),
            "Persistent filesystem history unavailable for device {device}"
        );
        let value = unsafe { CFUUIDGetUUIDBytes(raw.cast()) };
        let bytes: [u8; 16] = unsafe { std::mem::transmute(value) };
        unsafe {
            CFRelease(raw as CFTypeRef);
        }
        Ok(uuid::Uuid::from_bytes(bytes).to_string())
    }
    fn volume_uuid(path: &Path) -> Result<String> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let mut attrs: libc::attrlist = unsafe { std::mem::zeroed() };
        attrs.bitmapcount = 5;
        attrs.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;
        let mut data = [0u8; 20];
        ensure!(
            unsafe {
                libc::getattrlist(
                    name.as_ptr(),
                    (&mut attrs as *mut libc::attrlist).cast(),
                    data.as_mut_ptr().cast(),
                    data.len(),
                    0,
                )
            } == 0,
            "Cannot read filesystem volume identity: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            u32::from_ne_bytes(data[..4].try_into()?) == 20,
            "Unexpected volume identity response"
        );
        Ok(uuid::Uuid::from_bytes(data[4..].try_into()?).to_string())
    }
    pub fn identity(root: &Path) -> Result<Identity> {
        let ns = fs::symlink_metadata(root)?;
        let (device, mount, relative) = if root == Path::new("/")
            && fs::metadata("/System/Volumes/Data").is_ok_and(|m| m.dev() != ns.dev())
        {
            (
                fs::metadata("/System/Volumes/Data")?.dev(),
                PathBuf::from("/"),
                PathBuf::new(),
            )
        } else {
            let name = CString::new(root.as_os_str().as_bytes())?;
            let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
            ensure!(
                unsafe { libc::statfs(name.as_ptr(), stat.as_mut_ptr()) } == 0,
                "statfs failed: {}",
                std::io::Error::last_os_error()
            );
            let stat = unsafe { stat.assume_init() };
            let physical = PathBuf::from(std::ffi::OsStr::from_bytes(
                unsafe { CStr::from_ptr(stat.f_mntonname.as_ptr()) }.to_bytes(),
            ));
            // APFS firmlinks expose /Users on Data although its physical mount
            // is /System/Volumes/Data. A /Users prefix is not a device root.
            let mount = if root.starts_with(&physical) {
                physical
            } else {
                PathBuf::from("/")
            };
            (
                ns.dev(),
                mount.clone(),
                root.strip_prefix(&mount)?.to_owned(),
            )
        };
        Ok(Identity {
            volume_uuid: Some(volume_uuid(
                if root == Path::new("/") && device != ns.dev() {
                    Path::new("/System/Volumes/Data")
                } else {
                    root
                },
            )?),
            namespace_device: ns.dev(),
            namespace_inode: ns.ino(),
            namespace_uuid: volume_uuid(root)?,
            device,
            uuid: uuid(device)?,
            mount,
            relative,
        })
    }
    struct Delivery {
        sender: SyncSender<Batch>,
        overflow: Arc<AtomicBool>,
        latest: Arc<AtomicU64>,
    }
    unsafe extern "C" fn callback(
        _: Stream,
        info: *mut c_void,
        count: usize,
        paths: *mut c_void,
        flags: *const u32,
        ids: *const u64,
    ) {
        let delivery = unsafe { &*(info as *const Delivery) };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ids = unsafe { std::slice::from_raw_parts(ids, count) };
            let latest = ids.iter().copied().max().unwrap_or(0);
            delivery.latest.fetch_max(latest, Ordering::Relaxed);
            // Bound callback allocation as well as channel capacity. Overflow
            // is a recovery signal, never permission to advance a checkpoint.
            if count > 8192 {
                delivery.overflow.store(true, Ordering::Release);
                return;
            }
            let paths = unsafe { std::slice::from_raw_parts(paths as *const *const c_char, count) };
            let flags = unsafe { std::slice::from_raw_parts(flags, count) };
            let mut size = 0;
            let mut events = Vec::with_capacity(count);
            for i in 0..count {
                let raw = unsafe { CStr::from_ptr(paths[i]) }.to_bytes();
                size += raw.len() + 64;
                if size > 1024 * 1024 {
                    delivery.overflow.store(true, Ordering::Release);
                    return;
                }
                events.push(Event {
                    path: PathBuf::from(std::ffi::OsStr::from_bytes(raw)),
                    flags: flags[i],
                    id: ids[i],
                });
            }
            if delivery.sender.try_send(Batch { events }).is_err() {
                delivery.overflow.store(true, Ordering::Release);
            }
        }));
        if result.is_err() {
            delivery.overflow.store(true, Ordering::Release);
        }
    }
    pub fn watch(identity: Identity, since: u64) -> Result<Watch> {
        let (sender, receiver) = mpsc::sync_channel(64);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let overflow = Arc::new(AtomicBool::new(false));
        let shared_overflow = overflow.clone();
        let latest = Arc::new(AtomicU64::new(since));
        let shared_latest = latest.clone();
        let join = thread::Builder::new()
            .name("mactrim-fsevents".into())
            .spawn(move || {
                let mut delivery = Delivery {
                    sender,
                    overflow: shared_overflow,
                    latest: shared_latest,
                };
                let relative = identity.relative.as_os_str().as_bytes();
                unsafe {
                    let path = CFStringCreateWithBytes(
                        std::ptr::null(),
                        relative.as_ptr(),
                        relative.len() as isize,
                        kCFStringEncodingUTF8,
                        0,
                    );
                    if path.is_null() {
                        let _ = ready_tx.send(Err("Cannot encode FSEvents path"));
                        return;
                    }
                    let values = [path as *const c_void];
                    let array = CFArrayCreate(
                        std::ptr::null(),
                        values.as_ptr() as *mut _,
                        1,
                        &kCFTypeArrayCallBacks,
                    );
                    let mut context = StreamContext {
                        version: 0,
                        info: &mut delivery as *mut _ as *mut c_void,
                        retain: std::ptr::null(),
                        release: std::ptr::null(),
                        description: std::ptr::null(),
                    };
                    let stream = FSEventStreamCreateRelativeToDevice(
                        std::ptr::null(),
                        callback,
                        &mut context,
                        identity.device as i32,
                        array.cast(),
                        since,
                        0.5,
                        4 | 16, // WatchRoot + FileEvents: keep invalidations at file/parent scope.
                    );
                    CFRelease(array.cast());
                    CFRelease(path.cast());
                    if stream.is_null() {
                        let _ = ready_tx.send(Err("Cannot create FSEvents stream"));
                        return;
                    }
                    FSEventStreamScheduleWithRunLoop(
                        stream,
                        CFRunLoopGetCurrent().cast(),
                        kCFRunLoopDefaultMode.cast(),
                    );
                    if FSEventStreamStart(stream) == 0 {
                        FSEventStreamInvalidate(stream);
                        FSEventStreamRelease(stream);
                        let _ = ready_tx.send(Err("Cannot start FSEvents stream"));
                        return;
                    }
                    FSEventStreamFlushAsync(stream);
                    let _ = ready_tx.send(Ok(()));
                    while !stopped.load(Ordering::Acquire) {
                        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 0);
                    }
                    FSEventStreamStop(stream);
                    FSEventStreamInvalidate(stream);
                    FSEventStreamRelease(stream);
                }
            })?;
        let watch = Watch {
            receiver,
            overflow,
            overflow_latest: latest,
            stop,
            join: Some(join),
        };
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .context("FSEvents startup did not complete")?
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(watch)
    }
}

#[cfg(target_os = "macos")]
pub use native::{current_id, identity, watch};
#[cfg(not(target_os = "macos"))]
pub fn identity(_: &Path) -> Result<Identity> {
    anyhow::bail!("The event service requires macOS");
}
#[cfg(not(target_os = "macos"))]
pub fn current_id() -> u64 {
    0
}
#[cfg(not(target_os = "macos"))]
pub fn watch(_: Identity, _: u64) -> Result<Watch> {
    anyhow::bail!("The event service requires macOS");
}
