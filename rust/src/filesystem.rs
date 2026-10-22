//! Filesystem metadata only. No change notifications or event history.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub volume_uuid: Option<String>,
}
impl Identity {
    pub fn same_root(&self, other: &Self) -> bool {
        self.inode == other.inode
            && match (&self.volume_uuid, &other.volume_uuid) {
                (Some(a), Some(b)) => a == b,
                _ => self.device == other.device,
            }
    }
}
pub fn identity(root: &Path) -> Result<Identity> {
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "Scan root must be a real directory"
    );
    Ok(Identity {
        device: meta.dev(),
        inode: meta.ino(),
        volume_uuid: volume_uuid(root)?,
    })
}
#[cfg(target_os = "macos")]
fn volume_uuid(root: &Path) -> Result<Option<String>> {
    let name = CString::new(root.as_os_str().as_bytes())?;
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
        "Cannot read filesystem identity: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        u32::from_ne_bytes(data[..4].try_into()?) == 20,
        "Unexpected filesystem identity response"
    );
    Ok(Some(
        uuid::Uuid::from_bytes(data[4..].try_into()?).to_string(),
    ))
}
#[cfg(not(target_os = "macos"))]
fn volume_uuid(_: &Path) -> Result<Option<String>> {
    Ok(None)
}

pub fn capacity(root: &Path) -> Result<(u64, u64)> {
    let name = CString::new(root.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), value.as_mut_ptr()) } == 0,
        "Filesystem capacity unavailable: {}",
        std::io::Error::last_os_error()
    );
    let value = unsafe { value.assume_init() };
    Ok((
        (value.f_blocks.saturating_sub(value.f_bfree) as u64) * value.f_frsize,
        (value.f_bavail as u64) * value.f_frsize,
    ))
}
