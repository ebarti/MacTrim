//! Explicit per-user launchd installation. Installation never grants access or
//! changes system privacy settings; an installed service has no cleanup API.
use crate::{
    service::{self, Request},
    store,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub const LABEL: &str = "io.github.ebarti.mactrim.storage";
const APP_ID: &str = "io.github.ebarti.mactrim.service";
#[derive(Serialize, Deserialize)]
struct Receipt {
    schema: String,
    #[serde(with = "crate::paths")]
    state: PathBuf,
    #[serde(with = "crate::paths")]
    root: PathBuf,
    executable_sha256: String,
}
pub fn bundle(state: &Path) -> PathBuf {
    state.join("agent/MacTrim Service.app")
}
fn executable(state: &Path) -> PathBuf {
    bundle(state).join("Contents/MacOS/mactrim")
}
fn text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .context("LaunchAgent installation requires UTF-8 paths")
}
pub fn plist_value(state: &Path, root: &Path) -> Result<Value> {
    let mut p = Dictionary::new();
    p.insert("Label".into(), Value::String(LABEL.into()));
    p.insert(
        "ProgramArguments".into(),
        Value::Array(
            [
                text(&executable(state))?,
                "--state".into(),
                text(state)?,
                "service".into(),
                "run".into(),
                text(root)?,
            ]
            .into_iter()
            .map(Value::String)
            .collect(),
        ),
    );
    p.insert("RunAtLoad".into(), Value::Boolean(true));
    let mut keep = Dictionary::new();
    keep.insert("SuccessfulExit".into(), Value::Boolean(false));
    p.insert("KeepAlive".into(), Value::Dictionary(keep));
    p.insert("ThrottleInterval".into(), Value::Integer(10.into()));
    p.insert("ProcessType".into(), Value::String("Background".into()));
    p.insert("LowPriorityIO".into(), Value::Boolean(true));
    p.insert("WorkingDirectory".into(), Value::String("/".into()));
    p.insert(
        "StandardOutPath".into(),
        Value::String(text(&state.join("service.log"))?),
    );
    p.insert(
        "StandardErrorPath".into(),
        Value::String(text(&state.join("service.log"))?),
    );
    p.insert("MacTrimManagedVersion".into(), Value::Integer(1.into()));
    p.insert("MacTrimState".into(), Value::String(text(state)?));
    Ok(Value::Dictionary(p))
}
fn safe_existing(path: &Path, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o777 == mode,
        "Unexpected installation file preserved: {}",
        path.display()
    );
    Ok(())
}
fn atomic_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        safe_existing(path, mode)?;
    }
    let mut pending =
        tempfile::NamedTempFile::new_in(path.parent().context("Missing installation parent")?)?;
    pending.write_all(data)?;
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    pending.as_file().sync_all()?;
    pending.persist(path).map_err(|e| e.error)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn sha256(path: &Path) -> Result<String> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// Stage a stable app bundle. Pure filesystem work can be tested with temporary
/// homes; launchctl is only called by the explicit install/uninstall commands.
fn validate_installation(agent: &Path, state: &Path) -> Result<()> {
    let exe = agent.join("MacTrim Service.app/Contents/MacOS/mactrim");
    safe_existing(&exe, 0o700)?;
    let old: Receipt = serde_json::from_reader(store::private_file(
        &agent.join("installation.json"),
        false,
    )?)?;
    ensure!(
        old.schema == "mactrim.agent.v1"
            && old.state == state
            && old.executable_sha256 == sha256(&exe)?,
        "Installed executable was modified; original preserved"
    );
    let allowed = [
        "",
        "installation.json",
        "MacTrim Service.app",
        "MacTrim Service.app/Contents",
        "MacTrim Service.app/Contents/Info.plist",
        "MacTrim Service.app/Contents/MacOS",
        "MacTrim Service.app/Contents/MacOS/mactrim",
        "MacTrim Service.app/Contents/_CodeSignature",
        "MacTrim Service.app/Contents/_CodeSignature/CodeResources",
    ];
    for entry in walkdir::WalkDir::new(agent).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(agent)?;
        ensure!(
            relative.to_str().is_some_and(|s| allowed.contains(&s)),
            "Unexpected installation contents preserved: {}",
            entry.path().display()
        );
        let m = fs::symlink_metadata(entry.path())?;
        ensure!(
            !m.file_type().is_symlink()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0,
            "Unsafe installation contents preserved"
        );
    }
    Ok(())
}
pub fn stage(state: &Path, root: &Path, source: &Path) -> Result<PathBuf> {
    store::prepare_private(state)?;
    let agent = state.join("agent");
    if fs::symlink_metadata(&agent).is_ok() {
        store::prepare_private(&agent)?;
        validate_installation(&agent, state)?;
    }
    let pending = tempfile::Builder::new()
        .prefix("agent-stage-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(state)?;
    let app = pending.path().join("MacTrim Service.app");
    for path in [
        app.clone(),
        app.join("Contents"),
        app.join("Contents/MacOS"),
    ] {
        store::prepare_private(&path)?;
    }
    let dest = app.join("Contents/MacOS/mactrim");
    let mut contents = Dictionary::new();
    for (k, v) in [
        ("CFBundleIdentifier", APP_ID),
        ("CFBundleName", "MacTrim Service"),
        ("CFBundleExecutable", "mactrim"),
        ("CFBundlePackageType", "APPL"),
        ("CFBundleVersion", env!("CARGO_PKG_VERSION")),
    ] {
        contents.insert(k.into(), Value::String(v.into()));
    }
    let mut xml = Vec::new();
    Value::Dictionary(contents).to_writer_xml(&mut xml)?;
    atomic_file(&app.join("Contents/Info.plist"), &xml, 0o600)?;
    let mut source_file = File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&dest)?;
    std::io::copy(&mut source_file, &mut output)?;
    output.sync_all()?;
    #[cfg(target_os = "macos")]
    {
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--identifier", APP_ID])
            .arg(&app)
            .output()?;
        ensure!(
            signed.status.success(),
            "Service signing failed: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    let r = Receipt {
        schema: "mactrim.agent.v1".into(),
        state: state.to_owned(),
        root: root.to_owned(),
        executable_sha256: sha256(&dest)?,
    };
    atomic_file(
        &pending.path().join("installation.json"),
        &serde_json::to_vec(&r)?,
        0o600,
    )?;
    File::open(&dest)?.sync_all()?;
    for path in [
        app.join("Contents/MacOS"),
        app.join("Contents"),
        app,
        pending.path().to_owned(),
    ] {
        File::open(path)?.sync_all()?;
    }
    validate_installation(pending.path(), state)?;
    for entry in walkdir::WalkDir::new(pending.path()).contents_first(true) {
        File::open(entry?.path())?.sync_all()?;
    }
    if agent.exists() {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;
            let a = std::ffi::CString::new(pending.path().as_os_str().as_bytes())?;
            let b = std::ffi::CString::new(agent.as_os_str().as_bytes())?;
            ensure!(
                unsafe {
                    libc::renameatx_np(
                        libc::AT_FDCWD,
                        a.as_ptr(),
                        libc::AT_FDCWD,
                        b.as_ptr(),
                        libc::RENAME_SWAP,
                    )
                } == 0,
                "Atomic service upgrade failed: {}",
                std::io::Error::last_os_error()
            );
            // The temporary directory now holds only the validated previous app.
        }
        #[cfg(not(target_os = "macos"))]
        anyhow::bail!("Service upgrades require macOS");
    } else {
        fs::rename(pending.path(), &agent)?;
    }
    File::open(state)?.sync_all()?;
    store::private_file(&state.join("service.log"), true)?;
    Ok(executable(state))
}
fn agent_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}
fn validate_agent(state: &Path, path: &Path) -> Result<()> {
    safe_existing(path, 0o600)?;
    let v = Value::from_reader(store::private_file(path, false)?)?;
    let p = v.as_dictionary().context("Invalid LaunchAgent")?;
    ensure!(
        p.get("Label").and_then(Value::as_string) == Some(LABEL)
            && p.get("MacTrimManagedVersion")
                .and_then(Value::as_unsigned_integer)
                == Some(1)
            && p.get("MacTrimState").and_then(Value::as_string) == state.to_str(),
        "LaunchAgent belongs to another installation; original preserved"
    );
    Ok(())
}
fn launchctl(args: &[&std::ffi::OsStr]) -> Result<()> {
    let out = Command::new("/bin/launchctl").args(args).output()?;
    ensure!(
        out.status.success(),
        "launchctl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}
fn loaded() -> bool {
    Command::new("/bin/launchctl")
        .arg("print")
        .arg(format!("gui/{}/{LABEL}", unsafe { libc::geteuid() }))
        .output()
        .is_ok_and(|o| o.status.success())
}
pub fn start_managed(state: &Path) -> Result<bool> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let path = agent_path(&home);
    if !path.exists() {
        return Ok(false);
    }
    // A separate --state fixture must never kick another installed service.
    let v = Value::from_file(&path)?;
    if v.as_dictionary()
        .and_then(|p| p.get("MacTrimState"))
        .and_then(Value::as_string)
        != state.to_str()
    {
        return Ok(false);
    }
    validate_agent(state, &path)?;
    if loaded() {
        launchctl(&[
            "kickstart".as_ref(),
            format!("gui/{}/{LABEL}", unsafe { libc::geteuid() }).as_ref(),
        ])?;
    } else {
        launchctl(&[
            "bootstrap".as_ref(),
            format!("gui/{}", unsafe { libc::geteuid() }).as_ref(),
            path.as_os_str(),
        ])?;
    }
    Ok(true)
}
pub fn install(state: &Path, root: &Path) -> Result<PathBuf> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Install this per-user service without sudo"
    );
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let path = agent_path(&home);
    let parent = path.parent().unwrap();
    if parent.exists() {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == unsafe { libc::geteuid() },
            "Unsafe LaunchAgents directory"
        );
    } else {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        validate_agent(state, &path)?;
    }
    if let Some(saved) = store::Store::configured_root(state)? {
        ensure!(
            saved == root,
            "This state belongs to another root; use a separate --state directory"
        );
    }
    let running = service::request(state, &Request::Status).ok();
    if let Some(reply) = &running {
        ensure!(
            reply.status.root == root,
            "Running service belongs to another root"
        );
    }
    // A failed signature or copy leaves the old service running unchanged.
    stage(state, root, &std::env::current_exe()?)?;
    if running.is_some() {
        service::request(state, &Request::Stop)?;
        let start = Instant::now();
        while service::request(state, &Request::Status).is_ok() {
            ensure!(
                start.elapsed() < Duration::from_secs(10),
                "Service has not stopped; installation not started"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    if loaded() {
        validate_agent(state, &path)?;
        launchctl(&[
            "bootout".as_ref(),
            format!("gui/{}/{LABEL}", unsafe { libc::geteuid() }).as_ref(),
        ])?;
    }
    let mut data = Vec::new();
    plist_value(state, root)?.to_writer_xml(&mut data)?;
    atomic_file(&path, &data, 0o600)?;
    start_managed(state)?;
    Ok(bundle(state))
}
pub fn uninstall(state: &Path) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let path = agent_path(&home);
    validate_agent(state, &path)?;
    if loaded() {
        launchctl(&[
            "bootout".as_ref(),
            format!("gui/{}/{LABEL}", unsafe { libc::geteuid() }).as_ref(),
        ])?;
    }
    fs::remove_file(&path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    // Keep the executable, index, History and all cleanup recovery data.
    Ok(())
}
