#![cfg(target_os = "macos")]
use mactrim_rs::agent;
use std::{fs, path::PathBuf, process::Command};
fn binary() -> PathBuf {
    std::env::var_os("MACTRIM_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mactrim").into())
}
#[test]
fn native_cli_measures_deep_sizes_and_reports_build_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir_all(root.join("node_modules/package/deeper")).unwrap();
    fs::write(
        root.join("node_modules/package/deeper/data"),
        vec![1; 65536],
    )
    .unwrap();
    std::os::unix::fs::symlink(&root, root.join("cycle")).unwrap();
    let output = Command::new(binary())
        .arg("--state")
        .arg(&state)
        .arg("scan")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["node"]["logical"].as_u64().unwrap() >= 65536);
    assert_eq!(result["directories"], 2);
    assert_eq!(result["node"]["status"], 0);
    let output = Command::new(binary()).arg("build-info").output().unwrap();
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["runtime"], "Rust; no Python interpreter");
    assert_eq!(info["binary_sha256"].as_str().unwrap().len(), 64);
}
#[test]
fn launchagent_arguments_are_literal_and_successful_stop_does_not_restart() {
    let state = PathBuf::from("/fixture/space and $(not-a-command)");
    let root = PathBuf::from("/fixture/quoted ' root");
    let value = agent::plist_value(&state, &root).unwrap();
    let dict = value.as_dictionary().unwrap();
    let args = dict["ProgramArguments"].as_array().unwrap();
    assert_eq!(args[2].as_string(), state.to_str());
    assert_eq!(args[5].as_string(), root.to_str());
    assert_eq!(
        dict["KeepAlive"].as_dictionary().unwrap()["SuccessfulExit"].as_boolean(),
        Some(false)
    );
    let mut xml = Vec::new();
    value.to_writer_xml(&mut xml).unwrap();
    assert_eq!(
        plist::Value::from_reader(std::io::Cursor::new(xml)).unwrap(),
        value
    );
}
#[test]
fn staged_native_service_is_signed_and_failed_upgrade_preserves_it() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let state = base.join("state");
    let installed = agent::stage(&state, &base, &binary()).unwrap();
    let first = fs::read(&installed).unwrap();
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(agent::bundle(&state))
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        Command::new(&installed)
            .arg("--version")
            .status()
            .unwrap()
            .success()
    );
    let invalid = base.join("not-a-binary");
    fs::write(&invalid, b"invalid executable").unwrap();
    assert!(agent::stage(&state, &base, &invalid).is_err());
    assert_eq!(fs::read(&installed).unwrap(), first);
    agent::stage(&state, &base, &binary()).unwrap();
    let custom = state.join("agent/keep-this-note");
    fs::write(&custom, b"user data").unwrap();
    assert!(agent::stage(&state, &base, &binary()).is_err());
    assert_eq!(fs::read(&custom).unwrap(), b"user data");
}
#[test]
fn unapproved_cleanup_cannot_delete_any_payload() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let state = base.join("state");
    let data = base.join("keep");
    fs::write(&data, b"preserve").unwrap();
    let result = Command::new(binary())
        .arg("--state")
        .arg(&state)
        .args([
            "cleanup",
            "purge",
            "00000000-0000-0000-0000-000000000000",
            "--approve",
            "wrong",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(data).unwrap(), b"preserve");
    assert!(!state.exists());
}
