#![cfg(target_os = "macos")]
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
        .arg("--json")
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
    assert!(result["logical"].as_u64().unwrap() >= 65536);
    assert_eq!(result["directories"], 4);
    assert_eq!(result["coverage"], 0);
    let output = Command::new(binary()).arg("build-info").output().unwrap();
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["runtime"], "Rust; no Python interpreter");
    assert_eq!(info["binary_sha256"].as_str().unwrap().len(), 64);
}
#[test]
fn executable_has_no_service_entrypoint_or_filesystem_event_framework() {
    let help = Command::new(binary()).arg("--help").output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(!text.lines().any(|l| l.trim_start().starts_with("service ")));
    let removed = Command::new(binary())
        .args(["service", "start"])
        .output()
        .unwrap();
    assert!(!removed.status.success());
    let linked = Command::new("/usr/bin/otool")
        .arg("-L")
        .arg(binary())
        .output()
        .unwrap();
    assert!(linked.status.success());
    let linked = String::from_utf8_lossy(&linked.stdout);
    assert!(!linked.contains("CoreServices.framework"), "{linked}");
    let symbols = Command::new("/usr/bin/nm")
        .arg("-u")
        .arg(binary())
        .output()
        .unwrap();
    assert!(symbols.status.success());
    assert!(!String::from_utf8_lossy(&symbols.stdout).contains("FSEvent"));
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

#[test]
fn separate_cli_scans_compare_offline_edits_and_print_readable_output() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    let invoke = |args: &[&std::ffi::OsStr]| {
        Command::new(binary())
            .arg("--state")
            .arg(&state)
            .args(args)
            .output()
            .unwrap()
    };
    let initial = invoke(&["status".as_ref()]);
    assert!(initial.status.success());
    assert!(!state.exists());
    assert!(String::from_utf8_lossy(&initial.stdout).contains("no background service"));
    let scan = invoke(&["scan".as_ref(), root.as_os_str()]);
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let text = String::from_utf8_lossy(&scan.stdout);
    assert!(text.contains("Scan #1 saved"));
    assert!(!text.trim_start().starts_with('{'));
    fs::write(root.join("a/data"), vec![2; 65536]).unwrap();
    let status = invoke(&["status".as_ref()]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("Scan #1 saved"));
    let scan = invoke(&["--json".as_ref(), "refresh".as_ref(), root.as_os_str()]);
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let saved: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(saved["id"], 2);
    assert_eq!(saved["visited"], 3);
    let history = invoke(&[
        "--json".as_ref(),
        "history".as_ref(),
        root.as_os_str(),
        "--from".as_ref(),
        "1".as_ref(),
        "--to".as_ref(),
        "2".as_ref(),
    ]);
    assert!(
        history.status.success(),
        "{}",
        String::from_utf8_lossy(&history.stderr)
    );
    let compared: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(compared["compare_from"]["id"], 1);
    assert_eq!(compared["compare_to"]["id"], 2);
    assert_eq!(compared["snapshots"].as_array().unwrap().len(), 2);
    assert!(compared["history"].as_array().unwrap().iter().any(|v| {
        v["after"]["logical"].as_u64().unwrap() > v["before"]["logical"].as_u64().unwrap()
    }));
    let human = invoke(&["history".as_ref(), root.as_os_str()]);
    let human = String::from_utf8_lossy(&human.stdout);
    assert!(human.contains("Growth"));
    assert!(!human.trim_start().starts_with('{'));
    assert!(!state.join("service.sock").exists());
    assert!(!state.join("service.sqlite3").exists());
}
