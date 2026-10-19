#![cfg(target_os = "macos")]
use mactrim_rs::{service, store};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn binary() -> PathBuf {
    std::env::var_os("MACTRIM_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mactrim").into())
}
fn cli(state: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(binary())
        .arg("--state")
        .arg(state)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "CLI timed out for {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    (temp, base)
}

#[test]
fn absent_service_status_and_repeated_stop_succeed_without_creating_state() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    for _ in 0..2 {
        for args in [
            &["status"][..],
            &["service", "status"],
            &["service", "stop"],
        ] {
            let reply = success(cli(&state, args));
            assert_eq!(reply["status"]["phase"], "Stopped");
            assert_eq!(reply["status"]["pid"], 0);
            assert!(!reply["message"].as_str().unwrap().is_empty());
            assert!(
                !state.exists(),
                "An offline query must not initialize a new index"
            );
        }
    }
}

#[test]
fn stale_owned_socket_is_stopped_and_is_preserved() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    store::prepare_private(&state).unwrap();
    let socket = state.join("service.sock");
    drop(UnixListener::bind(&socket).unwrap());
    for args in [&["status"][..], &["service", "stop"]] {
        let reply = success(cli(&state, args));
        assert_eq!(reply["status"]["phase"], "Stopped");
        assert!(fs::symlink_metadata(&socket).is_ok());
    }
}

#[test]
fn unsafe_socket_is_never_reported_as_a_stopped_service() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    store::prepare_private(&state).unwrap();
    let socket = state.join("service.sock");
    fs::write(&socket, b"preserve unexpected data").unwrap();
    for args in [
        &["status"][..],
        &["service", "stop"],
        &["service", "start"],
        &["service", "restart"],
    ] {
        let output = cli(&state, args);
        assert!(
            !output.status.success(),
            "Unsafe socket accepted for {args:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Unsafe service socket"));
        assert_eq!(fs::read(&socket).unwrap(), b"preserve unexpected data");
        assert!(!state.join("writer.lock").exists());
    }
}

#[test]
fn denied_socket_access_remains_an_error() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "Run lifecycle checks without sudo"
    );
    let (_temp, base) = fixture();
    let state = base.join("state");
    store::prepare_private(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o000)).unwrap();
    let outputs = [cli(&state, &["status"]), cli(&state, &["service", "stop"])];
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    for output in outputs {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
    }
}

#[test]
fn malformed_service_reply_remains_an_error() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    store::prepare_private(&state).unwrap();
    let socket = state.join("service.sock");
    for args in [&["status"][..], &["service", "stop"]] {
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            stream.write_all(b"this is not a service reply\n").unwrap();
        });
        let output = cli(&state, args);
        server.join().unwrap();
        fs::remove_file(&socket).unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("No such file or directory"));
    }
}

#[test]
fn stop_waits_for_the_acknowledged_services_writer_to_close() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    store::prepare_private(&state).unwrap();
    let writer = store::private_file(&state.join("writer.lock"), true).unwrap();
    fs2::FileExt::lock_exclusive(&writer).unwrap();
    let socket = state.join("service.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (acknowledged, ack) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["command"],
            "stop"
        );
        serde_json::to_writer(&mut stream, &Ok::<_, String>(service::Reply::default())).unwrap();
        stream.write_all(b"\n").unwrap();
        drop(stream);
        drop(listener);
        fs::remove_file(socket).unwrap();
        acknowledged.send(()).unwrap();
        let _ = released.recv_timeout(Duration::from_secs(5));
        drop(writer);
    });
    let mut stopping = Command::new(binary())
        .arg("--state")
        .arg(&state)
        .args(["service", "stop"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ack.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        success(cli(&state, &["service", "status"]))["status"]["phase"],
        "Starting or stopping"
    );
    assert!(
        stopping.try_wait().unwrap().is_none(),
        "Stop acknowledged before the writer was released"
    );
    release.send(()).unwrap();
    assert_eq!(
        success(stopping.wait_with_output().unwrap())["status"]["phase"],
        "Stopped"
    );
    server.join().unwrap();
}

struct Running(PathBuf);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = cli(&self.0, &["service", "stop"]);
    }
}
fn settled(state: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let reply = success(cli(state, &["status"]));
        if reply["status"]["last_saved"].as_u64().unwrap() > 0
            && reply["status"]["pending_regions"] == 0
            && reply["status"]["running"] == false
        {
            return reply;
        }
        assert!(Instant::now() < deadline, "Service did not settle: {reply}");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn immediate_stop_start_and_restart_keep_the_saved_root_and_index() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    let root = base.join("files");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("data"), vec![1; 8192]).unwrap();
    let _running = Running(state.clone());
    success(cli(&state, &["service", "start", root.to_str().unwrap()]));
    let first = settled(&state);
    let baseline = first["status"]["root_node"]["logical"].clone();
    let mut pid = first["status"]["pid"].clone();
    assert_eq!(
        success(cli(&state, &["service", "start", root.to_str().unwrap()]))["status"]["pid"],
        pid
    );
    for _ in 0..3 {
        let stopped = success(cli(&state, &["service", "stop"]));
        assert_eq!(stopped["status"]["phase"], "Stopped");
        assert!(
            !state.join("service.sock").exists(),
            "Stop returned before shutdown"
        );
        assert_eq!(
            success(cli(&state, &["service", "stop"]))["status"]["phase"],
            "Stopped"
        );
        success(cli(&state, &["service", "start", root.to_str().unwrap()]));
        let current = settled(&state);
        assert_ne!(current["status"]["pid"], pid);
        assert_eq!(current["status"]["root_node"]["logical"], baseline);
        pid = current["status"]["pid"].clone();
        let current = success(cli(&state, &["service", "restart"]));
        assert_ne!(current["status"]["pid"], pid);
        assert_eq!(current["status"]["root"], root.to_str().unwrap());
        let current = settled(&state);
        assert_eq!(current["status"]["root_node"]["logical"], baseline);
        pid = current["status"]["pid"].clone();
    }
    success(cli(&state, &["service", "stop"]));
    let current = success(cli(&state, &["service", "restart"]));
    assert_eq!(current["status"]["root"], root.to_str().unwrap());
    assert_eq!(settled(&state)["status"]["root_node"]["logical"], baseline);
    let mismatch = base.join("other");
    fs::create_dir(&mismatch).unwrap();
    let pid = success(cli(&state, &["status"]))["status"]["pid"].clone();
    assert!(
        !cli(&state, &["service", "restart", mismatch.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        success(cli(&state, &["service", "status"]))["status"]["pid"],
        pid
    );
    assert_eq!(
        service::request(&state, &service::Request::Status)
            .unwrap()
            .status
            .root,
        root
    );
}

#[test]
fn restart_can_start_a_new_service_with_an_explicit_root() {
    let (_temp, base) = fixture();
    let state = base.join("state");
    let root = base.join("files");
    fs::create_dir(&root).unwrap();
    let _running = Running(state.clone());
    let reply = success(cli(&state, &["service", "restart", root.to_str().unwrap()]));
    assert_eq!(reply["status"]["root"], root.to_str().unwrap());
    assert!(reply["status"]["pid"].as_u64().unwrap() > 0);
    settled(&state);
}
