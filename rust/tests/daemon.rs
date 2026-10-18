#![cfg(target_os = "macos")]
use mactrim_rs::service::{Request, Status, request};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn(root: &Path, state: &Path) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_mactrim"))
            .arg("--state")
            .arg(state)
            .args(["service", "run"])
            .arg(root)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
fn wait(state: &Path, predicate: impl Fn(&Status) -> bool) -> Status {
    let started = Instant::now();
    let mut last = None;
    loop {
        if let Ok(reply) = request(state, &Request::Status) {
            if predicate(&reply.status) {
                return reply.status;
            }
            last = Some(reply.status);
        }
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "Service did not reach expected state: {last:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
#[test]
fn real_daemon_tracks_edits_and_recovers_changes_made_while_stopped() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = root.join(".state");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    fs::write(root.join("b/stable"), vec![1; 4096]).unwrap();
    let mut daemon = spawn(&root, &state);
    let first = wait(&state, |s| {
        s.last_saved > 0 && !s.running && s.pending_regions == 0
    });
    fs::write(root.join("a/data"), vec![2; 128 * 1024]).unwrap();
    let second = wait(&state, |s| {
        s.root_node
            .as_ref()
            .is_some_and(|n| n.logical > first.root_node.as_ref().unwrap().logical)
            && !s.running
            && s.pending_regions == 0
    });
    assert!(second.reused > 0, "An unchanged sibling must be reused");
    request(&state, &Request::Stop).unwrap();
    assert!(daemon.0.wait().unwrap().success());
    fs::write(root.join("a/data"), vec![3; 256 * 1024]).unwrap();
    let _daemon = spawn(&root, &state);
    let third = wait(&state, |s| {
        s.root_node
            .as_ref()
            .is_some_and(|n| n.logical > second.root_node.as_ref().unwrap().logical)
            && !s.running
            && s.pending_regions == 0
    });
    assert!(third.reused > 0);
    let reply = request(
        &state,
        &Request::List {
            path: root.clone(),
            offset: 0,
            limit: 20,
            logical: false,
        },
    )
    .unwrap();
    assert_eq!(reply.rows[0].path, root.join("a"));
    request(&state, &Request::Pause).unwrap();
    wait(&state, |s| s.paused);
    fs::write(root.join("a/new"), vec![4; 4096]).unwrap();
    wait(&state, |s| s.paused && s.pending_regions > 0);
    request(&state, &Request::Refresh { full: false }).unwrap();
    wait(&state, |s| {
        !s.paused && !s.running && s.pending_regions == 0
    });
}
