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
        Command::new(
            std::env::var_os("MACTRIM_TEST_BINARY")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_mactrim").into()),
        )
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
#[track_caller]
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
    let mut restarted = spawn(&root, &state);
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
            anchor: None,
        },
    )
    .unwrap();
    assert_eq!(reply.rows[0].path, root.join("a"));
    request(&state, &Request::Pause).unwrap();
    let paused = wait(&state, |s| s.paused);
    assert!(paused.error.is_none());
    assert_eq!(
        paused.last_interruption.unwrap().reason,
        "User requested Pause"
    );
    fs::write(root.join("a/new"), vec![4; 4096]).unwrap();
    wait(&state, |s| s.paused && s.pending_regions > 0);
    request(&state, &Request::Stop).unwrap();
    assert!(restarted.0.wait().unwrap().success());
    let _daemon = spawn(&root, &state);
    let paused = wait(&state, |s| s.paused && !s.loading && s.history_ready);
    assert!(
        paused.error.is_none(),
        "User pause became a failure on restart"
    );
    assert_eq!(paused.last_saved, third.last_saved);
    assert!(paused.pending_regions > 0);
    request(&state, &Request::Refresh { full: false }).unwrap();
    let resumed = wait(&state, |s| {
        !s.paused && !s.running && s.pending_regions == 0
    });
    assert!(resumed.error.is_none());
    for _ in 0..3 {
        request(&state, &Request::Refresh { full: true }).unwrap();
        request(&state, &Request::Pause).unwrap();
        request(&state, &Request::Refresh { full: false }).unwrap();
        let settled = wait(&state, |s| {
            !s.running && !s.paused && s.pending_regions == 0
        });
        assert!(
            settled.error.is_none(),
            "Late cancellation became a failure: {:?}",
            settled.error
        );
    }
}

#[test]
fn replaced_history_stays_idle_until_explicit_refresh_and_preserves_budget() {
    use mactrim_rs::{
        events,
        regions::Regions,
        scan,
        store::{Generation, Store},
    };
    use std::sync::atomic::AtomicBool;
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    fs::write(root.join("b/stable"), vec![1; 4096]).unwrap();
    let mut identity = events::identity(&root).unwrap();
    identity.uuid = "retired-fixture-history".into();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity, events::current_id()).unwrap();
    let baseline = scan::measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &baseline).unwrap();
    let work = store.claim().unwrap();
    store.commit(&generation, &work, &baseline).unwrap();
    drop(store);

    let mut daemon = spawn(&root, &state);
    let idle = wait(&state, |s| {
        !s.loading && s.history_ready && s.paused && s.finish_then_idle
    });
    assert!(!idle.running && !idle.detail_running);
    assert_eq!(idle.visited, 0);
    assert_eq!(idle.last_saved, generation.created);
    assert_eq!(idle.cpu_percent, 10);
    assert!(idle.verification.is_some());
    assert!(
        request(
            &state,
            &Request::Policy {
                cpu_percent: Some(0)
            }
        )
        .is_err()
    );
    request(
        &state,
        &Request::Policy {
            cpu_percent: Some(25),
        },
    )
    .unwrap();
    wait(&state, |s| s.cpu_percent == 25 && s.paused && !s.running);
    fs::write(root.join("a/data"), vec![2; 128 * 1024]).unwrap();
    let queued = wait(&state, |s| s.pending_regions > 0 && s.paused);
    assert_eq!(queued.visited, 0, "New events resumed measurement");
    assert_eq!(queued.last_saved, generation.created);
    request(&state, &Request::Stop).unwrap();
    assert!(daemon.0.wait().unwrap().success());

    let mut restarted = spawn(&root, &state);
    let idle = wait(&state, |s| {
        !s.loading && s.history_ready && s.paused && s.finish_then_idle
    });
    assert_eq!(idle.visited, 0, "Restart resumed measurement");
    assert_eq!(idle.cpu_percent, 25);
    assert_eq!(idle.directories, generation.directories);
    request(&state, &Request::Refresh { full: false }).unwrap();
    let refreshed = wait(&state, |s| {
        !s.paused
            && !s.running
            && s.pending_regions == 0
            && s.root_node
                .as_ref()
                .is_some_and(|n| n.logical > baseline.root_node().unwrap().logical)
    });
    assert!(!refreshed.finish_then_idle);
    assert!(
        refreshed.reused > 0,
        "Explicit Refresh walked an unchanged sibling"
    );
    assert!(
        refreshed.verification.is_some(),
        "Incremental refresh concealed missing history"
    );
    request(&state, &Request::Stop).unwrap();
    assert!(restarted.0.wait().unwrap().success());
}
