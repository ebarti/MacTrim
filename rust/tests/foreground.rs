use mactrim_rs::{
    model::{Index, Node},
    scan,
    session::{self, Request, ScanState, Session},
    snapshots::{Capture, Snapshots},
    store,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    fs::create_dir(&root).unwrap();
    (temp, root, base.join("state"))
}
fn settled(session: &Session) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while session.status().running {
        assert!(Instant::now() < deadline, "{:?}", session.status());
        thread::sleep(Duration::from_millis(5));
    }
    assert!(session.status().error.is_none(), "{:?}", session.status());
}
fn listing(session: &std::sync::Arc<Session>, path: &Path) -> session::Reply {
    session
        .request(&Request::List {
            path: path.to_owned(),
            offset: 0,
            limit: 200,
            logical: false,
            anchor: None,
        })
        .unwrap()
}
#[test]
fn edits_do_nothing_until_requested_full_scan_and_navigation_does_not_start_work() {
    let (_temp, root, state) = fixture();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    let session = Session::new(state.clone(), root.clone());
    session.start_scan().unwrap();
    settled(&session);
    let first = session.status();
    assert_eq!(first.scan_state, ScanState::Completed);
    let a = listing(&session, &root)
        .rows
        .into_iter()
        .find(|r| r.path == root.join("a"))
        .unwrap();
    fs::write(root.join("a/data"), vec![2; 65536]).unwrap();
    // Navigation and status queries have no change receiver and cannot start a scan.
    for _ in 0..4 {
        listing(&session, &root.join("a"));
        listing(&session, &root);
    }
    let idle = session.status();
    assert!(!idle.running);
    assert_eq!(idle.snapshot_id, first.snapshot_id);
    assert_eq!(idle.visited, first.visited);
    let unchanged = listing(&session, &root)
        .rows
        .into_iter()
        .find(|r| r.path == root.join("a"))
        .unwrap();
    assert_eq!(unchanged.node, a.node);
    session.request(&Request::Scan).unwrap();
    settled(&session);
    let next = session.status();
    assert!(next.snapshot_id > first.snapshot_id);
    assert_eq!(next.visited, first.visited);
    let updated = listing(&session, &root)
        .rows
        .into_iter()
        .find(|r| r.path == root.join("a"))
        .unwrap();
    assert!(updated.node.logical > a.node.logical);
    let reply = session
        .request(&Request::History {
            path: root.clone(),
            from: first.snapshot_id,
            to: next.snapshot_id,
            offset: 0,
            limit: 200,
        })
        .unwrap();
    assert!(
        reply
            .history
            .iter()
            .any(|c| c.path == root.join("a") && c.growth().is_some_and(|v| v > 0))
    );
    session.close();
    assert!(!state.join("service.sock").exists());
    assert!(!state.join("service.sqlite3").exists());
    assert!(
        Snapshots::open(&state).is_ok(),
        "Closing the terminal releases its writer"
    );
    assert!(
        session.start_scan().is_err(),
        "Closed sessions cannot restart"
    );
}
#[test]
fn cancelling_an_active_pass_preserves_last_scan_and_never_restarts() {
    let (_temp, root, state) = fixture();
    let session = Session::new(state.clone(), root.clone());
    session.start_scan().unwrap();
    settled(&session);
    let saved = session.status().snapshot_id;
    for i in 0..8000 {
        fs::create_dir(root.join(format!("dir-{i:05}"))).unwrap();
    }
    session.start_scan().unwrap();
    assert!(
        !session.start_scan().unwrap(),
        "Another request cannot reset the active scan"
    );
    let _ = listing(&session, &root.join("dir-00000"));
    session.cancel();
    settled(&session);
    assert_eq!(session.status().snapshot_id, saved);
    assert_eq!(session.status().scan_state, ScanState::Cancelled);
    assert!(session.status().phase.contains("cancelled"));
    for _ in 0..5 {
        listing(&session, &root);
        assert!(!session.status().running);
    }
    session.close();
    assert_eq!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn closing_active_terminal_cancels_and_joins_the_owned_worker() {
    let (_temp, root, state) = fixture();
    for i in 0..4000 {
        fs::create_dir(root.join(format!("dir-{i}"))).unwrap();
    }
    let session = Session::new(state.clone(), root);
    session.start_scan().unwrap();
    session.close();
    assert!(!session.status().running);
    assert!(Snapshots::open(&state).is_ok());
    assert!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn writer_exclusion_checksum_and_cancelled_serialization_preserve_completed_data() {
    let (_temp, root, state) = fixture();
    fs::create_dir(root.join("a")).unwrap();
    let mut catalog = Snapshots::open(&state).unwrap();
    assert!(Snapshots::open(&state).is_err());
    let index = scan::full(&root, &[], &AtomicBool::new(false), None).unwrap();
    let capture = Capture::begin(&root).unwrap();
    let first = catalog
        .save(&index, &capture, &AtomicBool::new(false))
        .unwrap();
    let before = fs::read_dir(&state)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|e| e == "gz"))
        .count();
    assert!(
        catalog
            .save(&index, &capture, &AtomicBool::new(true))
            .is_err()
    );
    let after = fs::read_dir(&state)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|e| e == "gz"))
        .count();
    assert_eq!(before, after);
    let file = state.join(&first.generation.name);
    let original = fs::read(&file).unwrap();
    fs::write(&file, b"corrupt").unwrap();
    assert!(
        catalog
            .load(&first)
            .unwrap_err()
            .to_string()
            .contains("checksum")
    );
    fs::write(&file, original).unwrap();
    assert!(catalog.load(&first).is_ok());
}
#[test]
fn directory_pages_and_anchor_are_ranked_across_the_entire_saved_scope() {
    let (_temp, root, _state) = fixture();
    let mut index = Index::new(root.clone());
    index.insert(root.clone(), Node::default());
    for i in 0..750 {
        index.insert(
            root.join(format!("d-{i:04}")),
            Node {
                allocated: i,
                logical: i,
                ..Node::default()
            },
        );
    }
    let (rows, more, offset) =
        session::directory_rows(Some(&index), &root, false, 200, 200, None).unwrap();
    assert!(more);
    assert_eq!(offset, 200);
    assert_eq!(rows[0].node.allocated, 549);
    assert_eq!(rows[199].node.allocated, 350);
    let anchor = root.join("d-0010");
    let (rows, more, offset) =
        session::directory_rows(Some(&index), &root, false, 0, 200, Some(&anchor)).unwrap();
    assert_eq!(offset, 600);
    assert!(!more);
    assert!(rows.iter().any(|r| r.path == anchor));
}
#[test]
fn comparison_pages_are_distinct_and_sort_all_changed_directories() {
    let (_temp, root, state) = fixture();
    for i in 0..240 {
        let p = root.join(format!("d-{i:04}"));
        fs::create_dir(&p).unwrap();
        fs::write(p.join("data"), vec![1; 4096]).unwrap();
    }
    let mut catalog = Snapshots::open(&state).unwrap();
    let capture = Capture::begin(&root).unwrap();
    let first = scan::full(&root, &[], &AtomicBool::new(false), None).unwrap();
    let a = catalog
        .save(&first, &capture, &AtomicBool::new(false))
        .unwrap();
    for i in 0..240 {
        fs::write(root.join(format!("d-{i:04}/data")), vec![2; 8192 + i * 512]).unwrap();
    }
    let capture = Capture::begin(&root).unwrap();
    let second = scan::full(&root, &[], &AtomicBool::new(false), None).unwrap();
    let b = catalog
        .save(&second, &capture, &AtomicBool::new(false))
        .unwrap();
    drop(catalog);
    let x = session::history(&state, &root, Some(a.id), Some(b.id), 0, 100).unwrap();
    let y = session::history(&state, &root, Some(a.id), Some(b.id), 100, 100).unwrap();
    assert!(x.more && y.more);
    assert_eq!(x.history.len(), 100);
    assert_eq!(y.history.len(), 100);
    assert!(
        x.history
            .iter()
            .all(|c| !y.history.iter().any(|d| d.path == c.path))
    );
    assert!(x.history.windows(2).all(|p|p[0].growth().unwrap().unsigned_abs()>=p[1].growth().unwrap().unsigned_abs()));
    assert_eq!(x.capacity_history.len(), 2);
    assert_eq!(x.snapshots.len(), 2);
}
#[test]
fn byte_paths_round_trip_without_loss_in_a_saved_tree() {
    use std::os::unix::ffi::OsStringExt;
    let (_temp, root, state) = fixture();
    let path = root.join(std::ffi::OsString::from_vec(vec![b'a', 0xff]));
    let mut catalog = Snapshots::open(&state).unwrap();
    let capture = Capture::begin(&root).unwrap();
    let mut index = Index::new(root.clone());
    index.full_scan = true;
    index.insert(root, Node::default());
    index.insert(
        path.clone(),
        Node {
            error_path: Some(path.join("error")),
            ..Node::default()
        },
    );
    let saved = catalog
        .save(&index, &capture, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(catalog.load(&saved).unwrap().nodes, index.nodes);
}
#[test]
fn full_traversal_does_not_follow_symlinks_or_scan_its_own_snapshot_directory() {
    let (_temp, root, _state) = fixture();
    let state = root.join("state");
    store::prepare_private(&state).unwrap();
    fs::write(state.join("not-counted"), vec![2; 65536]).unwrap();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    std::os::unix::fs::symlink(&root, root.join("cycle")).unwrap();
    let index = scan::full(
        &root,
        std::slice::from_ref(&state),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    assert!(index.root_node().unwrap().logical < 65536);
    assert_eq!(index.nodes[&state].status, 1);
    assert!(!index.nodes.contains_key(&root.join("cycle/a")));
}

#[test]
fn unreadable_previous_tree_does_not_prevent_a_new_independent_full_scan() {
    let (_temp, root, state) = fixture();
    fs::write(root.join("data"), vec![1; 8192]).unwrap();
    let session = Session::new(state.clone(), root.clone());
    session.start_scan().unwrap();
    settled(&session);
    session.close();
    let old = Snapshots::read_only(&state)
        .unwrap()
        .unwrap()
        .latest(&root)
        .unwrap()
        .unwrap();
    let path = state.join(&old.generation.name);
    fs::write(&path, b"damaged").unwrap();
    let next = Session::new(state.clone(), root);
    next.start_scan().unwrap();
    settled(&next);
    assert!(next.status().snapshot_id > Some(old.id));
    assert!(next.status().warning.is_some());
    next.close();
    assert_eq!(fs::read(path).unwrap(), b"damaged");
    assert_eq!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_failed_scan_reports_failed_instead_of_completed_when_no_snapshot_was_saved() {
    let (_temp, root, state) = fixture();
    let session = Session::new(state.clone(), root.join("missing"));
    assert_eq!(session.status().scan_state, ScanState::Ready);
    session.start_scan().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while session.status().running {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let status = session.status();
    assert_eq!(status.scan_state, ScanState::Failed);
    assert!(status.error.is_some());
    assert!(status.snapshot_id.is_none());
    session.close();
    assert!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .is_empty()
    );
}
