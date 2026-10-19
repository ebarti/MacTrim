use mactrim_rs::{
    model::*,
    regions::Regions,
    scan::measure,
    store::{Generation, Store},
};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

fn identity() -> Identity {
    Identity {
        volume_uuid: None,
        namespace_device: 1,
        namespace_inode: 2,
        namespace_uuid: "a".into(),
        device: 1,
        uuid: "a".into(),
        mount: "/".into(),
        relative: "tmp".into(),
    }
}
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("node_modules")).unwrap();
    fs::create_dir_all(root.join("node_modules/a/deep")).unwrap();
    fs::write(root.join("node_modules/a/deep/blob"), vec![1; 128 * 1024]).unwrap();
    (temp, root, state)
}

#[test]
fn coalescing_and_component_boundaries() {
    let mut regions: Regions = ["/a/b/c", "/a/bb", "/a/b/d"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    regions.insert("/a/b".into());
    assert_eq!(regions.paths().count(), 2);
    assert!(regions.intersects(std::path::Path::new("/a/b/c/x")));
    assert!(!regions.intersects(std::path::Path::new("/a/bc")));
}

#[test]
fn collapsed_details_keep_deep_sizes_and_tree_survives_restart() {
    let (_temp, root, state) = fixture();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let lazy = &result.nodes[&root.join("node_modules")];
    assert_eq!(lazy.flags & COLLAPSED, COLLAPSED);
    assert!(lazy.logical >= 128 * 1024);
    assert_eq!(result.nodes.len(), 2);
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let work = store.work().unwrap();
    let generation = Generation::write(&state, &result).unwrap();
    store.commit(&generation, &work, &result).unwrap();
    drop(store);
    let store = Store::open(&state).unwrap();
    assert_eq!(store.load().unwrap().unwrap().nodes, result.nodes);
    assert_eq!(store.applied().unwrap(), 100);
    assert!(store.work().unwrap().paths.is_empty());
}

#[test]
fn new_events_during_scan_cannot_be_acknowledged_by_an_old_candidate() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let ticket = store.work().unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    store
        .ingest(140, [root.join("node_modules")], "Changed during scan")
        .unwrap();
    let generation = Generation::write(&state, &result).unwrap();
    store.commit(&generation, &ticket, &result).unwrap();
    assert_eq!(store.applied().unwrap(), 100);
    assert_eq!(store.cursor().unwrap(), 140);
    assert!(!store.work().unwrap().paths.is_empty());
}

#[test]
fn crash_before_index_commit_retains_dirty_work_and_previous_tree() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    store
        .ingest(103, [root.join("node_modules")], "Simulated delivery gap")
        .unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let orphan = Generation::write(&state, &result).unwrap();
    drop(store); // Crash after generation fsync, before checkpoint commit.
    let store = Store::open(&state).unwrap();
    assert_eq!(store.cursor().unwrap(), 103);
    assert_eq!(store.applied().unwrap(), 0);
    assert!(!store.work().unwrap().paths.is_empty());
    assert!(store.load().unwrap().is_none());
    store.reap_orphans().unwrap();
    assert!(!state.join(orphan.name).exists());
}

#[test]
fn duplicate_writer_and_corruption_are_refused() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    assert!(Store::open(&state).is_err());
    store.bind(&root, &identity(), 20).unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &result).unwrap();
    store
        .commit(&generation, &store.work().unwrap(), &result)
        .unwrap();
    fs::write(state.join(&generation.name), b"broken").unwrap();
    assert!(store.load().is_err());
    assert!(state.join(generation.name).exists());
}

#[test]
fn changed_history_holds_measurement_without_queuing_a_root_scan() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &result).unwrap();
    store
        .commit(&generation, &store.work().unwrap(), &result)
        .unwrap();
    let mut changed = identity();
    changed.uuid = "replacement".into();
    assert!(store.bind(&root, &changed, 30).unwrap());
    assert!(store.work().unwrap().paths.is_empty());
    assert_eq!(store.applied().unwrap(), 0);
    assert!(store.verification().unwrap().is_some());
    assert!(
        store
            .get::<Option<String>>("finish_then_idle")
            .unwrap()
            .flatten()
            .is_some()
    );
    assert!(store.load().unwrap().is_some());
}

#[test]
fn changed_file_with_unchanged_directory_timestamp_is_remeasured() {
    let (_temp, root, _state) = fixture();
    fs::create_dir(root.join("unchanged")).unwrap();
    fs::write(root.join("unchanged/other"), vec![0; 4096]).unwrap();
    let cancel = AtomicBool::new(false);
    let first = measure(&root, &[], None, &Regions::default(), &cancel, None).unwrap();
    fs::write(root.join("node_modules/a/deep/blob"), vec![0; 512 * 1024]).unwrap();
    let dirty = [root.join("node_modules/a/deep")].into_iter().collect();
    let second = measure(&root, &[], Some(&first), &dirty, &cancel, None).unwrap();
    assert!(second.reused > 0);
    assert_eq!(
        second.nodes[&root.join("node_modules")].logical
            - first.nodes[&root.join("node_modules")].logical,
        384 * 1024
    );
}

#[test]
fn hardlinks_are_counted_once_and_symlinks_are_not_followed() {
    let (_temp, root, _state) = fixture();
    fs::hard_link(
        root.join("node_modules/a/deep/blob"),
        root.join("same-file"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&root, root.join("cycle")).unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    assert!(result.root_node().unwrap().logical < 256 * 1024);
    assert!(!result.nodes.contains_key(&root.join("cycle")));
    assert!(result.nodes.values().any(|n| n.flags & LINKED != 0));
}

#[test]
fn cancellation_never_returns_a_candidate_to_commit() {
    let (_temp, root, _state) = fixture();
    let failure = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(true),
        None,
    )
    .expect_err("An interrupted scan returned a candidate");
    assert!(
        failure.is::<mactrim_rs::scan::Cancelled>(),
        "Cancellation lost its type: {failure:#}"
    );
}

#[test]
fn edit_during_initial_baseline_does_not_force_another_root_scan() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let work = store.claim().unwrap();
    let result = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    store
        .ingest(140, [root.join("node_modules/a/deep")], "New edit")
        .unwrap();
    let generation = Generation::write(&state, &result).unwrap();
    store.commit(&generation, &work, &result).unwrap();
    assert_eq!(
        store.work().unwrap().paths,
        vec![root.join("node_modules/a/deep")]
    );
    assert_eq!(store.applied().unwrap(), 100);
}

#[test]
fn claimed_work_survives_process_restart() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let work = store.claim().unwrap();
    drop(store);
    let store = Store::open(&state).unwrap();
    assert_eq!(store.work().unwrap().paths, work.paths);
}

#[test]
fn broad_uncertainty_does_not_absorb_precise_pending_paths() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let baseline = measure(
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
    store
        .ingest(
            110,
            [root.join("a/b/c"), root.join("a/bb")],
            "Precise changes",
        )
        .unwrap();
    store
        .ingest(120, [root.clone()], "Broad filesystem notification")
        .unwrap();
    store
        .ingest(130, [root.join("a/b")], "Directory changed")
        .unwrap();
    assert_eq!(
        store.work().unwrap().paths,
        vec![root.join("a/b"), root.join("a/bb")]
    );
    assert!(store.verification().unwrap().is_some());
    assert!(!store.claim().unwrap().full);
    store
        .defer_active("Shared files require broader verification")
        .unwrap();
    assert_eq!(
        store.work().unwrap().paths,
        vec![root.join("a/b"), root.join("a/bb")]
    );
    assert_eq!(
        store.generation().unwrap().unwrap().digest,
        generation.digest
    );
}

#[test]
fn large_pending_queue_keeps_precise_scopes_instead_of_collapsing_to_root() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    store.claim().unwrap();
    // More than the old one-MiB intake limit. Paths need not exist yet: a
    // deletion notification is also durable work.
    let suffix = format!("{}/{}", "x".repeat(240), "y".repeat(240));
    let paths: Vec<_> = (0..2200)
        .map(|n| root.join(format!("scope-{n:04}/{suffix}")))
        .collect();
    store.ingest(200, paths.clone(), "Large batch").unwrap();
    // The active baseline still exists; finish it to inspect only the intake.
    let baseline = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &baseline).unwrap();
    let active = store
        .get::<Option<mactrim_rs::store::Work>>("active")
        .unwrap()
        .flatten()
        .unwrap();
    store.commit(&generation, &active, &baseline).unwrap();
    assert_eq!(store.pending_count().unwrap(), paths.len());
    assert_eq!(store.work().unwrap().paths, paths);
}

#[test]
fn incremental_worker_refuses_hidden_full_hardlink_fallback() {
    let (_temp, root, _state) = fixture();
    fs::hard_link(
        root.join("node_modules/a/deep/blob"),
        root.join("same-file"),
    )
    .unwrap();
    let cancel = AtomicBool::new(false);
    let baseline = measure(&root, &[], None, &Regions::default(), &cancel, None).unwrap();
    let failure = mactrim_rs::scan::measure_with_options(
        &root,
        &[],
        Some(&baseline),
        &[root.join("node_modules")].into_iter().collect(),
        &cancel,
        None,
        mactrim_rs::scan::Options {
            budget: None,
            allow_full: false,
        },
    )
    .unwrap_err();
    assert!(
        failure.is::<mactrim_rs::scan::NeedsFullReconciliation>(),
        "{failure:#}"
    );
    let unchanged = mactrim_rs::scan::measure_with_options(
        &root,
        &[],
        Some(&baseline),
        &Regions::default(),
        &cancel,
        None,
        mactrim_rs::scan::Options {
            budget: None,
            allow_full: false,
        },
    )
    .unwrap();
    assert_eq!(baseline.root_node().unwrap().entries, unchanged.reused);
    assert_eq!(unchanged.visited, 0);
}

#[test]
fn cancelled_checkpoint_never_leaves_a_published_partial_tree() {
    let (_temp, root, state) = fixture();
    let baseline = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let _store = Store::open(&state).unwrap();
    let before: std::collections::BTreeSet<_> = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let failure = Generation::update_controlled(
        &state,
        &baseline,
        None,
        Some(&mactrim_rs::budget::Budget::new(100)),
        &AtomicBool::new(true),
    )
    .unwrap_err();
    assert!(failure.is::<mactrim_rs::scan::Cancelled>());
    let after: std::collections::BTreeSet<_> = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn history_change_during_first_baseline_does_not_queue_a_second_baseline() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let active = store.claim().unwrap();
    let mut changed = identity();
    changed.uuid = "replacement".into();
    store.bind(&root, &changed, 30).unwrap();
    let measured = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &measured).unwrap();
    store.commit(&generation, &active, &measured).unwrap();
    assert!(store.work().unwrap().paths.is_empty());
    assert_eq!(store.applied().unwrap(), 0);
    assert!(store.verification().unwrap().is_some());
    assert_eq!(store.load().unwrap().unwrap().nodes, measured.nodes);
}

#[test]
fn upgrade_defers_old_automatic_root_work_without_losing_precise_changes() {
    let (_temp, root, state) = fixture();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let work = store.claim().unwrap();
    let baseline = measure(
        &root,
        &[],
        None,
        &Regions::default(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap();
    let generation = Generation::write(&state, &baseline).unwrap();
    store.commit(&generation, &work, &baseline).unwrap();
    let mut legacy = serde_json::to_value(work).unwrap();
    let object = legacy.as_object_mut().unwrap();
    object.remove("full");
    object.remove("verification_revision");
    object.insert("reason".into(), "Filesystem changes".into());
    // Reproduce a ticket written by the previous installed version.
    let db = rusqlite::Connection::open(state.join("service.sqlite3")).unwrap();
    db.execute(
        "INSERT OR REPLACE INTO meta VALUES('active', ?)",
        [serde_json::to_string(&legacy).unwrap()],
    )
    .unwrap();
    drop(db);
    store
        .ingest(110, [root.join("precise-change")], "New change")
        .unwrap();
    store.defer_legacy_root_work().unwrap();
    assert_eq!(
        store.work().unwrap().paths,
        vec![root.join("precise-change")]
    );
    assert!(
        store
            .get::<Option<mactrim_rs::store::Work>>("active")
            .unwrap()
            .flatten()
            .is_none()
    );
    assert!(
        store
            .get::<Option<String>>("finish_then_idle")
            .unwrap()
            .flatten()
            .is_some()
    );
    assert_eq!(
        store.generation().unwrap().unwrap().digest,
        generation.digest
    );
}
