use mactrim_rs::{
    model::*,
    regions::Regions,
    scan::measure,
    store::{Generation, Store},
};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

fn identity() -> Identity {
    Identity {
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
fn changed_history_invalidates_root_and_does_not_erase_saved_observation() {
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
    assert_eq!(store.work().unwrap().paths, vec![root]);
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
    assert!(
        measure(
            &root,
            &[],
            None,
            &Regions::default(),
            &AtomicBool::new(true),
            None
        )
        .is_err()
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
