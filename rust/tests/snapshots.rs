use mactrim_rs::{
    model::*,
    scan,
    snapshots::{Capture, Snapshots},
    store::{Generation, Store},
};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    fs::create_dir(&root).unwrap();
    (temp, root, base.join("state"))
}
fn save(store: &mut Snapshots, root: &std::path::Path) -> (mactrim_rs::snapshots::Snapshot, Index) {
    let capture = Capture::begin(root).unwrap();
    let index = scan::full(root, &[], &AtomicBool::new(false), None).unwrap();
    let saved = store
        .save(&index, &capture, &AtomicBool::new(false))
        .unwrap();
    (saved, index)
}

#[test]
fn each_full_scan_is_distinct_and_compares_changes_without_any_notifications() {
    let (_temp, root, state) = fixture();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("stable")).unwrap();
    fs::write(root.join("a/data"), vec![1; 4096]).unwrap();
    fs::write(root.join("stable/data"), vec![2; 8192]).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (first, _) = save(&mut store, &root);
    fs::write(root.join("a/data"), vec![3; 65536]).unwrap();
    let (second, index) = save(&mut store, &root);
    let (third, _) = save(&mut store, &root);
    assert_eq!(index.reused, 0);
    assert!(index.visited >= 5);
    assert!(first.id < second.id && second.id < third.id);
    assert_eq!(store.list(Some(&root)).unwrap().len(), 3);
    let comparison = store.compare(&root, &first, &second).unwrap();
    let change = comparison
        .changes
        .iter()
        .find(|c| c.path == root.join("a"))
        .unwrap();
    assert_eq!(
        change.after.as_ref().unwrap().logical - change.before.as_ref().unwrap().logical,
        61440
    );
    assert!(change.growth().is_some());
    assert!(
        !comparison
            .changes
            .iter()
            .any(|c| c.path == root.join("stable"))
    );
    assert!(
        store
            .compare(&root, &second, &third)
            .unwrap()
            .changes
            .is_empty()
    );
    drop(store);
    let store = Snapshots::read_only(&state).unwrap().unwrap();
    assert_eq!(
        store.load(&store.get(first.id).unwrap()).unwrap().nodes[&root.join("a")].logical,
        change.before.as_ref().unwrap().logical
    );
    assert_eq!(
        store.load(&store.get(second.id).unwrap()).unwrap().nodes,
        index.nodes
    );
}

#[test]
fn complete_scans_retain_dependency_and_deep_directory_details() {
    let (_temp, root, state) = fixture();
    let deep = root
        .join("node_modules")
        .join((0..18).map(|n| format!("depth-{n}")).collect::<PathBuf>());
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("payload"), vec![1; 65536]).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (saved, index) = save(&mut store, &root);
    assert!(index.nodes.contains_key(&deep));
    assert!(index.nodes.values().all(|n| n.flags & COLLAPSED == 0));
    assert!(index.nodes[&root.join("node_modules")].logical >= 65536);
    assert_eq!(store.load(&saved).unwrap().nodes, index.nodes);
}

#[test]
fn additions_and_deletions_are_quantified_only_when_their_parent_was_measured() {
    let (_temp, root, state) = fixture();
    fs::create_dir(root.join("removed")).unwrap();
    fs::write(root.join("removed/data"), vec![1; 8192]).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (a, _) = save(&mut store, &root);
    fs::remove_dir_all(root.join("removed")).unwrap();
    fs::create_dir(root.join("added")).unwrap();
    fs::write(root.join("added/data"), vec![2; 16384]).unwrap();
    let (b, _) = save(&mut store, &root);
    let comparison = store.compare(&root, &a, &b).unwrap();
    assert!(
        comparison
            .changes
            .iter()
            .find(|c| c.path == root.join("removed"))
            .unwrap()
            .growth()
            .unwrap()
            < 0
    );
    assert!(
        comparison
            .changes
            .iter()
            .find(|c| c.path == root.join("added"))
            .unwrap()
            .growth()
            .unwrap()
            > 0
    );
    let mut before = Index::new(root.clone());
    before.insert(
        root.clone(),
        Node {
            status: 3,
            ..Node::default()
        },
    );
    let after = store.load(&b).unwrap();
    assert!(
        mactrim_rs::snapshots::differences(&before, &after, b.finished, true)
            .iter()
            .find(|c| c.path == root.join("added"))
            .unwrap()
            .growth()
            .is_none()
    );
}

#[test]
fn interrupted_or_replaced_candidates_do_not_replace_completed_scans() {
    let (_temp, root, state) = fixture();
    fs::write(root.join("data"), vec![1; 4096]).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (saved, index) = save(&mut store, &root);
    let capture = Capture::begin(&root).unwrap();
    let failure = store
        .save(&index, &capture, &AtomicBool::new(true))
        .unwrap_err();
    assert!(failure.is::<scan::Cancelled>());
    fs::rename(&root, root.with_file_name("old-root")).unwrap();
    fs::create_dir(&root).unwrap();
    assert!(
        store
            .save(&index, &capture, &AtomicBool::new(false))
            .is_err()
    );
    assert_eq!(store.list(Some(&root)).unwrap().len(), 1);
    assert_eq!(store.load(&saved).unwrap().nodes, index.nodes);
}

#[test]
fn filesystem_replacement_keeps_values_but_marks_growth_unknown() {
    let (_temp, root, state) = fixture();
    fs::write(root.join("data"), vec![1; 4096]).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (first, _) = save(&mut store, &root);
    fs::write(root.join("data"), vec![2; 32768]).unwrap();
    let (mut second, _) = save(&mut store, &root);
    second.identity.inode += 1;
    let comparison = store.compare(&root, &first, &second).unwrap();
    assert!(!comparison.same_filesystem);
    assert!(!comparison.changes.is_empty());
    assert!(comparison.changes.iter().all(|c| c.growth().is_none()));
}

#[test]
fn hardlinks_are_counted_once_with_stable_attribution_between_full_scans() {
    let (_temp, root, state) = fixture();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/shared"), vec![1; 65536]).unwrap();
    fs::hard_link(root.join("a/shared"), root.join("b/shared")).unwrap();
    let mut store = Snapshots::open(&state).unwrap();
    let (first, _) = save(&mut store, &root);
    let (second, index) = save(&mut store, &root);
    assert!(index.root_node().unwrap().logical < 131072);
    assert!(
        store
            .compare(&root, &first, &second)
            .unwrap()
            .changes
            .is_empty()
    );
    fs::write(root.join("b/shared"), vec![2; 131072]).unwrap();
    let (third, index) = save(&mut store, &root);
    assert!(index.root_node().unwrap().logical < 262144);
    assert!(
        store
            .compare(&root, &second, &third)
            .unwrap()
            .changes
            .iter()
            .find(|c| c.path == root)
            .unwrap()
            .growth()
            .unwrap()
            > 0
    );
}

#[test]
fn legacy_saved_tree_is_imported_once_and_original_files_are_preserved() {
    let (_temp, root, state) = fixture();
    fs::write(root.join("data"), vec![1; 4096]).unwrap();
    let index = scan::full(&root, &[], &AtomicBool::new(false), None).unwrap();
    let mut old = Store::open(&state).unwrap();
    let identity = Identity {
        volume_uuid: None,
        namespace_device: 1,
        namespace_inode: 2,
        namespace_uuid: "old".into(),
        device: 1,
        uuid: "old".into(),
        mount: "/".into(),
        relative: "fixture".into(),
    };
    old.bind(&root, &identity, 100).unwrap();
    let generation = Generation::write(&state, &index).unwrap();
    let work = old.claim().unwrap();
    old.commit(&generation, &work, &index).unwrap();
    drop(old);
    let store = Snapshots::open(&state).unwrap();
    let imported = store.latest(&root).unwrap().unwrap();
    assert!(imported.imported);
    assert_eq!(store.load(&imported).unwrap().nodes, index.nodes);
    assert!(state.join("service.sqlite3").is_file());
    assert!(state.join(&generation.name).is_file());
    drop(store);
    assert_eq!(
        Snapshots::open(&state)
            .unwrap()
            .list(Some(&root))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn comparisons_reject_mixed_roots_and_empty_catalogs_are_readable() {
    let (_temp, root, state) = fixture();
    let mut store = Snapshots::open(&state).unwrap();
    assert!(store.endpoints(&root, None, None).unwrap().is_none());
    let (a, _) = save(&mut store, &root);
    let other = root.with_file_name("other");
    fs::create_dir(&other).unwrap();
    let (b, _) = save(&mut store, &other);
    assert!(store.endpoints(&root, Some(a.id), Some(b.id)).is_err());
    assert!(store.endpoints(&other, None, None).unwrap().is_none());
}
