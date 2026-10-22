use mactrim_rs::{
    model::*,
    regions::Regions,
    scan::measure,
    store::{Generation, Store},
};
use std::{fs, path::Path, sync::atomic::AtomicBool};
fn scan(root: &Path, old: Option<&Index>, changed: &Path) -> Index {
    measure(
        root,
        &[],
        old,
        &[changed.to_owned()].into_iter().collect::<Regions>(),
        &AtomicBool::new(false),
        None,
    )
    .unwrap()
}
fn identity() -> Identity {
    Identity {
        volume_uuid: None,
        namespace_device: 1,
        namespace_inode: 2,
        namespace_uuid: "fixture".into(),
        device: 1,
        uuid: "fixture".into(),
        mount: "/".into(),
        relative: "fixture".into(),
    }
}
fn equivalent(a: &Index, b: &Index) {
    assert_eq!(a.nodes.len(), b.nodes.len());
    for (path, node) in &a.nodes {
        assert_eq!(node, b.nodes.get(path).unwrap(), "{}", path.display());
    }
}
#[test]
fn scoped_replacement_and_compressed_deltas_survive_restart_and_compaction() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir(&root).unwrap();
    for n in 0..80 {
        let d = root.join(format!("{n:03}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(d.join("deep")).unwrap();
        fs::write(d.join("deep/data"), vec![n as u8; 4096]).unwrap();
    }
    let selected = fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("deep");
    let first = scan(&root, None, &root);
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 100).unwrap();
    let base = Generation::write(&state, &first).unwrap();
    store.commit(&base, &store.work().unwrap(), &first).unwrap();
    let original = first.nodes.clone();
    fs::write(selected.join("data"), vec![7; 32768]).unwrap();
    let next = scan(&root, Some(&first), &selected.join("data"));
    assert!(!next.full_scan);
    assert_eq!(
        next.visited, 2,
        "Only the invalidated directory and its file should be visited"
    );
    assert_eq!(first.nodes, original);
    equivalent(&next, &scan(&root, None, &root));
    store
        .ingest(110, [selected.clone()], "fixture edit")
        .unwrap();
    let work = store.claim().unwrap();
    let delta = Generation::update(&state, &next, Some((&base, &first))).unwrap();
    assert_eq!(
        delta.patches, 1,
        "The small change should produce a delta, not replace the baseline"
    );
    drop(store); // A candidate that was never committed must not advance the saved tree.
    let mut store = Store::open(&state).unwrap();
    equivalent(&store.load().unwrap().unwrap(), &first);
    store.commit(&delta, &work, &next).unwrap();
    drop(store);
    let mut store = Store::open(&state).unwrap();
    equivalent(&store.load().unwrap().unwrap(), &next);
    let mut previous = next;
    let mut generation = store.generation().unwrap().unwrap();
    let mut compacted = false;
    for n in 0..40 {
        fs::write(selected.join("data"), vec![n; 65536 + n as usize]).unwrap();
        let current = scan(&root, Some(&previous), &selected);
        store
            .ingest(120 + n as u64, [selected.clone()], "fixture edit")
            .unwrap();
        let save = Generation::update(&state, &current, Some((&generation, &previous))).unwrap();
        compacted |= save.name != generation.name;
        let work = store.claim().unwrap();
        store.commit(&save, &work, &current).unwrap();
        generation = save;
        previous = current;
        if compacted {
            break;
        }
    }
    assert!(
        compacted,
        "Delta storage is compacted by its size relative to the checkpoint"
    );
    equivalent(&store.load().unwrap().unwrap(), &previous);
    assert_eq!(previous.nodes.len(), 161);
}
#[test]
fn deep_collapsed_sizes_and_deleted_or_new_directories_match_a_fresh_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let mut deep = root.to_owned();
    for _ in 0..12 {
        deep.push("level");
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("data"), vec![1; 4096]).unwrap();
    fs::create_dir(root.join("other")).unwrap();
    let first = scan(root, None, root);
    fs::write(deep.join("data"), vec![1; 65536]).unwrap();
    let next = scan(root, Some(&first), &deep.join("data"));
    equivalent(&next, &scan(root, None, root));
    assert_eq!(first.nodes.len(), next.nodes.len());
    fs::remove_dir(root.join("other")).unwrap();
    fs::create_dir(root.join("new")).unwrap();
    let next = scan(root, Some(&next), &root.join("other"));
    equivalent(&next, &scan(root, None, root));
}
#[test]
fn a_new_cross_scope_hardlink_forces_consistent_global_accounting() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/file"), vec![1; 8192]).unwrap();
    let first = scan(root, None, root);
    fs::hard_link(root.join("a/file"), root.join("b/link")).unwrap();
    let next = scan(root, Some(&first), &root.join("b"));
    assert!(next.full_scan);
    equivalent(&next, &scan(root, None, root));
}

#[test]
fn non_utf8_directory_names_survive_durable_work_tree_and_ipc() {
    use mactrim_rs::service::{Request, Row};
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir(&root).unwrap();
    let path = root.join(std::ffi::OsString::from_vec(vec![b'a', 0xff]));
    // APFS rejects malformed UTF-8 filenames. Exercise the portable record
    // codec with the same byte path without claiming APFS created that name.
    let mut index = Index::new(root.clone());
    index.insert(root.clone(), Node::default());
    index.insert(
        path.clone(),
        Node {
            error_path: Some(path.join("unreadable")),
            ..Node::default()
        },
    );
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &identity(), 1).unwrap();
    store.ingest(2, [path.clone()], "non-UTF8 edit").unwrap();
    let work = store.claim().unwrap();
    let encoded = serde_json::to_vec(&work).unwrap();
    let decoded: mactrim_rs::store::Work = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.paths, work.paths);
    let generation = Generation::write(&state, &index).unwrap();
    store.commit(&generation, &work, &index).unwrap();
    equivalent(&store.load().unwrap().unwrap(), &index);
    let request = Request::List {
        path: path.clone(),
        offset: 0,
        limit: 10,
        logical: false,
        anchor: None,
    };
    let request: Request = serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(matches!(request,Request::List{path:p,..} if p==path));
    let row = Row {
        path: path.clone(),
        node: index.nodes[&path].clone(),
        directory: true,
    };
    let row: Row = serde_json::from_slice(&serde_json::to_vec(&row).unwrap()).unwrap();
    assert_eq!(row.path, path);
}
