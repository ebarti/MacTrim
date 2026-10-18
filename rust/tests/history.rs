use mactrim_rs::{
    history,
    model::*,
    regions::Regions,
    scan::measure,
    store::{Generation, Store},
};
use std::{fs, sync::atomic::AtomicBool};
fn id() -> Identity {
    Identity {
        namespace_device: 1,
        namespace_inode: 2,
        namespace_uuid: "x".into(),
        device: 1,
        uuid: "x".into(),
        mount: "/".into(),
        relative: "".into(),
    }
}
#[test]
fn directory_history_keeps_first_and_latest_hourly_values() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("data"), vec![0; 4096]).unwrap();
    let cancel = AtomicBool::new(false);
    let first = measure(&root, &[], None, &Regions::default(), &cancel, None).unwrap();
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &id(), 100).unwrap();
    let work = store.claim().unwrap();
    let gen1 = Generation::write(&state, &first).unwrap();
    store.commit(&gen1, &work, &first).unwrap();
    fs::write(root.join("data"), vec![0; 16384]).unwrap();
    let second = measure(&root, &[], None, &Regions::default(), &cancel, None).unwrap();
    let d = history::changes(Some(&first), &second, gen1.created);
    store.ingest(105, [root.clone()], "edit").unwrap();
    let work = store.claim().unwrap();
    let gen2 = Generation::write(&state, &second).unwrap();
    store.commit_changes(&gen2, &work, &second, &d).unwrap();
    fs::write(root.join("data"), vec![0; 32768]).unwrap();
    let third = measure(&root, &[], None, &Regions::default(), &cancel, None).unwrap();
    let d = history::changes(Some(&second), &third, gen1.created);
    store.ingest(110, [root.clone()], "edit").unwrap();
    let work = store.claim().unwrap();
    let gen3 = Generation::write(&state, &third).unwrap();
    store.commit_changes(&gen3, &work, &third, &d).unwrap();
    let history = store.history(&root, 0).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].before.as_ref().unwrap().logical,
        first.root_node().unwrap().logical
    );
    assert_eq!(
        history[0].after.as_ref().unwrap().logical,
        third.root_node().unwrap().logical
    );
}
#[test]
fn baseline_is_not_duplicated_and_partial_growth_is_unknown() {
    let mut index = Index::new("/fixture".into());
    index.insert(
        "/fixture".into(),
        Node {
            logical: 4096,
            allocated: 4096,
            ..Node::default()
        },
    );
    assert!(history::changes(None, &index, 1).is_empty());
    let mut after = index.clone();
    after.nodes.get_mut(&after.root).unwrap().status = 2;
    let d = history::changes(Some(&index), &after, 2);
    assert_eq!(d.len(), 1);
    assert!(d[0].growth().is_none());
}

#[test]
fn denied_parent_is_not_evidence_that_descendants_were_deleted() {
    let mut before = Index::new("/fixture".into());
    before.insert("/fixture".into(), Node::default());
    before.insert(
        "/fixture/child".into(),
        Node {
            allocated: 4096,
            ..Node::default()
        },
    );
    let mut after = Index::new("/fixture".into());
    after.insert(
        "/fixture".into(),
        Node {
            status: 3,
            ..Node::default()
        },
    );
    let changes = history::changes(Some(&before), &after, 1);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, before.root);
    assert!(changes[0].growth().is_none());
}

#[test]
fn history_pages_rank_the_whole_scope_and_match_the_saved_deltas() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir(&root).unwrap();
    let mut before = Index::new(root.clone());
    before.insert(root.clone(), Node::default());
    for n in 0..613 {
        before.insert(
            root.join(format!("dir-{n:03}")),
            Node {
                allocated: 4096,
                logical: 4096,
                ..Node::default()
            },
        );
    }
    let mut store = Store::open(&state).unwrap();
    store.bind(&root, &id(), 100).unwrap();
    let generation = Generation::write(&state, &before).unwrap();
    let work = store.claim().unwrap();
    store.commit(&generation, &work, &before).unwrap();
    let mut after = before.clone();
    for n in 0..613 {
        after
            .nodes
            .get_mut(&root.join(format!("dir-{n:03}")))
            .unwrap()
            .allocated += n;
    }
    let generation = Generation::write(&state, &after).unwrap();
    let changes = history::changes(Some(&before), &after, generation.created);
    store.ingest(101, [root.clone()], "edits").unwrap();
    let work = store.claim().unwrap();
    store
        .commit_changes(&generation, &work, &after, &changes)
        .unwrap();
    let expected = store.history(&root, 0).unwrap();
    let mut observed = Vec::new();
    let mut offset = 0;
    loop {
        let (page, more) = Store::history_page(&state, &root, 0, offset, 100).unwrap();
        observed.extend(page);
        if !more {
            break;
        }
        offset += 100;
    }
    assert_eq!(
        observed.iter().map(|c| &c.path).collect::<Vec<_>>(),
        expected.iter().map(|c| &c.path).collect::<Vec<_>>()
    );
    assert_eq!(observed[0].path, root.join("dir-612"));
    let (page, more) = Store::history_page(&state, &root.join("dir-06"), 0, 0, 100).unwrap();
    assert!(page.is_empty());
    assert!(!more);
}
