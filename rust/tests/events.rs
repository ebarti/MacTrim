use mactrim_rs::{events::*, model::Identity};
use std::path::Path;
fn id() -> Identity {
    Identity {
        volume_uuid: None,
        namespace_device: 1,
        namespace_inode: 1,
        namespace_uuid: "x".into(),
        device: 1,
        uuid: "x".into(),
        mount: "/".into(),
        relative: "Users/test".into(),
    }
}
#[test]
fn skipped_event_numbers_are_not_delivery_loss() {
    let c = changes(
        Batch {
            events: vec![
                Event {
                    path: "Users/test/a".into(),
                    flags: 0,
                    id: 100,
                },
                Event {
                    path: "Users/test/b".into(),
                    flags: 0,
                    id: 999,
                },
            ],
        },
        Path::new("/Users/test"),
        &id(),
        Path::new("/state"),
        1,
    );
    assert_eq!(c.gap, 0);
    assert_eq!(c.latest, 999);
    assert_eq!(c.paths.len(), 2);
}
#[test]
fn coalescing_and_history_sentinel_do_not_mean_loss() {
    let c = changes(
        Batch {
            events: vec![
                Event {
                    path: "Users/test/a".into(),
                    flags: MUST_SCAN,
                    id: 100,
                },
                Event {
                    path: "".into(),
                    flags: HISTORY_DONE,
                    id: 101,
                },
            ],
        },
        Path::new("/Users/test"),
        &id(),
        Path::new("/state"),
        1,
    );
    assert_eq!(c.gap, 0);
    assert!(c.history_done);
    assert_eq!(c.paths, vec![Path::new("/Users/test/a")]);
}
#[test]
fn real_gap_signals_are_preserved() {
    for flag in [USER_DROPPED, KERNEL_DROPPED, WRAPPED, ROOT_CHANGED] {
        let c = changes(
            Batch {
                events: vec![Event {
                    path: "Users/test".into(),
                    flags: flag | MUST_SCAN,
                    id: 100,
                }],
            },
            Path::new("/Users/test"),
            &id(),
            Path::new("/state"),
            1,
        );
        assert_eq!(c.gap, flag);
    }
}
#[test]
fn service_writes_are_excluded_but_cursor_is_covered() {
    let c = changes(
        Batch {
            events: vec![Event {
                path: "Users/test/state".into(),
                flags: 0,
                id: 100,
            }],
        },
        Path::new("/Users/test"),
        &id(),
        Path::new("/Users/test/state"),
        1,
    );
    assert_eq!(c.latest, 100);
    assert!(c.paths.is_empty());
}

#[test]
fn file_events_dirty_the_parent_without_widening_to_the_grandparent() {
    let c = changes(
        Batch {
            events: vec![Event {
                path: "Users/test/project/file.txt".into(),
                flags: ITEM_IS_FILE | 0x1000,
                id: 123,
            }],
        },
        Path::new("/Users/test"),
        &id(),
        Path::new("/state"),
        100,
    );
    assert_eq!(c.paths, vec![Path::new("/Users/test/project")]);
    assert_eq!(c.latest, 123);
    assert_eq!(c.gap, 0);
}

#[test]
fn filesystem_identity_is_independent_of_journal_identity() {
    let mut old = id();
    old.volume_uuid = Some("volume".into());
    let mut new = old.clone();
    new.uuid = "new-history".into();
    assert!(old.same_filesystem(&new));
    new.volume_uuid = Some("replacement-volume".into());
    assert!(!old.same_filesystem(&new));
    // Legacy checkpoints had only the device and inode identity.
    old.volume_uuid = None;
    new.volume_uuid = Some("volume".into());
    new.namespace_uuid = "native-volume-uuid".into();
    assert!(old.same_filesystem(&new));
}

#[test]
fn broad_root_notification_does_not_swallow_precise_file_changes() {
    let c = changes(
        Batch {
            events: vec![
                Event {
                    path: "Users/test".into(),
                    flags: MUST_SCAN,
                    id: 120,
                },
                Event {
                    path: "Users/test/project/data".into(),
                    flags: ITEM_IS_FILE | 0x1000,
                    id: 121,
                },
            ],
        },
        Path::new("/Users/test"),
        &id(),
        Path::new("/state"),
        100,
    );
    assert_eq!(
        c.paths,
        vec![Path::new("/Users/test"), Path::new("/Users/test/project")]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn firmlink_device_scope_uses_volume_relative_paths() {
    let home = std::env::var_os("HOME").unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    let identity = identity(&home).unwrap();
    assert_eq!(identity.mount.join(&identity.relative), home);
    assert_ne!(identity.mount, Path::new("/Users"));
    assert!(identity.volume_uuid.is_some());
    assert_eq!(identity, mactrim_rs::events::identity(&home).unwrap());
}
