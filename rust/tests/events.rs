use mactrim_rs::{events::*, model::Identity};
use std::path::Path;
fn id() -> Identity {
    Identity {
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

#[cfg(target_os = "macos")]
#[test]
fn firmlink_device_scope_uses_volume_relative_paths() {
    let home = std::env::var_os("HOME").unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    let identity = identity(&home).unwrap();
    assert_eq!(identity.mount.join(&identity.relative), home);
    assert_ne!(identity.mount, Path::new("/Users"));
}
