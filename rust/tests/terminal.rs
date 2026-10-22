#![cfg(target_os = "macos")]
use mactrim_rs::snapshots::Snapshots;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
fn binary() -> PathBuf {
    std::env::var_os("MACTRIM_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mactrim").into())
}
struct RestoreDirectoryMode(PathBuf);
impl Drop for RestoreDirectoryMode {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}
struct Client(Box<dyn portable_pty::Child + Send + Sync>);
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait_screen(parser: &Arc<Mutex<vt100::Parser>>, condition: impl Fn(&str) -> bool) -> String {
    let start = Instant::now();
    loop {
        let content = parser.lock().unwrap().screen().contents();
        if condition(&content) {
            return content;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "Terminal did not reach expected state:\n{content}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
fn selected(content: &str, path: &Path) -> bool {
    content
        .lines()
        .any(|line| line.starts_with(&format!("{} ·", path.display())))
}
#[test]
fn actual_terminal_full_scans_save_compare_and_quit_without_background_work() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("files");
    let state = base.join("state");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a/data"), vec![1; 8192]).unwrap();
    fs::write(root.join("b/data"), vec![1; 4096]).unwrap();
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 45,
            cols: 140,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(binary());
    command.arg("--state");
    command.arg(&state);
    command.arg("storage");
    command.arg(&root);
    command.env("HOME", &base);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env_remove("NO_COLOR");
    let mut client = Client(pair.slave.spawn_command(command).unwrap());
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let parser = Arc::new(Mutex::new(vt100::Parser::new(45, 140, 0)));
    let incoming = parser.clone();
    let reading = thread::spawn(move || {
        let mut buf = [0; 16384];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            incoming.lock().unwrap().process(&buf[..n]);
        }
    });
    wait_screen(&parser, |s| {
        s.contains("SCAN COMPLETE · SAVED #1") && selected(s, &root.join("a"))
    });
    let initial = parser.lock().unwrap().screen().contents();
    assert!(initial.contains("Coverage: MEASURED"));
    assert!(!initial.contains("Starting a full scan"));
    assert!(!initial.contains("lazy details"));
    writer.write_all(b"\x1b[B").unwrap();
    writer.flush().unwrap();
    wait_screen(&parser, |s| selected(s, &root.join("b")));
    fs::write(root.join("b/data"), vec![2; 131072]).unwrap();
    thread::sleep(Duration::from_millis(750));
    assert_eq!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .len(),
        1,
        "An edit must not start an update"
    );
    let denied = root.join("unreadable");
    fs::create_dir(&denied).unwrap();
    let _mode = RestoreDirectoryMode(denied.clone());
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    writer.write_all(b"r").unwrap();
    writer.flush().unwrap();
    wait_screen(&parser, |s| {
        selected(s, &root.join("b"))
            && s.contains("SCAN COMPLETE · SAVED #2")
            && s.contains("128.0 KiB")
    });
    let completed = wait_screen(&parser, |s| {
        s.contains("SCAN COMPLETE · SAVED #2") && s.contains("Coverage: PARTIAL")
    });
    assert!(completed.contains("Saved on disk; safe to quit"));
    assert!(!completed.contains("Full scan started"));
    assert!(!completed.contains("Starting a full scan"));
    thread::sleep(Duration::from_millis(750));
    assert!(
        selected(&parser.lock().unwrap().screen().contents(), &root.join("b")),
        "Polling must not toggle selection after reordering"
    );
    writer.write_all(b"\x1b[C").unwrap();
    writer.flush().unwrap();
    wait_screen(&parser, |s| {
        s.lines()
            .any(|l| l.trim() == root.join("b").to_string_lossy())
    });
    assert_eq!(
        Snapshots::read_only(&state)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .len(),
        2,
        "Browsing must not start another scan"
    );
    writer.write_all(b"g").unwrap();
    writer.flush().unwrap();
    let mut evidence = format!("{completed}\n\n");
    for marker in [
        "Validate → exact approval",
        "Saved comparison",
        "Restore / separately approved purge",
    ] {
        writer.write_all(b"\t").unwrap();
        writer.flush().unwrap();
        let mut screen = wait_screen(&parser, |s| s.contains(marker));
        if marker == "Saved comparison" {
            let pair = |s: &str, from: u64, to: u64| {
                s.lines().any(|l| {
                    l.contains(&format!("Saved comparison #{from} "))
                        && l.contains(&format!("→ #{to} "))
                })
            };
            wait_screen(&parser, |s| {
                pair(s, 1, 2) && s.contains(&root.join("b").to_string_lossy().to_string())
            });
            writer.write_all(b"s").unwrap();
            writer.flush().unwrap();
            wait_screen(&parser, |s| {
                s.contains("Compare saved scans") && s.contains("#1") && s.contains("#2")
            });
            writer.write_all(b"2 1\r").unwrap();
            writer.flush().unwrap();
            wait_screen(&parser, |s| {
                pair(s, 2, 1) && !s.contains("Compare saved scans")
            });
            writer.write_all(b"s").unwrap();
            writer.flush().unwrap();
            wait_screen(&parser, |s| s.contains("Compare saved scans"));
            writer.write_all(b"\r").unwrap();
            writer.flush().unwrap();
            screen = wait_screen(&parser, |s| {
                pair(s, 1, 2) && !s.contains("Compare saved scans")
            });
        }
        evidence.push_str(&screen);
        evidence.push_str("\n\n");
    }
    let colored = (0..45).any(|row| {
        (0..140).any(|col| {
            parser
                .lock()
                .unwrap()
                .screen()
                .cell(row, col)
                .is_some_and(|c| matches!(c.bgcolor(), vt100::Color::Rgb(..)))
        })
    });
    assert!(colored, "The executable must render true-color UI styles");
    if let Some(dir) = std::env::var_os("MACTRIM_EVIDENCE_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(PathBuf::from(dir).join("native-terminal.txt"), evidence).unwrap();
    }
    writer.write_all(b"qY").unwrap();
    writer.flush().unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = client.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{}",
            parser.lock().unwrap().screen().contents()
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        Snapshots::open(&state).is_ok(),
        "Quitting releases the scan writer"
    );
    assert!(!state.join("service.sock").exists());
    assert!(!state.join("service.sqlite3").exists());
    drop(writer);
    drop(pair.master);
    reading.join().unwrap();
}
