#![cfg(target_os = "macos")]
use mactrim_rs::service::{Request, request};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::{
    fs,
    io::{Read, Write},
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
struct Service(PathBuf);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = request(&self.0, &Request::Stop);
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
fn actual_terminal_preserves_selection_and_closing_client_keeps_service_alive() {
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
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env_remove("NO_COLOR");
    let mut client = Client(pair.slave.spawn_command(command).unwrap());
    drop(pair.slave);
    let _service = Service(state.clone());
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
        s.contains("Index saved; incremental tracking active") && selected(s, &root.join("a"))
    });
    writer.write_all(b"\x1b[B").unwrap();
    writer.flush().unwrap();
    wait_screen(&parser, |s| selected(s, &root.join("b")));
    let pid = request(&state, &Request::Status).unwrap().status.pid;
    fs::write(root.join("b/data"), vec![2; 131072]).unwrap();
    wait_screen(&parser, |s| {
        selected(s, &root.join("b")) && s.contains("128.0 KiB")
    });
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
    assert_eq!(request(&state, &Request::Status).unwrap().status.pid, pid);
    let mut evidence = String::new();
    for marker in [
        "Validate → exact approval",
        "Directory deltas",
        "Restore / separately approved purge",
    ] {
        writer.write_all(b"\t").unwrap();
        writer.flush().unwrap();
        let screen = wait_screen(&parser, |s| s.contains(marker));
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
    writer.write_all(b"q").unwrap();
    writer.flush().unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = client.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        request(&state, &Request::Status).unwrap().status.pid,
        pid,
        "Closing the UI must leave the same service running"
    );
    drop(writer);
    drop(pair.master);
    reading.join().unwrap();
}
