use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct Output {
    pub status: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
pub fn command(program: &str, args: &[&std::ffi::OsStr]) -> Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let read = |input: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut b = Vec::new();
            input
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut b)
                .map(|_| b)
        })
    };
    let stdout = read(Box::new(out));
    let stderr = read(Box::new(err));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(20) {
            child.kill()?;
            let _ = child.wait();
            anyhow::bail!("Read-only probe timed out: {program}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("Probe reader failed"))??;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("Probe reader failed"))??;
    ensure!(
        stdout.len() <= 64 * 1024 * 1024 && stderr.len() <= 64 * 1024 * 1024,
        "Probe output incomplete"
    );
    Ok(Output {
        status: status.success(),
        stdout,
        stderr,
    })
}
#[derive(Clone, Debug, Default)]
pub struct Activity {
    pub complete: bool,
    pub paths: Vec<(u32, PathBuf)>,
    pub commands: BTreeMap<u32, String>,
    pub issues: Vec<String>,
}
impl Activity {
    pub fn blockers(&self, scope: &Path) -> Vec<String> {
        let mut b = if self.complete {
            vec![]
        } else {
            self.issues.clone()
        };
        for (pid, path) in &self.paths {
            if path.starts_with(scope) {
                b.push(format!(
                    "PID {pid} has an open path or cwd in {}",
                    path.display()
                ));
            }
        }
        for (pid, command) in &self.commands {
            if *pid != std::process::id() && command.contains(scope.to_string_lossy().as_ref()) {
                b.push(format!("PID {pid} command references this scope"));
            }
        }
        b.sort();
        b.dedup();
        b
    }
}
fn pids() -> Result<BTreeMap<u32, String>> {
    let uid = unsafe { libc::geteuid() }.to_string();
    let out = command(
        "/bin/ps",
        &[
            "-U".as_ref(),
            uid.as_ref(),
            "-ww".as_ref(),
            "-o".as_ref(),
            "pid=,uid=,stat=,command=".as_ref(),
        ],
    )?;
    ensure!(
        out.status && out.stderr.is_empty(),
        "Process inventory incomplete"
    );
    let mut pids = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() >= 4, "Malformed process inventory");
        let pid = fields[0].parse::<u32>()?;
        if fields[1] == uid && !fields[2].contains('Z') && fields.get(3) != Some(&"/bin/ps") {
            pids.insert(pid, fields[3..].join(" "));
        }
    }
    Ok(pids)
}
pub trait ActivityProvider {
    fn snapshot(&self) -> Result<Activity>;
}
#[derive(Default)]
pub struct NativeActivity;
impl ActivityProvider for NativeActivity {
    fn snapshot(&self) -> Result<Activity> {
        let mut last = Activity::default();
        for _ in 0..3 {
            let before = pids()?;
            let uid = unsafe { libc::geteuid() }.to_string();
            let output = command(
                "/usr/sbin/lsof",
                &[
                    "-nP".as_ref(),
                    "-u".as_ref(),
                    uid.as_ref(),
                    "-F0pcftn".as_ref(),
                ],
            )?;
            let after = pids()?;
            let mut result = Activity {
                commands: after.clone(),
                ..Activity::default()
            };
            if !output.status || !output.stderr.is_empty() || !output.stdout.ends_with(b"\n") {
                result
                    .issues
                    .push("lsof access or output incomplete; cleanup is blocked".into());
            }
            let mut seen = BTreeSet::new();
            let mut cwd = BTreeSet::new();
            let mut pid = 0;
            let mut descriptor = String::new();
            let mut kind = String::new();
            let mut named = true;
            for field in output
                .stdout
                .split(|c| *c == 0)
                .map(|f| f.strip_prefix(b"\n").unwrap_or(f))
                .filter(|f| !f.is_empty())
            {
                let text = String::from_utf8_lossy(&field[1..]);
                match field[0] {
                    b'p' => {
                        if !named && ["REG", "DIR", ""].contains(&kind.as_str()) {
                            result.issues.push("lsof omitted a file name".into());
                        }
                        pid = text.parse().context("Malformed lsof PID")?;
                        seen.insert(pid);
                        descriptor.clear();
                        kind.clear();
                        named = true;
                    }
                    b'f' => {
                        if !named && ["REG", "DIR", ""].contains(&kind.as_str()) {
                            result.issues.push("lsof omitted a file name".into());
                        }
                        descriptor = text.into_owned();
                        kind.clear();
                        named = false;
                    }
                    b't' => kind = text.into_owned(),
                    b'c' => (),
                    b'n' => {
                        named = true;
                        if field[1..].starts_with(b"/") {
                            let raw = field[1..]
                                .strip_suffix(b" (deleted)")
                                .unwrap_or(&field[1..]);
                            let path = PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec()));
                            let path = std::fs::canonicalize(&path).unwrap_or(path);
                            result.paths.push((pid, path));
                            if descriptor == "cwd" {
                                cwd.insert(pid);
                            }
                        } else if ["REG", "DIR", ""].contains(&kind.as_str()) {
                            result.issues.push(format!("PID {pid}, fd {descriptor} ({kind}): {text}; path is unknown, so active-use coverage is incomplete"));
                        }
                    }
                    _ => result.issues.push("Unexpected lsof field".into()),
                }
            }
            for (pid, argv) in &after {
                if !seen.contains(pid) || !cwd.contains(pid) || before.get(pid) != Some(argv) {
                    result.issues.push(format!(
                        "Current-user process coverage uncertain for PID {pid}"
                    ));
                }
            }
            result.complete = result.issues.is_empty();
            if result.complete {
                return Ok(result);
            }
            last = result;
        }
        Ok(last)
    }
}
