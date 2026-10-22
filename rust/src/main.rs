use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use mactrim_rs::{
    model::Progress,
    regions::Regions,
    scan,
    service::{self, Request},
    store,
};
use std::{
    fs,
    io::{self, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "mactrim",
    version,
    about = "Rust storage explorer and persistent change tracker"
)]
struct Args {
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
enum Commands {
    BuildInfo,
    Doctor {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Scan {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    #[command(alias = "tui")]
    Storage {
        #[arg(default_value = "/")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Status,
    History {
        #[arg(default_value = "/")]
        path: PathBuf,
        #[arg(long, default_value = "60")]
        days: u64,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long, default_value = "200")]
        limit: usize,
    },
    Refresh {
        #[arg(long)]
        full: bool,
    },
    List {
        path: PathBuf,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long, default_value = "200")]
        limit: usize,
        #[arg(long)]
        logical: bool,
    },
    Service {
        #[command(subcommand)]
        action: Service,
    },
    Cleanup {
        #[command(subcommand)]
        action: Cleanup,
    },
}
#[derive(Subcommand)]
enum Cleanup {
    Scan {
        #[arg(long = "root")]
        roots: Vec<PathBuf>,
    },
    Validate {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value = "30")]
        older_than_days: u64,
    },
    Quarantine {
        id: String,
        #[arg(long)]
        approve: Option<String>,
    },
    Restore {
        id: String,
    },
    Purge {
        id: String,
        #[arg(long)]
        approve: Option<String>,
    },
    Journals,
    Recover,
    Activity,
}
#[derive(Subcommand)]
enum Service {
    Retention {
        #[arg(long)]
        days: u64,
    },
    Install {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Uninstall,
    Plist {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Run {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Start {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Stop,
    Pause,
}

fn default_state() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("HOME unavailable; supply --state")?)
            .join("Library/Application Support/MacTrimRust"),
    )
}
fn signal_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, flag.clone())?;
    }
    Ok(flag)
}
pub fn start(state: &Path, root: &Path) -> Result<()> {
    if let Ok(reply) = service::request(state, &Request::Status) {
        ensure!(
            reply.status.root == fs::canonicalize(root)?,
            "Running service belongs to another root; use a separate --state directory"
        );
        return Ok(());
    }
    store::prepare_private(state)?;
    let managed = mactrim_rs::agent::start_managed(state)?;
    let log = store::private_file(&state.join("service.log"), true)?;
    // Append inherited child output without reopening an unchecked pathname.
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::fcntl(log.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) } >= 0,
        "Cannot open service log for append"
    );
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--state"])
        .arg(state)
        .args(["service", "run"])
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .current_dir("/");
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = if managed {
        None
    } else {
        Some(command.spawn()?)
    };
    let started = Instant::now();
    loop {
        if service::request(state, &Request::Status).is_ok() {
            return Ok(());
        }
        if let Some(code) = child.as_mut().map(|c| c.try_wait()).transpose()?.flatten() {
            anyhow::bail!(
                "Service exited ({code}); inspect {}",
                state.join("service.log").display()
            );
        }
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "Service is still starting; inspect {}",
            state.join("service.log").display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn print<T: serde::Serialize>(value: T) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &value)?;
    writeln!(out)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("MacTrim: {error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    let state = service::state_path(&args.state.unwrap_or(default_state()?))?;
    match args.command.unwrap_or(Commands::Storage {
        root: "/".into(),
        json: false,
    }) {
        Commands::BuildInfo => build_info(),
        Commands::Doctor { root } => doctor(&state, &root),
        Commands::Cleanup { action } => cleanup_command(&state, action),
        Commands::Scan { root } => {
            let root = fs::canonicalize(root)?;
            let progress = Arc::new(Mutex::new(Progress {
                view: root.clone(),
                ..Progress::default()
            }));
            let index = scan::measure(
                &root,
                &[state],
                None,
                &Regions::default(),
                signal_flag()?.as_ref(),
                Some(&progress),
            )?;
            print(
                serde_json::json!({"root":root,"node":index.root_node(),"visited":index.visited,"directories":index.nodes.len(),"rows":index.rows(&root,false)}),
            )
        }
        Commands::Storage { root, json } => {
            let root = fs::canonicalize(root)?;
            if !json {
                use std::io::IsTerminal;
                ensure!(
                    io::stdout().is_terminal(),
                    "The TUI needs a terminal; use --json for machine-readable status"
                );
            }
            start(&state, &root)?;
            if json {
                print(service::request(&state, &Request::Status)?)
            } else {
                mactrim_rs::ui::run(state, root, signal_flag()?)
            }
        }
        Commands::Status => print(service::request(&state, &Request::Status)?),
        Commands::History {
            path,
            days,
            offset,
            limit,
        } => print(service::request(
            &state,
            &Request::History {
                path,
                since: store::now().saturating_sub(days.saturating_mul(86400)),
                offset,
                limit,
            },
        )?),
        Commands::Refresh { full } => print(service::request(&state, &Request::Refresh { full })?),
        Commands::List {
            path,
            offset,
            limit,
            logical,
        } => print(service::request(
            &state,
            &Request::List {
                path: fs::canonicalize(path)?,
                offset,
                limit,
                logical,
                anchor: None,
            },
        )?),
        Commands::Service { action } => match action {
            Service::Retention { days } => {
                print(service::request(&state, &Request::Retention { days })?)
            }
            Service::Install { root } => {
                let root = fs::canonicalize(root)?;
                let app = mactrim_rs::agent::install(&state, &root)?;
                print(
                    serde_json::json!({"installed":app,"state":state,"root":root,"label":mactrim_rs::agent::LABEL,"note":"Per-user storage service installed. Privacy permissions are controlled by macOS."}),
                )
            }
            Service::Uninstall => {
                mactrim_rs::agent::uninstall(&state)?;
                print(
                    serde_json::json!({"uninstalled":mactrim_rs::agent::LABEL,"state_preserved":state}),
                )
            }
            Service::Plist { root } => {
                mactrim_rs::agent::plist_value(&state, &fs::canonicalize(root)?)?
                    .to_writer_xml(io::stdout().lock())
                    .map_err(Into::into)
            }
            Service::Run { root } => service::run(root, state, signal_flag()?),
            Service::Start { root } => {
                start(&state, &root)?;
                print(service::request(&state, &Request::Status)?)
            }
            Service::Stop => print(service::request(&state, &Request::Stop)?),
            Service::Pause => print(service::request(&state, &Request::Pause)?),
        },
    }
}
fn build_info() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let executable = std::env::current_exe()?;
    let mut f = fs::File::open(&executable)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    print(
        serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"revision":option_env!("MACTRIM_REVISION").unwrap_or("development"),"source_sha256":option_env!("MACTRIM_SOURCE_SHA256").unwrap_or("development"),"dirty":option_env!("MACTRIM_DIRTY").map(|s|s=="true"),"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"binary_bytes":f.metadata()?.len(),"binary_sha256":format!("{:x}",hash.finalize()),"runtime":"Rust; no Python interpreter","executable":executable}),
    )
}
fn doctor(state: &Path, root: &Path) -> Result<()> {
    use mactrim_rs::events;
    let root = fs::canonicalize(root)?;
    let (used, available) = service::capacity(&root)?;
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let probes = [
        home.join("Library/Mail"),
        home.join("Library/Messages"),
        home.join("Library/Containers"),
        home.join("Library/Group Containers"),
    ]
    .into_iter()
    .map(|p| {
        let status = match fs::read_dir(&p) {
            Ok(_) => "directory enumeration allowed".to_owned(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => "not present".into(),
            Err(e) => format!("{e}"),
        };
        serde_json::json!({"path":p,"status":status})
    })
    .collect::<Vec<_>>();
    let service = service::request(state, &Request::Status)
        .map(|r| r.status)
        .ok();
    print(
        serde_json::json!({"root":root,"state":state,"uid":unsafe{libc::geteuid()},"volume":events::identity(&root)?,"filesystem_used":used,"filesystem_available":available,"access_probes":probes,"service":service,"note":"Access is reported per scope. Full Disk Access does not override Unix permissions, SIP, unavailable mounts or changing entries. No file contents were read."}),
    )
}
fn approval(provided: Option<String>, expected: &str) -> Result<String> {
    if let Some(text) = provided {
        ensure!(text == expected, "Exact approval required: {expected}");
        return Ok(text);
    }
    use std::io::IsTerminal;
    ensure!(
        io::stdin().is_terminal(),
        "Exact approval required; pass --approve {expected:?}"
    );
    eprintln!("Type {expected:?} to approve this action, or press Enter to stop:");
    let mut text = String::new();
    io::stdin().read_line(&mut text)?;
    let text = text.trim_end().to_owned();
    ensure!(text == expected, "No action approved");
    Ok(text)
}
fn cleanup_command(state: &Path, action: Cleanup) -> Result<()> {
    use mactrim_rs::cleanup::{
        self, Actions,
        activity::{ActivityProvider, NativeActivity},
    };
    match action {
        Cleanup::Scan { mut roots } => {
            let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
            if roots.is_empty() {
                roots = ["Github", "Developer", "Projects", ".codex/worktrees"]
                    .iter()
                    .map(|p| home.join(p))
                    .collect();
            }
            print(cleanup::discover(&roots, &home, signal_flag()?.as_ref())?)
        }
        Cleanup::Validate {
            paths,
            older_than_days,
        } => {
            let actions = Actions::open(state)?;
            let candidates = paths
                .iter()
                .map(|p| cleanup::classify(p))
                .collect::<Result<Vec<_>>>()?;
            let plan = actions.prepare(&candidates, older_than_days)?;
            print(
                serde_json::json!({"plan":plan.id,"approval":plan.approval,"quarantine_frees_bytes":0,"items":plan.items.iter().map(|i|serde_json::json!({"path":i.candidate.path,"allocated":i.snapshot.allocated,"logical":i.snapshot.logical,"inventory_entries":i.snapshot.entries.len(),"evidence":i.candidate.evidence,"regenerate":i.candidate.regenerate})).collect::<Vec<_>>()}),
            )
        }
        Cleanup::Quarantine { id, approve } => {
            let actions = Actions::open(state)?;
            let plan = actions.plan(&id)?;
            let text = approval(approve, &plan.approval)?;
            print(actions.apply(&id,&text)?.iter().map(|j|serde_json::json!({"journal":j.id,"original":j.original,"quarantine":j.quarantine,"status":j.status,"quarantine_frees_bytes":0})).collect::<Vec<_>>())
        }
        Cleanup::Restore { id } => {
            let j = Actions::open(state)?.restore(&id)?;
            print(serde_json::json!({"id":j.id,"status":j.status,"original":j.original}))
        }
        Cleanup::Purge { id, approve } => {
            let text = approval(approve, &format!("PURGE {id}"))?;
            let j = Actions::open(state)?.purge(&id, &text)?;
            print(
                serde_json::json!({"id":j.id,"status":j.status,"observed_allocated_before":j.snapshot.allocated,"note":"APFS physical reclamation may differ from allocation estimates"}),
            )
        }
        Cleanup::Journals | Cleanup::Recover => {
            let actions = Actions::open(state)?;
            let records = if matches!(action, Cleanup::Recover) {
                actions.recover()?
            } else {
                actions.journals()?
            };
            print(records.iter().map(|j|serde_json::json!({"id":j.id,"status":j.status,"original":j.original,"quarantine":j.quarantine,"allocated":j.snapshot.allocated})).collect::<Vec<_>>())
        }
        Cleanup::Activity => {
            let activity = NativeActivity.snapshot()?;
            print(
                serde_json::json!({"complete":activity.complete,"issues":activity.issues,"observed_paths":activity.paths.len(),"scope":"current UID open paths/cwd and process arguments; other UIDs unobserved"}),
            )
        }
    }
}
