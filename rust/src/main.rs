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
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
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
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    Storage {
        #[arg(default_value = "/")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Status,
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
}
#[derive(Subcommand)]
enum Service {
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
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join("service.log"))?;
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
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        if service::request(state, &Request::Status).is_ok() {
            return Ok(());
        }
        if let Some(code) = child.try_wait()? {
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
    match args.command {
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
        Commands::Storage { root, json: _ } => {
            let root = fs::canonicalize(root)?;
            start(&state, &root)?;
            print(service::request(&state, &Request::Status)?)
        }
        Commands::Status => print(service::request(&state, &Request::Status)?),
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
            },
        )?),
        Commands::Service { action } => match action {
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
