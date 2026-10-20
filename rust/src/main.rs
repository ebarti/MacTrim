use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use mactrim_rs::{
    filesystem, scan,
    session::{self},
    snapshots::{Capture, Snapshot, Snapshots},
    ui::size,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Parser)]
#[command(
    name = "mactrim",
    version,
    about = "Terminal disk usage explorer; full scans with saved comparisons"
)]
struct Args {
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    /// Print structured output instead of human-readable results.
    #[arg(long, global = true)]
    json: bool,
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
    /// Measure every accessible directory and save a distinct completed scan.
    Scan {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    /// Open the terminal app and start a full scan. Quitting stops all work.
    #[command(alias = "tui")]
    Storage {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    /// Show the latest saved scan. Does not start a process or scan.
    Status,
    /// List saved scans, newest first.
    Snapshots {
        root: Option<PathBuf>,
    },
    /// Compare two saved scans of the same root; defaults to the latest pair.
    History {
        #[arg(default_value = "/")]
        path: PathBuf,
        #[arg(long)]
        from: Option<u64>,
        #[arg(long)]
        to: Option<u64>,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long, default_value = "200")]
        limit: usize,
    },
    /// Run another full scan; no change journal or event tracking is used.
    Refresh {
        #[arg(default_value = "/")]
        root: PathBuf,
    },
    /// Browse a saved directory tree without starting another scan.
    List {
        path: PathBuf,
        #[arg(long)]
        scan: Option<u64>,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long, default_value = "200")]
        limit: usize,
        #[arg(long)]
        logical: bool,
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

fn print<T: serde::Serialize>(value: T) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &value)?;
    writeln!(&mut output)?;
    Ok(())
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        !path
            .components()
            .any(|c| c == std::path::Component::ParentDir),
        "Use an absolute path without '..'"
    );
    Ok(path)
}
fn catalog(state: &Path) -> Result<Option<Snapshots>> {
    if !state.join("scans.sqlite3").try_exists()? && state.join("service.sqlite3").try_exists()? {
        // Read-only import of the last legacy tree; its original files remain intact.
        drop(Snapshots::open(state)?);
    }
    Snapshots::read_only(state)
}
fn when(at: u64) -> String {
    chrono::DateTime::from_timestamp(at as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|| "unknown time".into())
}
fn print_snapshot(snapshot: &Snapshot) {
    println!("Scan #{} saved — {}", snapshot.id, snapshot.coverage_name());
    println!("Root: {}", snapshot.root.display());
    println!("Finished: {}", when(snapshot.finished));
    println!(
        "Usage: {} allocated; {} logical",
        size(snapshot.allocated),
        size(snapshot.logical)
    );
    if snapshot.imported {
        println!(
            "Imported index: {} directory aggregates; {} recorded entries",
            snapshot.directories, snapshot.visited
        );
        println!("Imported from the previous saved index; original data preserved.");
    } else {
        println!(
            "Full traversal: {} entries visited; {} directory aggregates saved",
            snapshot.visited, snapshot.directories
        );
    }
    if snapshot.coverage != 0 {
        println!(
            "Coverage is incomplete: unreadable, changing or excluded areas are identified in the saved tree."
        );
    }
}
fn full_scan(state: &Path, root: &Path, json: bool) -> Result<()> {
    let root = fs::canonicalize(root).context("Cannot access scan root")?;
    ensure!(state != root, "State directory cannot be the scan root");
    let cancel = signal_flag()?;
    let mut catalog = Snapshots::open(state)?;
    let capture = Capture::begin(&root)?;
    let index = scan::full(&root, &[state.to_owned()], &cancel, None)?;
    let snapshot = catalog.save(&index, &capture, &cancel)?;
    if json {
        print(snapshot)
    } else {
        print_snapshot(&snapshot);
        println!(
            "Compare saved scans with: mactrim history {}",
            root.display()
        );
        if let Some(warning) = catalog.import_warning()? {
            println!("{warning}");
        }
        Ok(())
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("MacTrim: {error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    let state = session::state_path(&absolute(&args.state.unwrap_or(default_state()?))?)?;
    match args
        .command
        .unwrap_or(Commands::Storage { root: "/".into() })
    {
        Commands::BuildInfo => build_info(),
        Commands::Doctor { root } => doctor(&state, &root, args.json),
        Commands::Scan { root } | Commands::Refresh { root } => full_scan(&state, &root, args.json),
        Commands::Storage { root } => {
            if args.json {
                return full_scan(&state, &root, true);
            }
            let root = fs::canonicalize(root).context("Cannot access scan root")?;
            ensure!(root != state, "State directory cannot be the scan root");
            mactrim_rs::ui::run(state, root, signal_flag()?)
        }
        Commands::Status => {
            let latest = catalog(&state)?
                .map(|c| c.list(None))
                .transpose()?
                .and_then(|s| s.into_iter().next());
            if args.json {
                print(serde_json::json!({"mode":"terminal-only","latest":latest}))
            } else {
                println!("Terminal-only mode; no background service.");
                if let Some(snapshot) = latest {
                    print_snapshot(&snapshot);
                } else {
                    println!("No completed scans yet. Run mactrim storage / or mactrim scan /.");
                }
                Ok(())
            }
        }
        Commands::Snapshots { root } => {
            let root = root.as_deref().map(absolute).transpose()?;
            let scans = catalog(&state)?
                .map(|c| c.list(root.as_deref()))
                .transpose()?
                .unwrap_or_default();
            if args.json {
                print(scans)
            } else {
                if scans.is_empty() {
                    println!("No completed scans yet.");
                }
                for s in scans {
                    println!(
                        "#{:<5} {}  {:<8} {:>12}  {}{}",
                        s.id,
                        when(s.finished),
                        s.coverage_name(),
                        size(s.allocated),
                        s.root.display(),
                        if s.imported { " [imported]" } else { "" }
                    );
                }
                Ok(())
            }
        }
        Commands::History {
            path,
            from,
            to,
            offset,
            limit,
        } => {
            drop(catalog(&state)?);
            let reply = session::history(&state, &absolute(&path)?, from, to, offset, limit)?;
            if args.json {
                return print(reply);
            }
            if let (Some(a), Some(b)) = (&reply.compare_from, &reply.compare_to) {
                println!(
                    "Scan #{} ({}) → #{} ({})",
                    a.id,
                    when(a.finished),
                    b.id,
                    when(b.finished)
                );
                if reply.same_filesystem == Some(false) {
                    println!("Root identity changed; growth is unknown.");
                }
                println!(
                    "{:>13} {:>13} {:>13}  Directory",
                    "Growth", "Before", "After"
                );
                for c in &reply.history {
                    let growth = c
                        .growth()
                        .map(|n| {
                            format!(
                                "{}{}",
                                if n >= 0 { "+" } else { "-" },
                                size(n.unsigned_abs().min(u64::MAX as u128) as u64)
                            )
                        })
                        .unwrap_or_else(|| "UNKNOWN".into());
                    println!(
                        "{:>13} {:>13} {:>13}  {}",
                        growth,
                        c.before
                            .as_ref()
                            .map(|n| size(n.allocated))
                            .unwrap_or_else(|| "unknown".into()),
                        c.after
                            .as_ref()
                            .map(|n| size(n.allocated))
                            .unwrap_or_else(|| "unknown".into()),
                        c.path.display()
                    );
                }
                if reply.history.is_empty() {
                    println!("No directory size changes in this scope.");
                }
            }
            println!("{}", reply.message);
            Ok(())
        }
        Commands::List {
            path,
            scan,
            offset,
            limit,
            logical,
        } => {
            ensure!(limit > 0 && limit <= 500, "Page size must be 1..500");
            let path = absolute(&path)?;
            let catalog = catalog(&state)?.context("No saved scan; run mactrim scan first")?;
            let snapshot = if let Some(id) = scan {
                catalog.get(id)?
            } else {
                catalog
                    .list(None)?
                    .into_iter()
                    .find(|s| path.starts_with(&s.root))
                    .context("No saved scan for this directory")?
            };
            ensure!(
                path.starts_with(&snapshot.root),
                "Path outside saved scan root"
            );
            let index = catalog.load(&snapshot)?;
            let (rows, more, offset) =
                session::directory_rows(Some(&index), &path, logical, offset, limit, None)?;
            if args.json {
                print(
                    serde_json::json!({"snapshot":snapshot,"rows":rows,"more":more,"offset":offset}),
                )
            } else {
                println!("Saved scan #{} · {}", snapshot.id, path.display());
                for r in rows {
                    println!(
                        "{:<9} {:>12}  {}{}",
                        r.node.status_name(),
                        size(if logical {
                            r.node.logical
                        } else {
                            r.node.allocated
                        }),
                        r.path
                            .file_name()
                            .unwrap_or(r.path.as_os_str())
                            .to_string_lossy(),
                        if r.directory { "/" } else { "" }
                    );
                }
                if more {
                    println!("More rows; use --offset {}", offset + limit);
                }
                Ok(())
            }
        }
        Commands::Cleanup { action } => cleanup_command(&state, action),
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

fn doctor(state: &Path, root: &Path, json: bool) -> Result<()> {
    let root = fs::canonicalize(root)?;
    let (used, available) = filesystem::capacity(&root)?;
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let probes = [
        "Library/Mail",
        "Library/Messages",
        "Library/Containers",
        "Library/Group Containers",
    ]
    .into_iter()
    .map(|p| {
        let path = home.join(p);
        let status = match fs::read_dir(&path) {
            Ok(_) => "directory enumeration allowed".into(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => "not present".into(),
            Err(e) => format!("{e}"),
        };
        (path, status)
    })
    .collect::<Vec<_>>();
    if json {
        print(
            serde_json::json!({"mode":"terminal-only","root":root,"state":state,"volume":filesystem::identity(&root)?,"filesystem_used":used,"filesystem_available":available,"access_probes":probes}),
        )
    } else {
        println!(
            "Terminal-only mode; no event monitoring.\nRoot: {}\nState: {}\nFilesystem: {} used; {} available",
            root.display(),
            state.display(),
            size(used),
            size(available)
        );
        for (p, s) in probes {
            println!("{}: {s}", p.display());
        }
        println!("Full Disk Access and Unix permissions apply to this terminal process.");
        Ok(())
    }
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
