use super::activity::command;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use walkdir::WalkDir;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    #[serde(with = "crate::paths")]
    pub path: PathBuf,
    pub category: String,
    pub eligible: bool,
    pub evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub regenerate: String,
    #[serde(with = "crate::paths::optional")]
    pub repository: Option<PathBuf>,
    pub allocated: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Discovery {
    pub candidates: Vec<Candidate>,
    pub warnings: Vec<String>,
    #[serde(with = "crate::paths::list")]
    pub skipped_roots: Vec<PathBuf>,
}
fn candidate(path: &Path, category: &str) -> Candidate {
    Candidate {
        id: format!(
            "{:x}",
            Sha256::digest([path.as_os_str().as_bytes(), category.as_bytes()].concat())
        ),
        path: path.to_owned(),
        category: category.into(),
        eligible: false,
        evidence: vec![],
        blockers: vec![],
        regenerate: String::new(),
        repository: None,
        allocated: None,
    }
}
fn git(path: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut values: Vec<&std::ffi::OsStr> = vec![
        "-c".as_ref(),
        "core.fsmonitor=false".as_ref(),
        "-c".as_ref(),
        "core.hooksPath=/dev/null".as_ref(),
        "-C".as_ref(),
        path.as_os_str(),
    ];
    // check-ignore consumes literal filenames and rejects pathspec magic.
    // Commands that do consume pathspecs must disable wildcard interpretation.
    if args.first() != Some(&"check-ignore") {
        values.insert(4, "--literal-pathspecs".as_ref());
    }
    values.extend(args.iter().map(std::ffi::OsStr::new));
    let result = command("/usr/bin/git", &values)?;
    anyhow::ensure!(
        result.status && result.stderr.is_empty(),
        "Git evidence unavailable"
    );
    Ok(result.stdout)
}
pub fn classify(path: &Path) -> Result<Candidate> {
    let path = fs::canonicalize(path)?;
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let category = if [
        "node_modules",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        "__pycache__",
        "target",
        "dist",
        "build",
    ]
    .contains(&name)
    {
        "repo-artifact"
    } else {
        "review"
    };
    let mut c = candidate(&path, category);
    if category == "repo-artifact" {
        let repo = git(
            path.parent().context("No artifact parent")?,
            &["rev-parse", "--show-toplevel"],
        )?;
        let repo = PathBuf::from(std::ffi::OsString::from_vec(
            repo.strip_suffix(b"\n").unwrap_or(&repo).to_vec(),
        ));
        let relative = path.strip_prefix(&repo)?;
        let rel = relative
            .to_str()
            .context("Non-UTF8 Git path is review-only")?;
        let ignored = git(&repo, &["check-ignore", "--quiet", "--", rel]).is_ok();
        let tracked = git(&repo, &["ls-files", "-z", "--", rel])?;
        let clean = git(
            &repo,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty();
        let tracked_spec = |name: &str| {
            let p = path.parent().unwrap().join(name);
            p.is_file()
                && !p.is_symlink()
                && p.strip_prefix(&repo)
                    .ok()
                    .and_then(Path::to_str)
                    .is_some_and(|rel| {
                        git(&repo, &["ls-files", "--error-unmatch", "--", rel]).is_ok()
                    })
        };
        let spec = if name == "node_modules" {
            [
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
            ]
            .iter()
            .any(|p| tracked_spec(p))
                && tracked_spec("package.json")
        } else if [".venv", "venv", ".tox", ".nox", "__pycache__"].contains(&name) {
            [
                "pyproject.toml",
                "requirements.txt",
                "uv.lock",
                "Pipfile.lock",
            ]
            .iter()
            .any(|p| tracked_spec(p))
                && (![".venv", "venv"].contains(&name) || path.join("pyvenv.cfg").is_file())
        } else if name == "target" {
            tracked_spec("Cargo.toml") && tracked_spec("Cargo.lock")
        } else {
            false
        };
        if !ignored {
            c.blockers.push("Artifact is not ignored by Git".into());
        }
        if !tracked.is_empty() {
            c.blockers.push("Tracked files must be retained".into());
        }
        if !clean {
            c.blockers
                .push("Repository source/index/untracked state is not clean".into());
        }
        if !spec {
            c.blockers
                .push("Regeneration specification or recognized artifact layout is absent".into());
        }
        let marker = if name == "node_modules" {
            [".package-lock.json", ".modules.yaml", ".yarn-state.yml"]
                .iter()
                .any(|p| {
                    let p = path.join(p);
                    p.is_file() && !p.is_symlink()
                })
        } else if [".venv", "venv"].contains(&name) {
            path.join("pyvenv.cfg").is_file() && path.join("bin/python").exists()
        } else if name == "target" {
            path.join(".rustc_info.json").is_file()
        } else {
            false
        };
        if !marker {
            c.blockers.push(
                "Recognized package-manager/environment metadata is absent; keep unique contents"
                    .into(),
            );
        }
        if repo.join(".gitmodules").exists() {
            c.blockers
                .push("Submodule repository requires manual review".into());
        }
        c.regenerate = if name == "node_modules" {
            "Install dependencies using this project's lockfile"
        } else if name == "target" {
            "cargo build --locked"
        } else {
            "Recreate using the tracked Python dependency specification"
        }
        .into();
        c.repository = Some(repo);
        c.evidence
            .push("Git ignore, tracked-file inventory and source/index status checked".into());
        c.eligible = c.blockers.is_empty();
    } else {
        c.blockers
            .push("Unique or unproven application data is report-only".into());
    }
    Ok(c)
}
pub fn discover(roots: &[PathBuf], home: &Path, cancel: &AtomicBool) -> Result<Discovery> {
    let mut result = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped_roots = Vec::new();
    let mut seen = BTreeSet::new();
    let mut repositories = BTreeSet::new();
    for root in roots {
        if !root.is_dir() {
            skipped_roots.push(root.clone());
            continue;
        }
        let mut walker = WalkDir::new(root)
            .follow_links(false)
            .max_open(16)
            .into_iter();
        while let Some(entry) = walker.next() {
            if cancel.load(Ordering::Relaxed) {
                anyhow::bail!("Cleanup discovery cancelled");
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            if !entry.file_type().is_dir() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy();
            if name == ".git" {
                repositories.insert(path.parent().unwrap().to_owned());
                walker.skip_current_dir();
                continue;
            }
            if path.join(".git").exists() {
                repositories.insert(path.to_owned());
            }
            if [
                "node_modules",
                ".venv",
                "venv",
                ".tox",
                ".nox",
                "__pycache__",
                "target",
                "dist",
                "build",
            ]
            .contains(&name.as_ref())
            {
                if seen.insert(path.to_owned()) {
                    result.push(classify(path).unwrap_or_else(|e| {
                        let mut c = candidate(path, "repo-artifact");
                        c.blockers.push(format!("Evidence unavailable: {e:#}"));
                        c
                    }));
                }
                walker.skip_current_dir();
            }
        }
    }
    for repo in repositories {
        let data = match git(&repo, &["worktree", "list", "--porcelain"]) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let target = git(&repo, &["symbolic-ref", "refs/remotes/origin/HEAD"])
            .or_else(|_| git(&repo, &["rev-parse", "--verify", "main"]));
        let Ok(target) = target else {
            continue;
        };
        let target = String::from_utf8_lossy(&target).trim().to_owned();
        for record in String::from_utf8_lossy(&data).split("\n\n").skip(1) {
            let Some(path) = record.lines().find_map(|l| l.strip_prefix("worktree ")) else {
                continue;
            };
            let path = PathBuf::from(path);
            let Some(head) = record.lines().find_map(|l| l.strip_prefix("HEAD ")) else {
                continue;
            };
            if git(&repo, &["merge-base", "--is-ancestor", head, &target]).is_ok()
                && seen.insert(path.clone())
            {
                let mut c = candidate(&path, "merged-worktree");
                c.evidence.push(format!(
                    "HEAD {head} is reachable from local {target}; remote freshness is unverified"
                ));
                c.blockers.push("Registered worktree has Git administration and recovery state; use git worktree tools after review".into());
                c.regenerate = "Review the registered checkout with git worktree list before any manual removal".into();
                result.push(c);
            }
        }
    }
    for path in [
        home.join(".npm/_cacache"),
        home.join(".cache/uv"),
        home.join("Library/Caches/pip"),
        home.join("Library/Caches/uv"),
    ] {
        if path.is_dir() && seen.insert(path.clone()) {
            let mut c = candidate(&path, "package-cache");
            c.evidence
                .push("Known package-manager cache location; contains download/build state".into());
            c.blockers.push(
                "Use the package manager's cache/prune command after reviewing its active users"
                    .into(),
            );
            c.regenerate = "npm cache verify / uv cache prune / pip cache purge".into();
            result.push(c);
        }
    }
    let mut installed = BTreeSet::new();
    for root in [PathBuf::from("/Applications"), home.join("Applications")] {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .max_depth(4)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_name() == "Info.plist"
                && let Ok(plist::Value::Dictionary(info)) = plist::Value::from_file(entry.path())
                && let Some(id) = info
                    .get("CFBundleIdentifier")
                    .and_then(plist::Value::as_string)
            {
                installed.insert(id.to_owned());
            }
        }
    }
    for parent in [
        home.join("Library/Containers"),
        home.join("Library/Application Support"),
        home.join("Library/Caches"),
        home.join("Library/Preferences"),
    ] {
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry
                    .file_name()
                    .to_string_lossy()
                    .trim_end_matches(".plist")
                    .to_owned();
                if name.starts_with("com.")
                    && !name.starts_with("com.apple.")
                    && !installed.contains(&name)
                    && entry.file_type().is_ok_and(|t| t.is_dir())
                    && seen.insert(entry.path())
                {
                    let mut c = candidate(&entry.path(), "possible-app-leftover");
                    c.evidence.push(format!("No application with bundle ID {name} was found in the inspected application roots"));
                    c.blockers.push("Helpers, shared vendor data and historical ownership are unproven; never delete solely because an app is missing".into());
                    result.push(c);
                }
            }
        }
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Discovery {
        candidates: result,
        warnings,
        skipped_roots,
    })
}
