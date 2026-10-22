//! Ratatui client. Navigation is local view state; the daemon owns measurement.
use crate::{
    cleanup::{self, Actions, Candidate, Journal, Plan},
    history::Change,
    model::COLLAPSED,
    service::{self, Reply, Request, Row, Status},
};
use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind},
    execute, terminal,
};
use ratatui::{
    prelude::*,
    widgets::{
        Axis, Bar, BarChart, BarGroup, Block, Borders, Cell, Chart, Clear, Dataset, GraphType,
        Paragraph, Row as TableRow, Table, TableState, Tabs, Wrap,
    },
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tui_input::{Input, backend::crossterm::EventHandler};

pub fn size(value: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = value as f64;
    let mut i = 0;
    while n >= 1024.0 && i < units.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{value} B")
    } else {
        format!("{n:.1} {}", units[i])
    }
}
fn visible(text: impl AsRef<str>) -> String {
    text.as_ref()
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn label(path: &Path) -> String {
    visible(
        path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy(),
    )
}
fn timestamp(value: u64) -> String {
    chrono::DateTime::from_timestamp(value as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%b %d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "not saved yet".into())
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Storage,
    Cleanup,
    History,
    Quarantine,
}
impl Tab {
    fn index(self) -> usize {
        match self {
            Self::Storage => 0,
            Self::Cleanup => 1,
            Self::History => 2,
            Self::Quarantine => 3,
        }
    }
    fn next(self) -> Self {
        match self {
            Self::Storage => Self::Cleanup,
            Self::Cleanup => Self::History,
            Self::History => Self::Quarantine,
            Self::Quarantine => Self::Storage,
        }
    }
}
enum Confirm {
    PauseStorage,
    CancelCleanup,
    FullRescan,
    Quarantine(Plan),
    Purge(String),
    Filter,
}
struct Prompt {
    kind: Confirm,
    input: Input,
    scroll: u16,
}
enum Message {
    Storage(u64, Result<Reply>),
    History(u64, Result<Reply>),
    Control(Result<Reply>),
    Discovery(u64, Result<cleanup::discovery::Discovery>),
    Prepared(u64, Result<Plan>),
    Applied(Result<Vec<Journal>>),
    Journals(Result<Vec<Journal>>),
    Action(Result<Journal>),
}
struct App {
    state: PathBuf,
    root: PathBuf,
    view: PathBuf,
    tab: Tab,
    status: Status,
    reply: Reply,
    rows: Vec<Row>,
    selected: Option<PathBuf>,
    table: TableState,
    offset: usize,
    logical: bool,
    version: u64,
    pending: bool,
    last_poll: Instant,
    sender: mpsc::Sender<Message>,
    message: String,
    prompt: Option<Prompt>,
    candidates: Vec<Candidate>,
    chosen: BTreeSet<String>,
    cleanup_index: usize,
    cleanup_gen: u64,
    cleanup_running: bool,
    validating: bool,
    cleanup_cancel: Arc<AtomicBool>,
    cleanup_loaded: bool,
    filter: String,
    history: Vec<Change>,
    capacity_history: Vec<crate::history::CapacityPoint>,
    history_index: usize,
    history_offset: usize,
    history_more: bool,
    journals: Vec<Journal>,
    journal_index: usize,
    busy: bool,
    table_area: Rect,
    chart_area: Rect,
    no_color: bool,
    prompt_max_scroll: u16,
}
impl App {
    fn new(state: PathBuf, root: PathBuf, sender: mpsc::Sender<Message>) -> Self {
        Self {
            state,
            view: root.clone(),
            root,
            tab: Tab::Storage,
            status: Status::default(),
            reply: Reply::default(),
            rows: vec![],
            selected: None,
            table: TableState::default(),
            offset: 0,
            logical: false,
            version: 0,
            pending: false,
            last_poll: Instant::now() - Duration::from_secs(5),
            sender,
            message: "Connecting to persistent storage service".into(),
            prompt: None,
            candidates: vec![],
            chosen: BTreeSet::new(),
            cleanup_index: 0,
            cleanup_gen: 0,
            cleanup_running: false,
            validating: false,
            cleanup_cancel: Arc::new(AtomicBool::new(false)),
            cleanup_loaded: false,
            filter: String::new(),
            history: vec![],
            capacity_history: vec![],
            history_index: 0,
            history_offset: 0,
            history_more: false,
            journals: vec![],
            journal_index: 0,
            busy: false,
            table_area: Rect::default(),
            chart_area: Rect::default(),
            prompt_max_scroll: 0,
            no_color: std::env::var_os("NO_COLOR").is_some_and(|s| !s.is_empty()),
        }
    }
    fn color(&self, c: Color) -> Color {
        if self.no_color { Color::Reset } else { c }
    }
    fn primary(&self) -> Style {
        Style::default().fg(self.color(Color::Rgb(57, 212, 225)))
    }
    fn warning(&self) -> Style {
        Style::default().fg(self.color(Color::Yellow))
    }
    fn highlight(&self) -> Style {
        Style::default()
            .bg(self.color(Color::Rgb(24, 65, 91)))
            .fg(self.color(Color::White))
            .add_modifier(Modifier::BOLD)
    }
    fn status_style(&self, status: u32) -> Style {
        Style::default().fg(self.color(match status {
            0 => Color::Green,
            1 => Color::DarkGray,
            3 => Color::Red,
            4 => Color::Cyan,
            _ => Color::Yellow,
        }))
    }
    fn control(&mut self, request: Request) {
        let state = self.state.clone();
        let tx = self.sender.clone();
        thread::spawn(move || {
            let _ = tx.send(Message::Control(service::request(&state, &request)));
        });
    }
    fn navigate(&mut self, path: PathBuf, lazy: bool) {
        if !path.starts_with(&self.root) {
            return;
        }
        self.view = path.clone();
        self.offset = 0;
        self.version += 1;
        self.rows.clear();
        self.selected = None;
        self.table.select(None);
        self.last_poll = Instant::now() - Duration::from_secs(5);
        if lazy {
            self.control(Request::Expand { path });
            self.message =
                "Details requested; the existing scan keeps its scope and progress".into();
        }
    }
    fn poll(&mut self) {
        let interval = if self.tab == Tab::History {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(600)
        };
        if self.pending || self.last_poll.elapsed() < interval {
            return;
        }
        if !matches!(self.tab, Tab::Storage | Tab::History) {
            return;
        }
        self.pending = true;
        self.last_poll = Instant::now();
        let state = self.state.clone();
        let tx = self.sender.clone();
        let version = self.version;
        let view = self.view.clone();
        let offset = self.offset;
        let logical = self.logical;
        let anchor = self.selected.clone();
        let tab = self.tab;
        let history_offset = self.history_offset;
        let history_days = if self.status.history_days == 0 {
            60
        } else {
            self.status.history_days
        };
        thread::spawn(move || {
            let request = if tab == Tab::Storage {
                Request::List {
                    path: view,
                    offset,
                    limit: 200,
                    logical,
                    anchor,
                }
            } else {
                Request::History {
                    path: view,
                    since: crate::store::now().saturating_sub(history_days.saturating_mul(86400)),
                    offset: history_offset,
                    limit: 200,
                }
            };
            let reply = service::request(&state, &request);
            let _ = tx.send(if tab == Tab::Storage {
                Message::Storage(version, reply)
            } else {
                Message::History(version, reply)
            });
        });
    }
    fn filtered(&self) -> Vec<&Candidate> {
        let q = self.filter.to_lowercase();
        self.candidates
            .iter()
            .filter(|c| {
                q.is_empty()
                    || c.path.to_string_lossy().to_lowercase().contains(&q)
                    || c.category.contains(&q)
            })
            .collect()
    }
    fn discover(&mut self) {
        if self.cleanup_running {
            return;
        }
        self.cleanup_running = true;
        self.cleanup_loaded = true;
        self.cleanup_gen += 1;
        self.cleanup_cancel = Arc::new(AtomicBool::new(false));
        self.message="Discovering repository artifacts, merged worktrees, package caches and possible app leftovers".into();
        let tx = self.sender.clone();
        let cancel = self.cleanup_cancel.clone();
        let generation = self.cleanup_gen;
        let root = self.root.clone();
        thread::spawn(move || {
            let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
            let roots = if root != Path::new("/") {
                vec![root]
            } else {
                ["Github", "Developer", "Projects", ".codex/worktrees"]
                    .iter()
                    .map(|p| home.join(p))
                    .collect()
            };
            let result = cleanup::discover(&roots, &home, &cancel);
            let _ = tx.send(Message::Discovery(generation, result));
        });
    }
    fn load_journals(&mut self) {
        let state = self.state.clone();
        let tx = self.sender.clone();
        thread::spawn(move || {
            let result = Actions::open(&state).and_then(|a| a.recover());
            let _ = tx.send(Message::Journals(result));
        });
    }
    fn switch(&mut self, tab: Tab) {
        self.tab = tab;
        self.pending = false;
        self.version += 1;
        self.last_poll = Instant::now() - Duration::from_secs(5);
        if tab == Tab::Cleanup && !self.cleanup_loaded {
            self.discover();
        }
        if tab == Tab::Quarantine {
            self.load_journals();
        }
    }
    fn prepare(&mut self) {
        if self.busy {
            return;
        }
        let candidates: Vec<_> = self
            .candidates
            .iter()
            .filter(|c| self.chosen.contains(&c.id))
            .cloned()
            .collect();
        if candidates.is_empty() {
            self.message = "Select proven candidates with Space before validating".into();
            return;
        }
        self.busy = true;
        self.validating = true;
        self.cleanup_cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cleanup_cancel.clone();
        let state = self.state.clone();
        let tx = self.sender.clone();
        let generation = self.cleanup_gen;
        self.message =
            "Validating fresh Git, process, ownership and descendant metadata; no move is approved"
                .into();
        thread::spawn(move || {
            let result =
                Actions::open(&state).and_then(|a| a.prepare_cancellable(&candidates, 30, &cancel));
            let _ = tx.send(Message::Prepared(generation, result));
        });
    }
    fn select_storage(&mut self, index: usize) {
        if let Some(row) = self.rows.get(index) {
            self.selected = Some(row.path.clone());
            self.table.select(Some(index));
        }
    }
    fn move_selection(&mut self, delta: isize) {
        match self.tab {
            Tab::Storage => {
                if !self.rows.is_empty() {
                    let n = (self.table.selected().unwrap_or(0) as isize + delta)
                        .clamp(0, self.rows.len() as isize - 1)
                        as usize;
                    self.select_storage(n);
                }
            }
            Tab::Cleanup => {
                self.cleanup_index = (self.cleanup_index as isize + delta)
                    .clamp(0, self.filtered().len().saturating_sub(1) as isize)
                    as usize;
            }
            Tab::History => {
                self.history_index = (self.history_index as isize + delta)
                    .clamp(0, self.history.len().saturating_sub(1) as isize)
                    as usize
            }
            Tab::Quarantine => {
                self.journal_index = (self.journal_index as isize + delta)
                    .clamp(0, self.journals.len().saturating_sub(1) as isize)
                    as usize
            }
        }
    }
    fn accept(&mut self, message: Message) {
        match message {
            Message::Storage(version, result) => {
                self.pending = false;
                if version != self.version {
                    return;
                }
                match result {
                    Ok(reply) => {
                        let identity = self
                            .selected
                            .as_ref()
                            .and_then(|p| reply.rows.iter().position(|r| &r.path == p));
                        let chosen = identity.or_else(|| {
                            (!reply.rows.is_empty()).then(|| {
                                self.table.selected().unwrap_or(0).min(reply.rows.len() - 1)
                            })
                        });
                        if self.message.starts_with("Connecting")
                            || self.message.starts_with("Service:")
                        {
                            self.message="Navigation reuses observations; the daemon keeps measuring when this client closes".into();
                        }
                        self.status = reply.status.clone();
                        self.rows = reply.rows.clone();
                        self.offset = reply.offset;
                        self.reply = reply;
                        if let Some(n) = chosen {
                            self.select_storage(n);
                        } else {
                            self.selected = None;
                            self.table.select(None);
                        }
                    }
                    Err(e) => self.message = format!("Service: {e:#}"),
                }
            }
            Message::History(version, result) => {
                self.pending = false;
                if version != self.version {
                    return;
                }
                match result {
                    Ok(reply) => {
                        self.status = reply.status;
                        self.history = reply.history;
                        self.capacity_history = reply.capacity_history;
                        self.history_more = reply.more;
                        self.history_index =
                            self.history_index.min(self.history.len().saturating_sub(1));
                    }
                    Err(e) => self.message = format!("History: {e:#}"),
                }
            }
            Message::Control(result) => match result {
                Ok(reply) => {
                    self.message = reply.message;
                    self.last_poll = Instant::now() - Duration::from_secs(5);
                }
                Err(e) => self.message = format!("Request failed: {e:#}"),
            },
            Message::Discovery(generation, result) => {
                if generation != self.cleanup_gen {
                    return;
                }
                self.cleanup_running = false;
                match result {
                    Ok(discovery) => {
                        self.candidates = discovery.candidates;
                        self.chosen.clear();
                        self.cleanup_index = 0;
                        self.message = format!(
                            "{} candidates · {} discovery warnings · {} unavailable roots; reports require manual review",
                            self.candidates.len(),
                            discovery.warnings.len(),
                            discovery.skipped_roots.len()
                        );
                        if let Some(w) = discovery.warnings.first() {
                            self.message.push_str(&format!(" · {w}"));
                        }
                    }
                    Err(e) => self.message = format!("Discovery: {e:#}"),
                }
            }
            Message::Prepared(generation, result) => {
                if generation != self.cleanup_gen {
                    return;
                }
                self.busy = false;
                self.validating = false;
                match result {
                    Ok(plan) => {
                        self.message="Validation complete. Quarantine frees zero bytes; review all selected paths before approval".into();
                        self.prompt = Some(Prompt {
                            kind: Confirm::Quarantine(plan),
                            input: Input::default(),
                            scroll: 0,
                        });
                    }
                    Err(e) => self.message = format!("Validation blocked: {e:#}"),
                }
            }
            Message::Applied(result) => {
                self.busy = false;
                match result {
                    Ok(records) => {
                        self.chosen.clear();
                        self.message = format!(
                            "{} items quarantined · zero bytes freed · Quarantine tab provides Restore and separately approved Purge",
                            records.len()
                        );
                        self.journals = records;
                    }
                    Err(e) => {
                        self.message =
                            format!("Quarantine stopped: {e:#}; inspect recovery journals")
                    }
                }
            }
            Message::Journals(result) => match result {
                Ok(records) => {
                    self.journals = records;
                    self.journal_index = self
                        .journal_index
                        .min(self.journals.len().saturating_sub(1));
                }
                Err(e) => self.message = format!("Recovery: {e:#}"),
            },
            Message::Action(result) => {
                self.busy = false;
                match result {
                    Ok(r) => {
                        self.message = format!("{}: {}", r.id, r.status);
                        self.load_journals();
                    }
                    Err(e) => self.message = format!("Action stopped safely: {e:#}"),
                }
            }
        }
    }
    fn input(&mut self, event: Event) -> bool {
        if let Some(mut prompt) = self.prompt.take() {
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Release {
                    self.prompt = Some(prompt);
                    return false;
                }
                if key.code == KeyCode::Esc
                    || matches!(key.code, KeyCode::Char('n') | KeyCode::Char('N'))
                        && matches!(
                            prompt.kind,
                            Confirm::PauseStorage | Confirm::CancelCleanup | Confirm::FullRescan
                        )
                {
                    self.message = "No action approved; current work continues".into();
                    return false;
                }
                if matches!(prompt.kind, Confirm::Quarantine(_))
                    && matches!(
                        key.code,
                        KeyCode::Down | KeyCode::Up | KeyCode::PageDown | KeyCode::PageUp
                    )
                {
                    prompt.scroll = match key.code {
                        KeyCode::Down => {
                            prompt.scroll.saturating_add(1).min(self.prompt_max_scroll)
                        }
                        KeyCode::PageDown => {
                            prompt.scroll.saturating_add(5).min(self.prompt_max_scroll)
                        }
                        KeyCode::PageUp => prompt.scroll.saturating_sub(5),
                        _ => prompt.scroll.saturating_sub(1),
                    };
                    self.prompt = Some(prompt);
                    return false;
                }
                match &prompt.kind {
                    Confirm::PauseStorage | Confirm::CancelCleanup | Confirm::FullRescan => {
                        if key.code == KeyCode::Char('y') || key.code == KeyCode::Char('Y') {
                            match prompt.kind {
                                Confirm::PauseStorage => self.control(Request::Pause),
                                Confirm::FullRescan => {
                                    self.control(Request::Refresh { full: true })
                                }
                                _ => {
                                    self.cleanup_cancel.store(true, Ordering::Relaxed);
                                    self.cleanup_gen += 1;
                                    self.cleanup_running = false;
                                    self.validating = false;
                                    self.busy = false;
                                    self.message =
                                        "Cleanup discovery cancelled; previous results remain"
                                            .into();
                                }
                            }
                            return false;
                        }
                        if key.code == KeyCode::Enter {
                            return false;
                        }
                    }
                    Confirm::Filter => {
                        if key.code == KeyCode::Enter {
                            self.filter = prompt.input.value().into();
                            self.cleanup_index = 0;
                            return false;
                        }
                    }
                    Confirm::Quarantine(plan) => {
                        if key.code == KeyCode::Enter {
                            if prompt.input.value() != plan.approval {
                                self.message = "Approval did not match; no move approved".into();
                                return false;
                            }
                            self.busy = true;
                            let state = self.state.clone();
                            let id = plan.id.clone();
                            let approval = plan.approval.clone();
                            let tx = self.sender.clone();
                            thread::spawn(move || {
                                let result =
                                    Actions::open(&state).and_then(|a| a.apply(&id, &approval));
                                let _ = tx.send(Message::Applied(result));
                            });
                            return false;
                        }
                    }
                    Confirm::Purge(id) => {
                        if key.code == KeyCode::Enter {
                            let expected = format!("PURGE {id}");
                            if prompt.input.value() != expected {
                                self.message =
                                    "Approval did not match; no deletion approved".into();
                                return false;
                            }
                            self.busy = true;
                            let state = self.state.clone();
                            let id = id.clone();
                            let tx = self.sender.clone();
                            thread::spawn(move || {
                                let result =
                                    Actions::open(&state).and_then(|a| a.purge(&id, &expected));
                                let _ = tx.send(Message::Action(result));
                            });
                            return false;
                        }
                    }
                }
                prompt.input.handle_event(&Event::Key(key));
                self.prompt = Some(prompt);
                return false;
            }
            self.prompt = Some(prompt);
            return false;
        }
        match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return !self.busy;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('x') {
                    if self.tab == Tab::Cleanup && (self.cleanup_running || self.validating) {
                        self.prompt = Some(Prompt {
                            kind: Confirm::CancelCleanup,
                            input: Input::default(),
                            scroll: 0,
                        });
                    } else if self.tab == Tab::Storage
                        && (self.status.running || self.status.detail_running)
                    {
                        self.prompt = Some(Prompt {
                            kind: Confirm::PauseStorage,
                            input: Input::default(),
                            scroll: 0,
                        });
                    }
                    return false;
                }
                match key.code {
                    KeyCode::Char(']') if self.tab == Tab::History && self.history_more => {
                        self.history_offset += 200;
                        self.version += 1;
                        self.last_poll = Instant::now() - Duration::from_secs(10);
                    }
                    KeyCode::Char('[') if self.tab == Tab::History => {
                        self.history_offset = self.history_offset.saturating_sub(200);
                        self.version += 1;
                        self.last_poll = Instant::now() - Duration::from_secs(10);
                    }
                    KeyCode::Char('q') => {
                        if self.busy {
                            self.message =
                                "A data action is finishing; its recovery journal is durable"
                                    .into();
                        } else {
                            return true;
                        }
                    }
                    KeyCode::Tab => self.switch(self.tab.next()),
                    KeyCode::F(1) => self.switch(Tab::Storage),
                    KeyCode::F(2) => self.switch(Tab::Cleanup),
                    KeyCode::F(3) => self.switch(Tab::History),
                    KeyCode::F(4) => self.switch(Tab::Quarantine),
                    KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
                    KeyCode::Enter | KeyCode::Right if self.tab == Tab::Storage => {
                        if let Some(row) =
                            self.rows.get(self.table.selected().unwrap_or(0)).cloned()
                            && row.directory
                        {
                            self.navigate(row.path, row.node.flags & COLLAPSED != 0);
                        }
                    }
                    KeyCode::Left | KeyCode::Backspace if self.tab == Tab::Storage => {
                        if let Some(p) = self.view.parent() {
                            self.navigate(p.to_owned(), false);
                        }
                    }
                    KeyCode::Char('g') if self.tab == Tab::Storage => {
                        self.navigate(self.root.clone(), false)
                    }
                    KeyCode::Char('m') if self.tab == Tab::Storage => {
                        self.logical = !self.logical;
                        self.version += 1;
                        self.last_poll = Instant::now() - Duration::from_secs(5);
                    }
                    KeyCode::Char('e') if self.tab == Tab::Storage => {
                        self.control(Request::Expand {
                            path: self.view.clone(),
                        })
                    }
                    KeyCode::Char(']') if self.tab == Tab::Storage && self.reply.more => {
                        self.offset += 200;
                        self.version += 1;
                        self.selected = None;
                        self.last_poll = Instant::now() - Duration::from_secs(5);
                    }
                    KeyCode::Char('[') if self.tab == Tab::Storage => {
                        self.offset = self.offset.saturating_sub(200);
                        self.version += 1;
                        self.selected = None;
                        self.last_poll = Instant::now() - Duration::from_secs(5);
                    }
                    KeyCode::Char('R') if self.tab == Tab::Storage => {
                        self.prompt = Some(Prompt {
                            kind: Confirm::FullRescan,
                            input: Input::default(),
                            scroll: 0,
                        })
                    }
                    KeyCode::Char('r') => match self.tab {
                        Tab::Storage | Tab::History => {
                            self.control(Request::Refresh { full: false })
                        }
                        Tab::Cleanup => self.discover(),
                        Tab::Quarantine => self.load_journals(),
                    },
                    KeyCode::Char('/') if self.tab == Tab::Cleanup => {
                        self.prompt = Some(Prompt {
                            kind: Confirm::Filter,
                            input: Input::from(self.filter.clone()),
                            scroll: 0,
                        })
                    }
                    KeyCode::Char(' ') if self.tab == Tab::Cleanup => {
                        if let Some(c) = self
                            .filtered()
                            .get(self.cleanup_index)
                            .map(|c| (*c).clone())
                        {
                            if c.eligible {
                                if !self.chosen.remove(&c.id) {
                                    self.chosen.insert(c.id);
                                }
                            } else {
                                self.message="Report-only item: ownership or safe recovery is not established".into();
                            }
                        }
                    }
                    KeyCode::Char('v') if self.tab == Tab::Cleanup => self.prepare(),
                    KeyCode::Char('u') if self.tab == Tab::Quarantine && !self.busy => {
                        if let Some(j) = self.journals.get(self.journal_index) {
                            let id = j.id.clone();
                            let state = self.state.clone();
                            let tx = self.sender.clone();
                            self.busy = true;
                            thread::spawn(move || {
                                let result = Actions::open(&state).and_then(|a| a.restore(&id));
                                let _ = tx.send(Message::Action(result));
                            });
                        }
                    }
                    KeyCode::Char('d') if self.tab == Tab::Quarantine && !self.busy => {
                        if let Some(j) = self.journals.get(self.journal_index) {
                            self.prompt = Some(Prompt {
                                kind: Confirm::Purge(j.id.clone()),
                                input: Input::default(),
                                scroll: 0,
                            });
                        }
                    }
                    _ => (),
                }
            }
            Event::Mouse(mouse)
                if mouse.kind == MouseEventKind::Down(MouseButton::Left)
                    && self.tab == Tab::Storage =>
            {
                if self.table_area.contains((mouse.column, mouse.row).into()) {
                    let n = mouse.row.saturating_sub(self.table_area.y + 2) as usize
                        + self.table.offset();
                    self.select_storage(n);
                } else if self.chart_area.contains((mouse.column, mouse.row).into()) {
                    let n = mouse.row.saturating_sub(self.chart_area.y + 1) as usize / 2;
                    self.select_storage(n);
                }
            }
            _ => (),
        }
        false
    }
    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(
            Block::default().style(
                Style::default()
                    .bg(self.color(Color::Rgb(10, 16, 28)))
                    .fg(self.color(Color::Gray)),
            ),
            area,
        );
        if area.width < 70 || area.height < 20 {
            frame.render_widget(Paragraph::new("MacTrim · enlarge the terminal to at least 70 columns × 20 rows.\nq closes this client; the background scan continues.").wrap(Wrap { trim: false }), area);
            return;
        }
        let chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(6),
        ])
        .split(area);
        frame.render_widget(
            Tabs::new([
                "Storage",
                "Cleanup",
                "History / Growth",
                "Quarantine / Recovery",
            ])
            .select(self.tab.index())
            .style(self.primary())
            .highlight_style(self.highlight())
            .block(
                Block::default()
                    .title(" MacTrim · Rust ")
                    .borders(Borders::BOTTOM),
            ),
            chunks[0],
        );
        let coverage = self
            .status
            .root_node
            .as_ref()
            .map(|n| n.status_name())
            .unwrap_or("PENDING");
        let header = vec![
            Line::styled(
                visible(self.view.to_string_lossy()),
                self.primary().add_modifier(Modifier::BOLD),
            ),
            Line::raw(format!(
                "Volume used {} · available {}  |  Coverage {} · {} retained directories · service metadata {}",
                size(self.status.filesystem_used),
                size(self.status.filesystem_available),
                coverage,
                self.status.directories,
                size(self.status.index_bytes)
            )),
            Line::raw(format!(
                "{} · saved {} · {} pending regions",
                visible(&self.status.phase),
                timestamp(self.status.last_saved),
                self.status.pending_regions
            )),
            Line::raw(self.reply.scope.as_ref().map(|n|format!("This folder: {} logical / {} allocated estimate · {}",size(n.logical),size(n.allocated),n.status_name())).unwrap_or_else(||"This folder: measurement pending; accessible descendants are measured at every depth".into())),
            Line::styled(if self.status.finish_then_idle {
                if self.status.running || self.status.detail_running {
                    "History changed: finishing and saving this scan, then idle; Refresh resumes measurement".into()
                } else {
                    "Measurement idle; saved observations retained. Press r to resume, or R for Full rescan".into()
                }
            } else if self.status.verification.is_some() {
                "Saved observations retained; some changes need verification. Full rescan requires R".into()
            } else if self.status.running {
                format!(
                    "Measuring {}",
                    visible(self.status.current_path.to_string_lossy())
                )
            } else if self.status.detail_running {
                "Loading browsing detail; the saved index remains available".into()
            } else {
                "Completed observations save automatically; q leaves the service running".into()
            }, if self.status.verification.is_some() { self.warning() } else { Style::default() }),
        ];
        frame.render_widget(Paragraph::new(header).wrap(Wrap { trim: false }), chunks[1]);
        match self.tab {
            Tab::Storage => self.draw_storage(frame, chunks[2]),
            Tab::Cleanup => self.draw_cleanup(frame, chunks[2]),
            Tab::History => self.draw_history(frame, chunks[2]),
            Tab::Quarantine => self.draw_journals(frame, chunks[2]),
        }
        let selected = self.rows.get(self.table.selected().unwrap_or(0));
        let detail = if self.tab == Tab::Storage {
            selected
                .map(|r| {
                    format!(
                        "{} · {} logical / {} allocated · {}{}",
                        visible(r.path.to_string_lossy()),
                        size(r.node.logical),
                        size(r.node.allocated),
                        r.node.status_name(),
                        r.node
                            .error_path
                            .as_ref()
                            .map(|p| format!(
                                " · {}: {}",
                                visible(p.to_string_lossy()),
                                std::io::Error::from_raw_os_error(r.node.error)
                            ))
                            .unwrap_or_default()
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        let foot=vec![Line::styled(if self.busy {"Working · recovery intent is durable"}else if self.cleanup_running&&self.tab==Tab::Cleanup {"Cleanup discovery running"}else{"q Close client · daemon continues · Tab/F1–F4 switch views"},self.primary()),Line::raw(detail),Line::styled(visible(self.status.error.as_deref().unwrap_or(&self.message)),if self.status.error.is_some(){self.warning()}else{Style::default()}),Line::raw(match self.tab{Tab::Storage=>format!("Enter/→ Browse · ← Parent · g Root · r Refresh events · R Full rescan · m Metric · [ ] Pages · Ctrl+X Pause · observed {} / {} visits",size(self.status.observed_allocated),self.status.visited),Tab::Cleanup=>"Space Select · v Validate → exact approval · / Filter · r Rescan · Ctrl+X Cancel discovery".into(),Tab::History=>"Observed directory deltas · nested rows overlap · incomplete or unobserved comparisons have unknown growth".into(),Tab::Quarantine=>"u Restore · d Purge with exact typed approval · r Recover journals · quarantine frees zero bytes".into()})];
        frame.render_widget(
            Paragraph::new(foot)
                .block(Block::default().borders(Borders::TOP))
                .wrap(Wrap { trim: false }),
            chunks[3],
        );
        if let Some(prompt) = &self.prompt {
            let width = area.width.saturating_sub(4).min(100);
            let height = area.height.saturating_sub(2).min(17);
            let modal = Rect::new(
                area.x + (area.width - width) / 2,
                area.y + (area.height - height) / 2,
                width,
                height,
            );
            frame.render_widget(Clear, modal);
            if let Confirm::Quarantine(plan) = &prompt.kind {
                frame.render_widget(
                    Block::default()
                        .title("Review quarantine · ↑/↓ scroll paths")
                        .borders(Borders::ALL)
                        .border_style(self.warning()),
                    modal,
                );
                let inner = modal.inner(Margin::new(1, 1));
                let sections = Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Min(2),
                    Constraint::Length(3),
                ])
                .split(inner);
                let allocated = plan.items.iter().map(|i| i.snapshot.allocated).sum();
                frame.render_widget(Paragraph::new(format!("{} validated items · {} allocated estimate\nQuarantine frees zero bytes. Esc closes without approval.",plan.items.len(),size(allocated))).wrap(Wrap{trim:false}),sections[0]);
                let paths = plan
                    .items
                    .iter()
                    .map(|i| {
                        format!(
                            "{} · {}",
                            visible(i.candidate.path.to_string_lossy()),
                            size(i.snapshot.allocated)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let paragraph = Paragraph::new(paths).wrap(Wrap { trim: false });
                self.prompt_max_scroll = paragraph
                    .line_count(sections[1].width)
                    .saturating_sub(sections[1].height as usize)
                    .min(u16::MAX as usize) as u16;
                frame.render_widget(
                    paragraph.scroll((prompt.scroll.min(self.prompt_max_scroll), 0)),
                    sections[1],
                );
                frame.render_widget(
                    Paragraph::new(format!(
                        "Type {} and press Enter:\n> {}",
                        plan.approval,
                        prompt.input.value()
                    ))
                    .style(self.primary())
                    .wrap(Wrap { trim: false }),
                    sections[2],
                );
                return;
            }
            let (title,text)=match &prompt.kind{
                Confirm::PauseStorage=>("Pause Storage?",format!("Pause the active scan for {}?\n\nY pauses measurement. N, Enter or Esc keeps it running.\nThe committed index and pending changes remain saved.",self.status.root.display())),
                Confirm::CancelCleanup=>("Cancel cleanup discovery?","Y cancels discovery/validation. N, Enter or Esc keeps it running.\nExisting results remain available; no data move is approved.".into()),
                Confirm::FullRescan=>("Full metadata rescan?",format!("Measure the complete accessible scope {} again?\nY starts a full scan. N, Enter or Esc keeps the current index.\nNormal Refresh uses event changes instead.",self.root.display())),
                Confirm::Filter=>("Filter cleanup candidates",format!("Path or category; Enter applies, Esc closes.\n\n{}",prompt.input.value())),
                Confirm::Quarantine(plan)=>{let bytes=plan.items.iter().map(|i|i.snapshot.allocated).sum();let paths=plan.items.iter().map(|i|format!("{} · {}",visible(i.candidate.path.to_string_lossy()),size(i.snapshot.allocated))).collect::<Vec<_>>().join("\n");("Review quarantine",format!("{} items · {} allocated estimate · zero bytes freed\n{}\n\nType {} and press Enter.\n{}",plan.items.len(),size(bytes),paths,plan.approval,prompt.input.value()))},
                Confirm::Purge(id)=>("Permanent deletion",format!("Delete the captured, unchanged quarantine contents for {id}?\nRestore is available before deletion. New or modified entries block purge.\n\nType PURGE {id} and press Enter.\n{}",prompt.input.value())),
            };
            frame.render_widget(
                Paragraph::new(text).wrap(Wrap { trim: false }).block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(self.warning()),
                ),
                modal,
            );
        }
    }
    fn draw_storage(&mut self, frame: &mut Frame, area: Rect) {
        let parts = if area.width >= 95 {
            Layout::horizontal([Constraint::Percentage(36), Constraint::Percentage(64)]).split(area)
        } else {
            Layout::horizontal([Constraint::Length(0), Constraint::Min(1)]).split(area)
        };
        self.chart_area = parts[0];
        self.table_area = parts[1];
        let metric = if self.logical { "Logical" } else { "Allocated" };
        if parts[0].width > 0 {
            let bars: Vec<_> = self
                .rows
                .iter()
                .take((area.height.saturating_sub(2) as usize / 2).min(15))
                .map(|r| {
                    Bar::default()
                        .label(label(&r.path))
                        .value(if self.logical {
                            r.node.logical
                        } else {
                            r.node.allocated
                        })
                        .text_value(size(if self.logical {
                            r.node.logical
                        } else {
                            r.node.allocated
                        }))
                        .style(if self.selected.as_ref() == Some(&r.path) {
                            self.highlight()
                        } else {
                            self.status_style(r.node.status)
                        })
                })
                .collect();
            let chart = BarChart::default()
                .direction(Direction::Horizontal)
                .bar_width(1)
                .bar_gap(1)
                .data(BarGroup::default().bars(&bars))
                .block(
                    Block::default()
                        .title(format!(" {metric} · this page "))
                        .borders(Borders::ALL),
                );
            frame.render_widget(chart, parts[0]);
        }
        let rows = self.rows.iter().map(|r| {
            TableRow::new(vec![
                Cell::from(r.node.status_name()).style(self.status_style(r.node.status)),
                Cell::from(size(if self.logical {
                    r.node.logical
                } else {
                    r.node.allocated
                })),
                Cell::from(format!(
                    "{}{}",
                    label(&r.path),
                    if r.directory { "/" } else { "" }
                )),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Min(15),
            ],
        )
        .header(TableRow::new(["Coverage", metric, "Directory / file"]).style(self.primary()))
        .row_highlight_style(self.highlight())
        .block(
            Block::default()
                .title(format!(
                    " Page {} · Enter loads lazy details ",
                    self.offset / 200 + 1
                ))
                .borders(Borders::ALL),
        );
        frame.render_stateful_widget(table, parts[1], &mut self.table);
    }
    fn draw_cleanup(&mut self, frame: &mut Frame, area: Rect) {
        let parts = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(area);
        let list = self.filtered();
        let rows = list.iter().map(|c| {
            TableRow::new([
                if self.chosen.contains(&c.id) {
                    "✓"
                } else {
                    " "
                }
                .into(),
                if c.eligible { "VALIDATE" } else { "REVIEW" }.into(),
                c.category.clone(),
                visible(c.path.to_string_lossy()),
            ])
            .style(if c.eligible {
                self.primary()
            } else {
                self.warning()
            })
        });
        let mut state = TableState::default().with_selected(Some(self.cleanup_index));
        let table = Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(9),
                Constraint::Length(20),
                Constraint::Min(15),
            ],
        )
        .header(TableRow::new(["", "Status", "Category", "Path"]).style(self.primary()))
        .row_highlight_style(self.highlight())
        .block(
            Block::default()
                .title(format!(
                    " {} candidates · {} selected ",
                    list.len(),
                    self.chosen.len()
                ))
                .borders(Borders::ALL),
        );
        frame.render_stateful_widget(table, parts[0], &mut state);
        let text=list.get(self.cleanup_index).map(|c|format!("{}\n\nEVIDENCE\n{}\n\nBLOCKERS\n{}\n\nREGENERATION / REVIEW\n{}\n\nFresh validation precedes any approval. Quarantine frees zero bytes.",visible(c.path.to_string_lossy()),c.evidence.iter().map(visible).collect::<Vec<_>>().join("\n"),c.blockers.iter().map(visible).collect::<Vec<_>>().join("\n"),visible(&c.regenerate))).unwrap_or_else(||"Discovery starts when this view opens. Nothing is selected initially.".into());
        frame.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(" Evidence and recovery ")
                    .borders(Borders::ALL),
            ),
            parts[1],
        );
    }
    fn draw_history(&self, frame: &mut Frame, area: Rect) {
        let split = Layout::vertical([Constraint::Length(8), Constraint::Min(4)]).split(area);
        let points: Vec<_> = self
            .capacity_history
            .iter()
            .map(|p| (p.at as f64, p.used as f64 / 1073741824.0))
            .collect();
        let first = points.first().map_or(0.0, |p| p.0);
        let last = points.last().map_or(first + 1.0, |p| p.0).max(first + 1.0);
        let low = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
        let high = points.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
        let (low, high) = if low.is_finite() {
            (low - 0.5, high + 0.5)
        } else {
            (0.0, 1.0)
        };
        let series = Dataset::default()
            .name("Filesystem used")
            .marker(ratatui::symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(self.primary())
            .data(&points);
        let chart = Chart::new(vec![series])
            .block(
                Block::default()
                    .title(" Filesystem used · GiB · hourly observations ")
                    .borders(Borders::ALL),
            )
            .x_axis(
                Axis::default()
                    .bounds([first, last])
                    .labels([timestamp(first as u64), timestamp(last as u64)]),
            )
            .y_axis(
                Axis::default()
                    .bounds([low, high])
                    .labels([format!("{low:.1}"), format!("{high:.1}")]),
            );
        frame.render_widget(chart, split[0]);
        let area = split[1];
        let rows = self.history.iter().map(|c| {
            let growth = c
                .growth()
                .map(|v| {
                    format!(
                        "{}{}",
                        if v >= 0 { "+" } else { "−" },
                        size(v.unsigned_abs().min(u64::MAX as u128) as u64)
                    )
                })
                .unwrap_or_else(|| "UNKNOWN".into());
            TableRow::new([
                growth,
                c.before
                    .as_ref()
                    .map(|n| size(n.allocated))
                    .unwrap_or_else(|| "unknown".into()),
                c.after
                    .as_ref()
                    .map(|n| size(n.allocated))
                    .unwrap_or_else(|| "unobserved".into()),
                visible(c.path.to_string_lossy()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(13),
                Constraint::Length(13),
                Constraint::Length(13),
                Constraint::Min(20),
            ],
        )
        .header(TableRow::new(["Growth", "Before", "Latest", "Directory"]).style(self.primary()))
        .row_highlight_style(self.highlight())
        .block(
            Block::default()
                .title(format!(
                    " Directory deltas · {} days · hourly coalescing · [ ] pages ",
                    if self.status.history_days == 0 {
                        60
                    } else {
                        self.status.history_days
                    }
                ))
                .borders(Borders::ALL),
        );
        let mut state = TableState::default().with_selected(Some(self.history_index));
        frame.render_stateful_widget(table, area, &mut state);
        if self.history.is_empty() {
            frame.render_widget(Paragraph::new("History begins with a measured baseline. Later changes appear here; earlier disk usage cannot be reconstructed from FSEvents alone.").wrap(Wrap{trim:false}),Rect::new(area.x+2,area.y+3,area.width.saturating_sub(4),area.height.saturating_sub(4)));
        }
    }
    fn draw_journals(&self, frame: &mut Frame, area: Rect) {
        let rows = self.journals.iter().map(|j| {
            TableRow::new([
                j.status.clone(),
                size(j.snapshot.allocated),
                j.id.clone(),
                visible(j.original.to_string_lossy()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(19),
                Constraint::Length(12),
                Constraint::Length(37),
                Constraint::Min(15),
            ],
        )
        .header(
            TableRow::new(["State", "Allocated", "Journal ID", "Original path"])
                .style(self.primary()),
        )
        .row_highlight_style(self.highlight())
        .block(
            Block::default()
                .title(" Restore / separately approved purge ")
                .borders(Borders::ALL),
        );
        let mut state = TableState::default().with_selected(Some(self.journal_index));
        frame.render_stateful_widget(table, area, &mut state);
    }
}
struct RestoreTerminal;
impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), event::DisableMouseCapture);
        let _ = terminal::disable_raw_mode();
        ratatui::restore();
    }
}
pub fn run(state: PathBuf, root: PathBuf, terminate: Arc<AtomicBool>) -> Result<()> {
    let mut terminal = ratatui::init();
    let _restore = RestoreTerminal;
    execute!(std::io::stdout(), event::EnableMouseCapture)?;
    let (tx, rx) = mpsc::channel();
    let mut app = App::new(state, root, tx);
    loop {
        if terminate.load(Ordering::Relaxed) {
            break;
        }
        while let Ok(message) = rx.try_recv() {
            app.accept(message);
        }
        app.poll();
        terminal.draw(|f| app.draw(f))?;
        if event::poll(Duration::from_millis(75))?
            && app.input(event::read().context("Terminal input failed")?)
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(path: &str, n: u64) -> Row {
        Row {
            path: path.into(),
            directory: true,
            node: crate::model::Node {
                allocated: n,
                ..Default::default()
            },
        }
    }
    #[test]
    fn incoming_sort_changes_preserve_selected_path() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        app.accept(Message::Storage(
            0,
            Ok(Reply {
                rows: vec![row("/fixture/a", 10), row("/fixture/b", 5)],
                ..Default::default()
            }),
        ));
        app.move_selection(1);
        app.accept(Message::Storage(
            0,
            Ok(Reply {
                rows: vec![row("/fixture/b", 20), row("/fixture/a", 10)],
                ..Default::default()
            }),
        ));
        assert_eq!(app.selected, Some("/fixture/b".into()));
        assert_eq!(app.table.selected(), Some(0));
    }
    #[test]
    fn stale_page_cannot_replace_a_new_view() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        app.version = 1;
        app.accept(Message::Storage(
            0,
            Ok(Reply {
                rows: vec![row("/fixture/a", 10)],
                ..Default::default()
            }),
        ));
        assert!(app.rows.is_empty());
    }
    #[test]
    fn an_empty_first_reply_keeps_the_loading_screen_usable() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        app.accept(Message::Storage(0, Ok(Reply::default())));
        assert!(app.rows.is_empty());
        assert!(app.table.selected().is_none());
    }
    #[test]
    fn escape_does_not_cancel_storage() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        app.status.running = true;
        app.input(Event::Key(event::KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        )));
        assert!(app.prompt.is_none());
        app.input(Event::Key(event::KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::CONTROL,
        )));
        assert!(app.prompt.is_some());
        app.input(Event::Key(event::KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        )));
        assert!(app.prompt.is_none());
    }
    #[test]
    fn all_views_render_in_the_library_test_backend() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(140, 45)).unwrap();
        for tab in [Tab::Storage, Tab::Cleanup, Tab::History, Tab::Quarantine] {
            app.tab = tab;
            terminal.draw(|f| app.draw(f)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(text.contains("MacTrim"));
        }
    }
    #[test]
    fn navigation_preserves_scan_and_cancellation_does_not_restart_discovery() {
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        app.status.running = true;
        app.status.visited = 42;
        app.navigate("/fixture/child".into(), false);
        assert!(app.status.running);
        assert_eq!(app.status.visited, 42);
        app.cleanup_loaded = true;
        app.cleanup_running = true;
        app.tab = Tab::Cleanup;
        app.input(Event::Key(event::KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::CONTROL,
        )));
        app.input(Event::Key(event::KeyEvent::new(
            KeyCode::Char('Y'),
            KeyModifiers::NONE,
        )));
        assert!(!app.cleanup_running);
        assert!(app.cleanup_cancel.load(Ordering::Relaxed));
        app.switch(Tab::Storage);
        app.switch(Tab::Cleanup);
        assert!(!app.cleanup_running);
        assert!(app.cleanup_loaded);
    }
    #[test]
    fn approval_input_stays_visible_when_many_paths_need_review() {
        use cleanup::actions::{Prepared, Snapshot};
        let (tx, _) = mpsc::channel();
        let mut app = App::new("/state".into(), "/fixture".into(), tx);
        let items = (0..30)
            .map(|i| Prepared {
                candidate: Candidate {
                    id: i.to_string(),
                    path: format!("/fixture/item-{i:02}").into(),
                    category: "fixture".into(),
                    eligible: true,
                    evidence: vec![],
                    blockers: vec![],
                    regenerate: String::new(),
                    repository: None,
                    allocated: None,
                },
                snapshot: Snapshot {
                    digest: String::new(),
                    logical: 0,
                    allocated: 0,
                    newest: 0,
                    entries: vec![],
                },
            })
            .collect();
        app.prompt = Some(Prompt {
            kind: Confirm::Quarantine(Plan {
                schema: String::new(),
                id: "fixture".into(),
                state: app.state.clone(),
                created: 0,
                minimum_days: 30,
                items,
                approval: "QUARANTINE fixture".into(),
            }),
            input: Input::default(),
            scroll: 0,
        });
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let rendered = |t: &Terminal<ratatui::backend::TestBackend>| {
            t.backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>()
        };
        assert!(rendered(&terminal).contains("Type QUARANTINE fixture"));
        app.prompt.as_mut().unwrap().scroll = app.prompt_max_scroll;
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(rendered(&terminal).contains("item-29"));
        assert!(rendered(&terminal).contains("Type QUARANTINE fixture"));
        let mut tiny = Terminal::new(ratatui::backend::TestBackend::new(40, 8)).unwrap();
        tiny.draw(|f| app.draw(f)).unwrap();
        assert!(rendered(&tiny).contains("enlarge"));
    }
}
