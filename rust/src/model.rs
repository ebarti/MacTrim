use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const POLICY: &str = "storage.native.v3";
pub const LINKED: u32 = 1;
pub const REUSED: u32 = 2;
pub const COLLAPSED: u32 = 4;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub logical: u64,
    pub allocated: u64,
    pub entries: u64,
    pub own_logical: u64,
    pub own_allocated: u64,
    pub signature: [u64; 6],
    pub flags: u32,
    pub status: u32,
    pub error: i32,
    pub error_path: Option<PathBuf>,
}

impl Node {
    pub fn status_name(&self) -> &'static str {
        match self.status {
            0 if self.flags & COLLAPSED != 0 => "LAZY",
            0 => "MEASURED",
            1 => "SKIPPED",
            3 => "DENIED",
            4 => "SCANNING",
            _ => "PARTIAL",
        }
    }
    pub fn measured(&self) -> bool {
        self.status == 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct Index {
    pub root: PathBuf,
    pub nodes: BTreeMap<PathBuf, Node>,
    pub children: BTreeMap<PathBuf, Vec<PathBuf>>,
    pub visited: u64,
    pub reused: u64,
}

impl Index {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            ..Self::default()
        }
    }
    pub fn insert(&mut self, path: PathBuf, node: Node) {
        if !self.nodes.contains_key(&path)
            && path != self.root
            && let Some(parent) = path.parent()
        {
            self.children
                .entry(parent.to_owned())
                .or_default()
                .push(path.clone());
        }
        self.nodes.insert(path, node);
    }
    pub fn root_node(&self) -> Option<&Node> {
        self.nodes.get(&self.root)
    }
    pub fn rows(&self, path: &Path, logical: bool) -> Vec<(PathBuf, Node)> {
        let mut rows: Vec<_> = self
            .children
            .get(path)
            .into_iter()
            .flatten()
            .filter_map(|p| self.nodes.get(p).map(|n| (p.clone(), n.clone())))
            .collect();
        rows.sort_unstable_by(|(a, x), (b, y)| {
            let size = |n: &Node| if logical { n.logical } else { n.allocated };
            size(y).cmp(&size(x)).then_with(|| a.cmp(b))
        });
        rows
    }
    pub fn copy_subtree(&mut self, old: &Index, root: &Path) {
        let mut pending = vec![root.to_owned()];
        while let Some(path) = pending.pop() {
            if let Some(node) = old.nodes.get(&path) {
                self.insert(path.clone(), node.clone());
            }
            pending.extend(old.children.get(&path).into_iter().flatten().cloned());
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Progress {
    pub phase: String,
    pub current: PathBuf,
    pub visited: u64,
    pub reused: u64,
    pub logical: u64,
    pub allocated: u64,
    pub view: PathBuf,
    pub rows: Vec<(PathBuf, Node)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub namespace_device: u64,
    pub namespace_inode: u64,
    pub namespace_uuid: String,
    pub device: u64,
    pub uuid: String,
    pub mount: PathBuf,
    pub relative: PathBuf,
}
