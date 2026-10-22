//! Hourly directory-size deltas. Unchanged trees are not copied into History.
use crate::model::{Index, Node};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapacityPoint {
    pub at: u64,
    pub used: u64,
    pub available: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub logical: u64,
    pub allocated: u64,
    pub complete: bool,
}
impl From<&Node> for Counts {
    fn from(n: &Node) -> Self {
        Self {
            logical: n.logical,
            allocated: n.allocated,
            complete: n.measured(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    #[serde(with = "crate::paths")]
    pub path: PathBuf,
    pub before: Option<Counts>,
    pub after: Option<Counts>,
    pub at: u64,
}
impl Change {
    pub fn growth(&self) -> Option<i128> {
        match (&self.before, &self.after) {
            (Some(a), Some(b)) if a.complete && b.complete => {
                Some(b.allocated as i128 - a.allocated as i128)
            }
            _ => None,
        }
    }
}
pub fn changes(previous: Option<&Index>, current: &Index, at: u64) -> Vec<Change> {
    let Some(previous) = previous else {
        return vec![];
    };
    let mut result = Vec::new();
    for delta in previous.nodes.diff(&current.nodes) {
        let (path, before, after) = match delta {
            im::ordmap::DiffItem::Add(p, n) => (p, None, Some(Counts::from(n))),
            im::ordmap::DiffItem::Update {
                old: (_, a),
                new: (p, b),
            } => (p, Some(Counts::from(a)), Some(Counts::from(b))),
            im::ordmap::DiffItem::Remove(p, n) => (p, Some(Counts::from(n)), None),
        };
        if before == after {
            continue;
        }
        let visible = path
            .parent()
            .and_then(|p| p.ancestors().find_map(|p| current.nodes.get(p)))
            .is_some_and(|n| n.measured() && n.flags & crate::model::COLLAPSED == 0);
        if after.is_some() || visible {
            result.push(Change {
                path: path.clone(),
                before,
                after,
                at,
            });
        }
    }
    result
}
