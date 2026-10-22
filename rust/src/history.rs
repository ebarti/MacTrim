//! Comparison values for independently completed full scans.
use crate::model::Node;
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
