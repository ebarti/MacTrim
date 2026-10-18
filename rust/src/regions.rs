//! Component-aware antichain. Queries do not compare every node to every event.
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default)]
pub struct Regions(BTreeSet<PathBuf>);

impl Regions {
    pub fn insert(&mut self, path: PathBuf) {
        if path.ancestors().any(|p| self.0.contains(p)) {
            return;
        }
        // Lexicographic descendants form a range; sibling prefixes are not children.
        let descendants: Vec<_> = self
            .0
            .range(path.clone()..)
            .take_while(|p| p.starts_with(&path))
            .cloned()
            .collect();
        for p in descendants {
            self.0.remove(&p);
        }
        self.0.insert(path);
    }
    pub fn intersects(&self, path: &Path) -> bool {
        path.ancestors().any(|p| self.0.contains(p))
            || self
                .0
                .range(path.to_path_buf()..)
                .next()
                .is_some_and(|p| p.starts_with(path))
    }
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.0.iter()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<PathBuf> for Regions {
    fn from_iter<T: IntoIterator<Item = PathBuf>>(iter: T) -> Self {
        let mut value = Self::default();
        for p in iter {
            value.insert(p);
        }
        value
    }
}
