//! store.rs — the §1.7 two-layer store (foundation surface):
//!
//! ```text
//!   Content Store: hash → entity   (immutable, content-addressed, dedup)
//!   Entity Tree:   path → hash      (mutable location index)
//! ```
//!
//! §4.8 store-race safety is STRUCTURAL in Rust (the profile's chosen §7b idiom):
//! a shared-mutable store without a lock is a compile error (`Send`/`Sync`), so the
//! race that crashed raw-thread peers is unrepresentable. A `RwLock` lets the
//! read-heavy hot path (`get_at` per request) run readers in parallel; only new
//! puts take the writer. Discipline: never hold the lock across I/O — every
//! accessor copies out owned values, callers work lock-free.
//!
//! The persistent grants/identities live here; the per-request Datalog EDB is
//! transient + rebuilt per request from these facts (profile `[async] store_model`).

use std::collections::HashMap;
use std::sync::RwLock;

use crate::model::Entity;

pub struct Store {
    inner: RwLock<Inner>,
}

struct Inner {
    content: HashMap<Vec<u8>, Entity>,
    tree: HashMap<String, Vec<u8>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Store {
        Store {
            inner: RwLock::new(Inner {
                content: HashMap::new(),
                tree: HashMap::new(),
            }),
        }
    }

    pub fn put_entity(&self, e: &Entity) {
        let mut inner = self.inner.write().unwrap();
        inner
            .content
            .entry(e.hash.clone())
            .or_insert_with(|| e.clone());
    }

    pub fn get_by_hash(&self, h: &[u8]) -> Option<Entity> {
        self.inner.read().unwrap().content.get(h).cloned()
    }

    pub fn bind(&self, path: &str, e: &Entity) {
        let mut inner = self.inner.write().unwrap();
        inner
            .content
            .entry(e.hash.clone())
            .or_insert_with(|| e.clone());
        inner.tree.insert(path.to_string(), e.hash.clone());
    }

    pub fn unbind(&self, path: &str) {
        self.inner.write().unwrap().tree.remove(path);
    }

    pub fn hash_at(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.read().unwrap().tree.get(path).cloned()
    }

    pub fn get_at(&self, path: &str) -> Option<Entity> {
        let inner = self.inner.read().unwrap();
        let h = inner.tree.get(path)?;
        inner.content.get(h).cloned()
    }

    /// One-level listing under `prefix` (§3.9): `(segment, bound_hash, has_children)`
    /// sorted by segment.
    pub fn listing(&self, prefix_in: &str) -> Vec<ListEntry> {
        let prefix = if prefix_in.ends_with('/') {
            prefix_in.to_string()
        } else {
            format!("{prefix_in}/")
        };
        let inner = self.inner.read().unwrap();
        let mut acc: HashMap<String, (Option<Vec<u8>>, bool)> = HashMap::new();
        for (path, hash) in inner.tree.iter() {
            if let Some(rest) = path.strip_prefix(&prefix) {
                if rest.is_empty() {
                    continue;
                }
                match rest.find('/') {
                    Some(i) => {
                        acc.entry(rest[..i].to_string()).or_insert((None, false)).1 = true;
                    }
                    None => {
                        acc.entry(rest.to_string()).or_insert((None, false)).0 = Some(hash.clone());
                    }
                }
            }
        }
        let mut out: Vec<ListEntry> = acc
            .into_iter()
            .map(|(seg, (hash, has_children))| ListEntry {
                seg,
                hash,
                has_children,
            })
            .collect();
        out.sort_by(|a, b| a.seg.cmp(&b.seg));
        out
    }
}

#[derive(Clone, Debug)]
pub struct ListEntry {
    pub seg: String,
    pub hash: Option<Vec<u8>>,
    pub has_children: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_host::Value;

    #[test]
    fn bind_get_listing() {
        let st = Store::new();
        let e = Entity::make("system/test", Value::Map(vec![]));
        st.bind("/p/system/a", &e);
        st.bind("/p/system/b/c", &e);
        assert_eq!(st.get_at("/p/system/a").unwrap().hash, e.hash);
        let ls = st.listing("/p/system/");
        assert_eq!(ls.len(), 2);
        assert_eq!(ls[0].seg, "a");
        assert!(ls[1].has_children);
    }
}
