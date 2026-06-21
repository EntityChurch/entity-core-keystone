//! Storage — the two layers of §1.7 (foundation surface):
//!
//! ```text
//!   Content Store: hash → entity   (immutable, content-addressed, dedup)
//!   Entity Tree:   path → hash      (mutable location index)
//! ```
//!
//! In-memory minimal impl. The store OWNS every entity it holds (it clones on
//! ingest); callers keep ownership of what they pass. Paths are the canonical
//! absolute `/{peer_id}/rest` form (§1.4) — the peer canonicalizes before
//! calling in.
//!
//! §4.8 store-safety is structural in Rust: a shared-mutable store WITHOUT a lock
//! is a compile error (`Send`/`Sync` bounds), so the store-race that crashed Zig
//! / hung Common-Lisp at the §7b T2.1 sustained-load probe is unrepresentable —
//! the borrow checker is the gate. A `RwLock` lets the read-heavy hot path
//! (`get_at` per request) run readers in parallel; only genuinely-new puts take
//! the writer lock. The discipline (§7b note): never hold the lock across I/O —
//! every accessor copies out under the lock and returns owned values, so callers
//! do their work (and any syscall) lock-free. Critical sections are single map
//! ops, so head-of-line blocking holds.
//!
//! Emit hook (§6.10 / §6.13(c)): the consumer-registration seam is live with zero
//! consumers (a core-only peer registers none); events are produced and discarded
//! when no consumer is set, so a future extension can attach without a rebuild.

use std::collections::HashMap;
use std::sync::RwLock;

use super::model::Entity;

/// A tree-change event (§6.10). `new_hash == None` denotes a delete.
#[derive(Clone, Debug)]
pub struct TreeChangeEvent {
    pub event_type: &'static str, // "created" | "modified" | "deleted"
    pub path: String,
    pub new_hash: Option<Vec<u8>>,
    pub previous_hash: Option<Vec<u8>>,
}

type TreeConsumer = Box<dyn Fn(&TreeChangeEvent) + Send + Sync>;

/// The two-layer content/tree store, guarded for concurrent dispatch (§4.8).
pub struct Store {
    inner: RwLock<Inner>,
    /// Emit consumers (§6.10). Registration is a separate lock so the hot path
    /// never contends on it.
    consumers: RwLock<Vec<TreeConsumer>>,
}

struct Inner {
    /// content_hash bytes → entity.
    content: HashMap<Vec<u8>, Entity>,
    /// path → content_hash bytes.
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
            consumers: RwLock::new(Vec::new()),
        }
    }

    /// Register an emit consumer (§6.10 / §6.13(c)). Live seam, no core consumers.
    pub fn register_tree_consumer<F>(&self, f: F)
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        self.consumers.write().unwrap().push(Box::new(f));
    }

    fn fire(&self, ev: &TreeChangeEvent) {
        for c in self.consumers.read().unwrap().iter() {
            c(ev);
        }
    }

    // ── content store ────────────────────────────────────────────────────────

    /// Store a copy of `e` keyed by its content_hash. A re-put of an existing
    /// hash fires nothing (§6.10 Store step).
    pub fn put_entity(&self, e: &Entity) {
        {
            let inner = self.inner.read().unwrap();
            if inner.content.contains_key(&e.hash) {
                return;
            }
        }
        let mut inner = self.inner.write().unwrap();
        inner
            .content
            .entry(e.hash.clone())
            .or_insert_with(|| e.clone());
    }

    pub fn get_by_hash(&self, h: &[u8]) -> Option<Entity> {
        self.inner.read().unwrap().content.get(h).cloned()
    }

    // ── entity tree (location index) ───────────────────────────────────────────

    /// bind = Store then Bind (§6.10). Fires a tree-change event when the binding
    /// at the path changes. Stores a copy of `e`.
    pub fn bind(&self, path: &str, e: &Entity) {
        let (changed, prev) = {
            let mut inner = self.inner.write().unwrap();
            inner
                .content
                .entry(e.hash.clone())
                .or_insert_with(|| e.clone());
            let prev = inner.tree.get(path).cloned();
            let changed = prev.as_deref() != Some(e.hash.as_slice());
            inner.tree.insert(path.to_string(), e.hash.clone());
            (changed, prev)
        };
        if changed {
            self.fire(&TreeChangeEvent {
                event_type: if prev.is_none() {
                    "created"
                } else {
                    "modified"
                },
                path: path.to_string(),
                new_hash: Some(e.hash.clone()),
                previous_hash: prev,
            });
        }
    }

    pub fn unbind(&self, path: &str) {
        let prev = {
            let mut inner = self.inner.write().unwrap();
            inner.tree.remove(path)
        };
        if let Some(prev_hash) = prev {
            self.fire(&TreeChangeEvent {
                event_type: "deleted",
                path: path.to_string(),
                new_hash: None,
                previous_hash: Some(prev_hash),
            });
        }
    }

    pub fn hash_at(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.read().unwrap().tree.get(path).cloned()
    }

    pub fn get_at(&self, path: &str) -> Option<Entity> {
        let inner = self.inner.read().unwrap();
        let h = inner.tree.get(path)?;
        inner.content.get(h).cloned()
    }

    // ── one-level listing (§3.9) ───────────────────────────────────────────────

    /// One-level listing under `prefix` (a trailing `/` is ensured). Returns
    /// `(segment, bound_hash, has_children)` sorted by segment.
    pub fn listing(&self, prefix_in: &str) -> Vec<ListEntry> {
        let prefix = if prefix_in.ends_with('/') {
            prefix_in.to_string()
        } else {
            format!("{prefix_in}/")
        };
        let inner = self.inner.read().unwrap();
        // child segment → (bound hash, has deeper children)
        let mut acc: HashMap<String, (Option<Vec<u8>>, bool)> = HashMap::new();
        for (path, hash) in inner.tree.iter() {
            if let Some(rest) = path.strip_prefix(&prefix) {
                if rest.is_empty() {
                    continue;
                }
                match rest.find('/') {
                    Some(i) => {
                        let seg = rest[..i].to_string();
                        acc.entry(seg).or_insert((None, false)).1 = true;
                    }
                    None => {
                        let entry = acc.entry(rest.to_string()).or_insert((None, false));
                        entry.0 = Some(hash.clone());
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

/// One listing entry (§3.9).
#[derive(Clone, Debug)]
pub struct ListEntry {
    pub seg: String,
    pub hash: Option<Vec<u8>>,
    pub has_children: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

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
        assert!(ls[0].hash.is_some());
        assert_eq!(ls[1].seg, "b");
        assert!(ls[1].has_children);
    }

    #[test]
    fn emit_consumer_fires_on_bind() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let st = Store::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        st.register_tree_consumer(move |_ev| {
            c.fetch_add(1, Ordering::SeqCst);
        });
        let e = Entity::make("system/test", Value::Map(vec![]));
        st.bind("/p/x", &e);
        st.bind("/p/x", &e); // no change → no event
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
