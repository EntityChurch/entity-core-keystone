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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use super::model::Entity;

/// The §6.8a execution-context core fields (SYSTEM-COMPOSITION §1.4) carried on a
/// tree-change event.
///
/// The RESERVED field *names* are the collision contract; the representation is
/// impl-defined (§9.4). On a core peer most slots are inert, and every one is read
/// from the wire rather than synthesized — a slot the request did not carry stays
/// `None`.
///
/// `capability` is deliberately not its own slot: it is redundant with
/// `caller_capability` / `handler_grant`, which distinguish the two authorities a
/// write runs under. Capability slots carry the token's CONTENT HASH, the reference
/// an event consumer can resolve against the store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecContext {
    pub request_id: String,
    pub handler_pattern: String,
    pub operation: String,
    pub author: Option<Vec<u8>>,
    pub caller_capability: Option<Vec<u8>>,
    pub handler_grant: Option<Vec<u8>>,
    pub chain_id: Option<String>,
    pub parent_chain_id: Option<String>,
    pub cascade_depth: Option<u64>,
}

/// A tree-change event (§6.10). `new_hash == None` denotes a delete.
#[derive(Clone, Debug)]
pub struct TreeChangeEvent {
    pub event_type: &'static str, // "created" | "modified" | "deleted"
    pub path: String,
    pub new_hash: Option<Vec<u8>>,
    pub previous_hash: Option<Vec<u8>>,
    /// The execution context of the dispatch that caused this write, or `None` for an
    /// AUTONOMOUS write (the peer's own bootstrap and seeding).
    ///
    /// The distinction is load-bearing rather than cosmetic: `EXTENSION-HISTORY` §2.1
    /// defines the autonomous case exactly (author = the local peer's identity hash),
    /// so an event with NO context is indistinguishable from an autonomous write, and
    /// a conforming recorder fills in the autonomous reading and attributes a remote
    /// caller's write to the local peer.
    pub context: Option<ExecContext>,
}

type TreeConsumer = Arc<dyn Fn(&TreeChangeEvent) + Send + Sync>;
type ContentConsumer = Arc<dyn Fn(&ContentStoreEvent) + Send + Sync>;

/// A content-store event (§6.10 Store step): an entity whose content hash the store did
/// not hold before. Fired before the tree-change event of the bind that stored it, so a
/// consumer sees content before it sees a path naming it (`SYSTEM-COMPOSITION` §2.2).
#[derive(Clone, Debug)]
pub struct ContentStoreEvent {
    pub content_hash: Vec<u8>,
    pub entity_type: String,
}

/// Identifies one registered consumer, for [`Store::unregister_consumer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsumerId(u64);

/// The two-layer content/tree store, guarded for concurrent dispatch (§4.8).
pub struct Store {
    inner: RwLock<Inner>,
    /// Emit consumers (§6.10), in registration order. Registration is a separate lock so
    /// the hot path never contends on it, and `fire` copies the list out before calling
    /// any consumer — so a consumer may itself register or unregister one.
    consumers: RwLock<Vec<(ConsumerId, TreeConsumer)>>,
    content_consumers: RwLock<Vec<(ConsumerId, ContentConsumer)>>,
    next_consumer: AtomicU64,
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
            content_consumers: RwLock::new(Vec::new()),
            next_consumer: AtomicU64::new(1),
        }
    }

    /// Register a tree-change emit consumer (§6.10 / §6.13(c)), after construction.
    /// Consumers are invoked synchronously, in registration order (`SYSTEM-COMPOSITION`
    /// §1.2). Returns the id [`Store::unregister_consumer`] takes.
    pub fn register_tree_consumer<F>(&self, f: F) -> ConsumerId
    where
        F: Fn(&TreeChangeEvent) + Send + Sync + 'static,
    {
        let id = ConsumerId(self.next_consumer.fetch_add(1, Ordering::SeqCst));
        self.consumers.write().unwrap().push((id, Arc::new(f)));
        id
    }

    /// Register a content-store emit consumer (§6.10 Store step), after construction, in
    /// registration order.
    pub fn register_content_consumer<F>(&self, f: F) -> ConsumerId
    where
        F: Fn(&ContentStoreEvent) + Send + Sync + 'static,
    {
        let id = ConsumerId(self.next_consumer.fetch_add(1, Ordering::SeqCst));
        self.content_consumers.write().unwrap().push((id, Arc::new(f)));
        id
    }

    /// Stop delivering events to a consumer. Idempotent: `false` when `id` is not
    /// registered (already removed, or never was).
    pub fn unregister_consumer(&self, id: ConsumerId) -> bool {
        let mut tree = self.consumers.write().unwrap();
        if let Some(i) = tree.iter().position(|(c, _)| *c == id) {
            tree.remove(i);
            return true;
        }
        drop(tree);
        let mut content = self.content_consumers.write().unwrap();
        if let Some(i) = content.iter().position(|(c, _)| *c == id) {
            content.remove(i);
            return true;
        }
        false
    }

    fn fire(&self, ev: &TreeChangeEvent) {
        let consumers: Vec<TreeConsumer> =
            self.consumers.read().unwrap().iter().map(|(_, c)| c.clone()).collect();
        for c in consumers {
            c(ev);
        }
    }

    fn fire_content(&self, e: &Entity) {
        let consumers: Vec<ContentConsumer> = self
            .content_consumers
            .read()
            .unwrap()
            .iter()
            .map(|(_, c)| c.clone())
            .collect();
        if consumers.is_empty() {
            return;
        }
        let ev = ContentStoreEvent {
            content_hash: e.hash.clone(),
            entity_type: e.typ.clone(),
        };
        for c in consumers {
            c(&ev);
        }
    }

    // ── content store ────────────────────────────────────────────────────────

    /// Store a copy of `e` keyed by its content_hash. A re-put of an existing
    /// hash fires nothing (§6.10 Store step).
    ///
    /// Returns `false`, storing nothing and firing nothing, when `e.hash` is not the content hash
    /// of `{e.typ, e.data}` ([`Entity::content_hash_holds`]): the store never files an entity
    /// under an address it does not have. Otherwise `true`, including for a re-put.
    pub fn put_entity(&self, e: &Entity) -> bool {
        if !e.content_hash_holds() {
            return false;
        }
        {
            let inner = self.inner.read().unwrap();
            if inner.content.contains_key(&e.hash) {
                return true;
            }
        }
        let inserted = {
            let mut inner = self.inner.write().unwrap();
            if inner.content.contains_key(&e.hash) {
                false
            } else {
                inner.content.insert(e.hash.clone(), e.clone());
                true
            }
        };
        if inserted {
            self.fire_content(e);
        }
        true
    }

    pub fn get_by_hash(&self, h: &[u8]) -> Option<Entity> {
        self.inner.read().unwrap().content.get(h).cloned()
    }

    // ── entity tree (location index) ───────────────────────────────────────────

    /// bind = Store then Bind (§6.10). Fires a tree-change event when the binding
    /// at the path changes. Stores a copy of `e`.
    /// Autonomous bind — the peer's own bootstrap and seeding. Delivers NO execution
    /// context, which is what distinguishes such a write from a dispatched one.
    ///
    /// Returns `false` and binds nothing for an entity whose hash does not hold, as
    /// [`Store::put_entity`].
    pub fn bind(&self, path: &str, e: &Entity) -> bool {
        self.bind_with_context(path, e, None)
    }

    /// Bind carrying the §6.8a execution context of the dispatch that caused it.
    ///
    /// Split from [`Store::bind`] rather than adding a parameter to it: Rust has no
    /// default arguments, and every EXISTING caller is genuinely autonomous, so this
    /// keeps them correct by construction instead of by remembering to pass `None`.
    pub fn bind_with_context(&self, path: &str, e: &Entity, context: Option<ExecContext>) -> bool {
        if !e.content_hash_holds() {
            return false;
        }
        let (inserted, changed, prev) = {
            let mut inner = self.inner.write().unwrap();
            let inserted = !inner.content.contains_key(&e.hash);
            if inserted {
                inner.content.insert(e.hash.clone(), e.clone());
            }
            let prev = inner.tree.get(path).cloned();
            let changed = prev.as_deref() != Some(e.hash.as_slice());
            inner.tree.insert(path.to_string(), e.hash.clone());
            (inserted, changed, prev)
        };
        if inserted {
            self.fire_content(e);
        }
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
                context,
            });
        }
        true
    }

    /// Autonomous unbind. See [`Store::bind`].
    pub fn unbind(&self, path: &str) {
        self.unbind_with_context(path, None);
    }

    pub fn unbind_with_context(&self, path: &str, context: Option<ExecContext>) {
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
                context,
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
