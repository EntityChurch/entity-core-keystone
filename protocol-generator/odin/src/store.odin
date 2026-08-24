package entity_core

import "core:mem"
import "core:slice"
import "core:strings"
import "core:sync"

// Storage — the two layers of §1.7 (foundation surface):
//
//   Content Store: hash → entity   (immutable, content-addressed, dedup)
//   Entity Tree:   path → hash      (mutable location index)
//
// In-memory minimal impl. The store OWNS every entity it holds (it clones on
// ingest); callers keep ownership of what they pass. Lookups return BORROWED
// views into store-owned entities — valid until the store mutates that entry or
// is destroyed. Paths are the canonical absolute "/{peer_id}/rest" form (§1.4);
// the peer canonicalizes before calling in.
//
// §4.8 store-safety is MANUAL (profile [async].store_safety = "manual-mutex").
// This is a raw-thread runtime — per-request dispatch runs on its own OS thread,
// so every content/tree map operation is guarded by an explicit sync.Mutex. A
// data race here = crash = conformance FAIL. Stored Entity payloads live until
// destroy, so an Entity returned by value (get_by_hash/get_at) stays valid after
// the lock releases (the map value is a struct copy; the heap blobs it points at
// are owned by the store until destroy).

// The store carries its OWN allocator (`al`) and uses it for every internal
// allocation — NOT the caller's context.allocator. §4.8 dispatch runs on OS
// threads whose default context differs from the main thread's; a store keyed to
// the calling thread's context would clone entities under thread-local heaps and
// then double/bad-free at destroy on the main thread. Pinning one allocator makes
// the store thread-safe under the mutex regardless of the dispatch thread.
Store :: struct {
	mu:      sync.Mutex,
	al:      mem.Allocator,
	content: map[string]Entity, // content_hash bytes (as string key) → owned Entity
	tree:    map[string]string, // path → content_hash bytes (as string)
}

store_init :: proc(allocator := context.allocator) -> Store {
	return Store{
		al = allocator,
		content = make(map[string]Entity, allocator),
		tree = make(map[string]string, allocator),
	}
}

store_destroy :: proc(st: ^Store, allocator := context.allocator) {
	al := st.al
	for k, v in st.content {
		delete(k, al)
		entity_destroy(v, al)
	}
	delete(st.content)
	for k, v in st.tree {
		delete(k, al)
		delete(v, al)
	}
	delete(st.tree)
}

// ── content store ─────────────────────────────────────────────────────────────

// store_put stores a deep copy of `e` keyed by its content_hash. A re-put of an
// existing hash is a no-op (§6.10 Store step). The store owns the copy.
store_put :: proc(st: ^Store, e: Entity, allocator := context.allocator) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	store_put_locked(st, e)
}

@(private = "file")
store_put_locked :: proc(st: ^Store, e: Entity) {
	key := string(e.hash)
	if _, exists := st.content[key]; exists {
		return
	}
	owned_key := strings.clone(key, st.al)
	owned, _ := entity_clone(e, st.al)
	st.content[owned_key] = owned
}

store_get_by_hash :: proc(st: ^Store, h: []u8) -> (Entity, bool) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	e, ok := st.content[string(h)]
	return e, ok
}

// ── entity tree (location index) ──────────────────────────────────────────────

// store_bind = Store then Bind (§6.10). Stores a copy of `e` and points `path`
// at its hash.
store_bind :: proc(st: ^Store, path: string, e: Entity, allocator := context.allocator) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	store_put_locked(st, e)
	if old, exists := st.tree[path]; exists {
		delete(old, st.al)
		st.tree[path] = strings.clone(string(e.hash), st.al)
	} else {
		st.tree[strings.clone(path, st.al)] = strings.clone(string(e.hash), st.al)
	}
}

store_unbind :: proc(st: ^Store, path: string, allocator := context.allocator) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	if _, exists := st.tree[path]; exists {
		k, v := delete_key(&st.tree, path)
		delete(k, st.al)
		delete(v, st.al)
	}
}

store_hash_at :: proc(st: ^Store, path: string) -> ([]u8, bool) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	h, ok := st.tree[path]
	return transmute([]u8)h, ok
}

store_get_at :: proc(st: ^Store, path: string) -> (Entity, bool) {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	h, ok := st.tree[path]
	if !ok {
		return Entity{}, false
	}
	e, eok := st.content[h]
	return e, eok
}

// ── one-level listing (§3.9) ──────────────────────────────────────────────────

List_Entry :: struct {
	seg:          string, // owned dup
	hash:         []u8, // borrows store memory (nil if this is only an interior node)
	has_children: bool,
}

// store_listing returns a one-level listing under `prefix_in` (a trailing "/" is
// ensured). Returns an owned slice; each `seg` is an owned dup, each `hash`
// borrows store memory. Caller frees the slice and each `seg`. Sorted by seg.
store_listing :: proc(
	st: ^Store,
	prefix_in: string,
	allocator := context.allocator,
) -> []List_Entry {
	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)

	prefix := prefix_in
	prefix_owned := false
	if len(prefix_in) == 0 || prefix_in[len(prefix_in) - 1] != '/' {
		prefix = strings.concatenate({prefix_in, "/"}, context.temp_allocator)
		prefix_owned = true
	}
	_ = prefix_owned
	plen := len(prefix)

	Acc :: struct {
		hash:   []u8,
		deeper: bool,
	}
	acc := make(map[string]Acc, context.temp_allocator)
	defer delete(acc)

	for path, hash_val in st.tree {
		if len(path) > plen && path[:plen] == prefix {
			rest := path[plen:]
			if idx := strings.index_byte(rest, '/'); idx >= 0 {
				seg := rest[:idx]
				a := acc[seg]
				a.deeper = true
				acc[seg] = a
			} else {
				a := acc[rest]
				a.hash = transmute([]u8)hash_val
				acc[rest] = a
			}
		}
	}

	out := make([dynamic]List_Entry, allocator)
	for seg, a in acc {
		append(&out, List_Entry{seg = strings.clone(seg, allocator), hash = a.hash, has_children = a.deeper})
	}
	slice.sort_by(out[:], proc(x, y: List_Entry) -> bool {
		return x.seg < y.seg
	})
	return out[:]
}

store_listing_destroy :: proc(entries: []List_Entry, allocator := context.allocator) {
	for e in entries {
		delete(e.seg, allocator)
	}
	delete(entries, allocator)
}
