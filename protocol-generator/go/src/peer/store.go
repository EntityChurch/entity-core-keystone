package peer

// store.go — Storage (foundation, §1.7): the two layers
//
//	Content Store: hash -> entity   (immutable, content-addressed, dedup)
//	Entity Tree:   path -> hash     (mutable location index)
//
// In-memory minimal impl. Paths are canonical absolute "/{peer_id}/rest" (§1.4);
// the peer canonicalizes before calling in. Hash keys render the 33-byte
// content_hash as lowercase hex (a comparable map key).
//
// DATA-RACE SAFETY (§4.8 / profile [concurrency].store_safety = sync.RWMutex):
// per-request dispatch runs on its own goroutine (§6.11), so the store MUST stay
// consistent under simultaneous inbound dispatches. A sync.RWMutex guards both
// maps — reads (resolve / listing) take RLock, writes (bind / put) take Lock.
// This is the PRE-RESOLVED cohort trap (Zig/Common-Lisp shipped unsynchronized
// stores that fell over under the §7b sustained-load probe); the Go peer starts
// with the mutex from S3, no race window. Emit consumers are invoked OUTSIDE the
// lock (snapshot the consumer list + the event under the lock, fire after
// unlocking) so a consumer never re-enters the store while it is held.
//
// EMIT PATHWAY (§6.10 / §6.13(c)) — the Core Extensibility Boundary: tree/content
// writes produce events; the bus delivers them to registered consumers. The hook
// is LIVE even with ZERO consumers (events are produced and discarded) so a
// future extension can register a consumer without the peer being rebuilt. A
// core-only peer registers zero consumers, but the seam is exercised on every
// bind.

import "sync"

// TreeEvent is a tree-change event (§6.10).
type TreeEvent struct {
	EventType    string // created / modified / deleted
	Path         string
	NewHash      string // hex, empty on delete
	PreviousHash string // hex, empty on create
}

// ContentEvent is a content-store event (§6.10) — fired when an entity is new.
type ContentEvent struct {
	Hash   []byte
	Entity Entity
}

// listingRow is one entry of a one-level listing: the path segment, the hex hash
// bound directly at it (empty if it is only an interior node), and whether it
// has children.
type listingRow struct {
	Segment     string
	Hash        string // hex, empty for an interior-only node
	HasChildren bool
}

// Store is the content-addressed store + the entity tree.
type Store struct {
	mu      sync.RWMutex
	content map[string]Entity // hash-hex -> entity
	tree    map[string]string // path -> hash-hex

	treeConsumers    []func(TreeEvent)
	contentConsumers []func(ContentEvent)
}

// NewStore constructs an empty store.
func NewStore() *Store {
	return &Store{
		content: make(map[string]Entity),
		tree:    make(map[string]string),
	}
}

// RegisterTreeConsumer registers a tree-event consumer (§6.10 consumer-
// registration primitive). Reachable any time, including post-bootstrap.
func (s *Store) RegisterTreeConsumer(fn func(TreeEvent)) {
	s.mu.Lock()
	s.treeConsumers = append(s.treeConsumers, fn)
	s.mu.Unlock()
}

// RegisterContentConsumer registers a content-event consumer.
func (s *Store) RegisterContentConsumer(fn func(ContentEvent)) {
	s.mu.Lock()
	s.contentConsumers = append(s.contentConsumers, fn)
	s.mu.Unlock()
}

func deriveEventType(prev, next string) string {
	switch {
	case prev == "":
		return "created"
	case next == "":
		return "deleted"
	default:
		return "modified"
	}
}

// PutEntity inserts an entity into the content store if new (a re-put of an
// existing hash fires nothing). Fires content consumers outside the lock.
func (s *Store) PutEntity(e Entity) {
	k := hexOf(e.Hash)
	s.mu.Lock()
	if _, exists := s.content[k]; exists {
		s.mu.Unlock()
		return
	}
	s.content[k] = e
	consumers := append([](func(ContentEvent)){}, s.contentConsumers...)
	s.mu.Unlock()
	ev := ContentEvent{Hash: e.Hash, Entity: e}
	for _, fn := range consumers {
		fn(ev)
	}
}

// GetByHash returns the entity with content_hash h, or false.
func (s *Store) GetByHash(h []byte) (Entity, bool) {
	s.mu.RLock()
	e, ok := s.content[hexOf(h)]
	s.mu.RUnlock()
	return e, ok
}

// Bind binds path to entity e (putting e in the content store first). Fires
// tree consumers outside the lock when the binding changes.
func (s *Store) Bind(path string, e Entity) {
	s.PutEntity(e)
	next := hexOf(e.Hash)
	s.mu.Lock()
	prev := s.tree[path]
	s.tree[path] = next
	changed := prev != next
	consumers := append([](func(TreeEvent)){}, s.treeConsumers...)
	s.mu.Unlock()
	if changed {
		ev := TreeEvent{EventType: deriveEventType(prev, next), Path: path, NewHash: next, PreviousHash: prev}
		for _, fn := range consumers {
			fn(ev)
		}
	}
}

// Unbind removes the binding at path. Fires a delete event when one was present.
func (s *Store) Unbind(path string) {
	s.mu.Lock()
	prev, had := s.tree[path]
	delete(s.tree, path)
	consumers := append([](func(TreeEvent)){}, s.treeConsumers...)
	s.mu.Unlock()
	if had {
		ev := TreeEvent{EventType: "deleted", Path: path, NewHash: "", PreviousHash: prev}
		for _, fn := range consumers {
			fn(ev)
		}
	}
}

// HashAt returns the hex content_hash bound at path, or "".
func (s *Store) HashAt(path string) string {
	s.mu.RLock()
	h := s.tree[path]
	s.mu.RUnlock()
	return h
}

// GetAt returns the entity bound at path, or false.
func (s *Store) GetAt(path string) (Entity, bool) {
	s.mu.RLock()
	h, ok := s.tree[path]
	if !ok {
		s.mu.RUnlock()
		return Entity{}, false
	}
	e, ok := s.content[h]
	s.mu.RUnlock()
	return e, ok
}

// Listing returns a one-level listing under prefix (a path; a trailing "/" is
// added if absent), sorted by segment. Each row carries the hex hash bound
// directly at the segment (empty if it is only an interior node) and whether it
// has children (§3.9).
func (s *Store) Listing(prefix string) []listingRow {
	if len(prefix) == 0 || prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}
	plen := len(prefix)
	type cell struct {
		hash   string
		deeper bool
	}
	acc := make(map[string]*cell)
	s.mu.RLock()
	for path, hash := range s.tree {
		if len(path) <= plen || path[:plen] != prefix {
			continue
		}
		rest := path[plen:]
		if i := indexByte(rest, '/'); i >= 0 {
			seg := rest[:i]
			c := acc[seg]
			if c == nil {
				acc[seg] = &cell{deeper: true}
			} else {
				c.deeper = true
			}
		} else {
			c := acc[rest]
			if c == nil {
				acc[rest] = &cell{hash: hash}
			} else {
				c.hash = hash
			}
		}
	}
	s.mu.RUnlock()

	rows := make([]listingRow, 0, len(acc))
	for seg, c := range acc {
		rows = append(rows, listingRow{Segment: seg, Hash: c.hash, HasChildren: c.deeper})
	}
	sortRows(rows)
	return rows
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func sortRows(rows []listingRow) {
	// small in-place insertion sort by segment (listings are small).
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j-1].Segment > rows[j].Segment; j-- {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}
