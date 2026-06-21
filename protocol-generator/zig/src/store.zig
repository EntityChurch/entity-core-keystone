//! Storage — the two layers of §1.7 (foundation surface):
//!
//!   Content Store: hash → entity   (immutable, content-addressed, dedup)
//!   Entity Tree:   path → hash      (mutable location index)
//!
//! In-memory minimal impl. The store OWNS every entity it holds (it dupes on
//! ingest); callers keep ownership of what they pass. Lookups return BORROWED
//! views into store-owned entities — valid until the store mutates that entry or
//! is deinit'd. Paths are the canonical absolute "/{peer_id}/rest" form (§1.4);
//! the peer canonicalizes before calling in.
//!
//! Emit hook (§6.10 / §6.13(c)): the consumer-registration seam is LIVE with zero
//! consumers (a core-only peer registers none), so a future extension can attach
//! without a rebuild. Events are produced and discarded when no consumer is set.

const std = @import("std");
const model = @import("model.zig");

const Entity = model.Entity;

pub const Error = error{OutOfMemory} || model.Error;

pub const TreeChangeEvent = struct {
    event_type: []const u8, // "created" | "modified" | "deleted"
    path: []const u8,
    new_hash: ?[]const u8,
    previous_hash: ?[]const u8,
};

pub const ContentStoreEvent = struct { hash: []const u8, entity: Entity };

pub const Store = struct {
    gpa: std.mem.Allocator,
    /// Guards the content+tree maps. Per-request dispatch runs on its own thread
    /// (§4.8), so without this every concurrent tree.get/put races the hashmaps —
    /// corrupting them and double-freeing under sustained load (keystone §7b t2_1).
    /// An RwLock (not a plain mutex) lets the read-heavy hot path (getAt per
    /// request) run readers in parallel; only genuinely-new puts take the writer
    /// lock. Critical sections are short (single map ops), so head-of-line (t1_3)
    /// holds — never held across a handler. Stored Entity payloads (typ/data heap
    /// blobs) are freed only at deinit, so an Entity returned by value
    /// (getByHash/getAt) stays valid after the lock releases.
    rwlock: std.Thread.RwLock = .{},
    /// content_hash bytes → owned Entity
    content: std.StringHashMapUnmanaged(Entity) = .{},
    /// path → content_hash bytes (owned key + owned value bytes)
    tree: std.StringHashMapUnmanaged([]const u8) = .{},
    tree_consumers: std.ArrayListUnmanaged(*const fn (TreeChangeEvent) void) = .empty,
    content_consumers: std.ArrayListUnmanaged(*const fn (ContentStoreEvent) void) = .empty,

    pub fn init(gpa: std.mem.Allocator) Store {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Store) void {
        const gpa = self.gpa;
        {
            var it = self.content.iterator();
            while (it.next()) |kv| {
                // key bytes are entity.hash (owned by the entity) — do not double-free;
                // we keyed on a duped copy, so free the key separately.
                gpa.free(kv.key_ptr.*);
                kv.value_ptr.deinit(gpa);
            }
            self.content.deinit(gpa);
        }
        {
            var it = self.tree.iterator();
            while (it.next()) |kv| {
                gpa.free(kv.key_ptr.*);
                gpa.free(kv.value_ptr.*);
            }
            self.tree.deinit(gpa);
        }
        self.tree_consumers.deinit(gpa);
        self.content_consumers.deinit(gpa);
    }

    pub fn registerTreeConsumer(self: *Store, f: *const fn (TreeChangeEvent) void) Error!void {
        try self.tree_consumers.append(self.gpa, f);
    }
    pub fn registerContentConsumer(self: *Store, f: *const fn (ContentStoreEvent) void) Error!void {
        try self.content_consumers.append(self.gpa, f);
    }

    // ── content store ────────────────────────────────────────────────────────

    /// Store a deep copy of `e` keyed by its content_hash. A re-put of an existing
    /// hash fires nothing (§6.10 Store step). The store owns the copy.
    pub fn putEntity(self: *Store, e: Entity) Error!void {
        // Common case (re-put of an existing hash — e.g. repeated responses under
        // load): a shared read suffices, so concurrent puts of known entities run
        // in parallel instead of serializing on the writer lock.
        {
            self.rwlock.lockShared();
            defer self.rwlock.unlockShared();
            if (self.content.contains(e.hash)) return;
        }
        self.rwlock.lock();
        defer self.rwlock.unlock();
        return self.putEntityLocked(e);
    }

    /// Caller MUST hold the writer lock (used by putEntity + bind).
    fn putEntityLocked(self: *Store, e: Entity) Error!void {
        const gpa = self.gpa;
        if (self.content.contains(e.hash)) return; // re-check: another writer may have raced in
        const key = try gpa.dupe(u8, e.hash);
        errdefer gpa.free(key);
        const owned = try e.clone(gpa);
        errdefer owned.deinit(gpa);
        try self.content.put(gpa, key, owned);
        for (self.content_consumers.items) |f| f(.{ .hash = owned.hash, .entity = owned });
    }

    pub fn getByHash(self: *Store, h: []const u8) ?Entity {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.content.get(h);
    }

    // ── entity tree (location index) ───────────────────────────────────────────

    /// bind = Store then Bind (§6.10). Fires a tree-change event when the binding
    /// at the path changes. Stores a copy of `e`.
    pub fn bind(self: *Store, path: []const u8, e: Entity) Error!void {
        self.rwlock.lock();
        defer self.rwlock.unlock();
        const gpa = self.gpa;
        try self.putEntityLocked(e);
        const prev = self.tree.get(path);
        const changed = prev == null or !std.mem.eql(u8, prev.?, e.hash);
        if (self.tree.getEntry(path)) |entry| {
            const new_val = try gpa.dupe(u8, e.hash);
            gpa.free(entry.value_ptr.*);
            entry.value_ptr.* = new_val;
        } else {
            const key = try gpa.dupe(u8, path);
            errdefer gpa.free(key);
            const val = try gpa.dupe(u8, e.hash);
            errdefer gpa.free(val);
            try self.tree.put(gpa, key, val);
        }
        if (changed) {
            const ev_type: []const u8 = if (prev == null) "created" else "modified";
            for (self.tree_consumers.items) |f|
                f(.{ .event_type = ev_type, .path = path, .new_hash = e.hash, .previous_hash = prev });
        }
    }

    pub fn unbind(self: *Store, path: []const u8) void {
        self.rwlock.lock();
        defer self.rwlock.unlock();
        const gpa = self.gpa;
        if (self.tree.fetchRemove(path)) |kv| {
            for (self.tree_consumers.items) |f|
                f(.{ .event_type = "deleted", .path = path, .new_hash = null, .previous_hash = kv.value });
            gpa.free(kv.key);
            gpa.free(kv.value);
        }
    }

    pub fn hashAt(self: *Store, path: []const u8) ?[]const u8 {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.tree.get(path);
    }

    pub fn getAt(self: *Store, path: []const u8) ?Entity {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        const h = self.tree.get(path) orelse return null;
        return self.content.get(h); // inlined (getByHash would re-lock)
    }

    // ── one-level listing (§3.9) ───────────────────────────────────────────────

    pub const ListEntry = struct { seg: []const u8, hash: ?[]const u8, has_children: bool };

    /// One-level listing under `prefix` (ensured to end in "/"). Returns an owned
    /// slice; each `seg` is an owned dup, each `hash` borrows store memory. Caller
    /// frees the slice and each `seg`.
    pub fn listing(self: *Store, gpa: std.mem.Allocator, prefix_in: []const u8) Error![]ListEntry {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        var prefix_buf: ?[]u8 = null;
        defer if (prefix_buf) |b| gpa.free(b);
        const prefix = blk: {
            if (prefix_in.len > 0 and prefix_in[prefix_in.len - 1] == '/') break :blk prefix_in;
            const b = try gpa.alloc(u8, prefix_in.len + 1);
            @memcpy(b[0..prefix_in.len], prefix_in);
            b[prefix_in.len] = '/';
            prefix_buf = b;
            break :blk b;
        };
        const plen = prefix.len;

        // child segment → (bound hash, has deeper children)
        var acc = std.StringHashMapUnmanaged(struct { hash: ?[]const u8, deeper: bool }){};
        defer acc.deinit(gpa);

        var it = self.tree.iterator();
        while (it.next()) |kv| {
            const path = kv.key_ptr.*;
            if (path.len > plen and std.mem.eql(u8, path[0..plen], prefix)) {
                const rest = path[plen..];
                if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
                    const seg = rest[0..i];
                    const gop = try acc.getOrPut(gpa, seg);
                    if (!gop.found_existing) gop.value_ptr.* = .{ .hash = null, .deeper = false };
                    gop.value_ptr.deeper = true;
                } else {
                    const gop = try acc.getOrPut(gpa, rest);
                    if (!gop.found_existing) gop.value_ptr.* = .{ .hash = kv.value_ptr.*, .deeper = false } else gop.value_ptr.hash = kv.value_ptr.*;
                }
            }
        }

        var out: std.ArrayList(ListEntry) = .empty;
        errdefer {
            for (out.items) |le| gpa.free(le.seg);
            out.deinit(gpa);
        }
        var ait = acc.iterator();
        while (ait.next()) |kv| {
            const seg = try gpa.dupe(u8, kv.key_ptr.*);
            try out.append(gpa, .{ .seg = seg, .hash = kv.value_ptr.hash, .has_children = kv.value_ptr.deeper });
        }
        const slice = try out.toOwnedSlice(gpa);
        std.mem.sort(ListEntry, slice, {}, struct {
            fn less(_: void, a: ListEntry, b: ListEntry) bool {
                return std.mem.order(u8, a.seg, b.seg) == .lt;
            }
        }.less);
        return slice;
    }
};

const testing = std.testing;

test "store bind/get/listing leak-clean" {
    const gpa = testing.allocator;
    var st = Store.init(gpa);
    defer st.deinit();
    const e = try Entity.make(gpa, "system/test", .{ .map = &.{} });
    defer e.deinit(gpa);
    try st.bind("/p/system/a", e);
    try st.bind("/p/system/b/c", e);
    const got = st.getAt("/p/system/a").?;
    try testing.expectEqualSlices(u8, e.hash, got.hash);

    const ls = try st.listing(gpa, "/p/system/");
    defer {
        for (ls) |le| gpa.free(le.seg);
        gpa.free(ls);
    }
    try testing.expectEqual(@as(usize, 2), ls.len);
    // entries sorted: "a" (bound leaf), "b" (has children)
    try testing.expectEqualStrings("a", ls[0].seg);
    try testing.expect(ls[0].hash != null);
    try testing.expectEqualStrings("b", ls[1].seg);
    try testing.expect(ls[1].has_children);
}
