//! entity-core-protocol-zig — public codec module surface (S2).
//!
//! The core protocol peer's codec layer: Entity Canonical Form (ECF) CBOR,
//! content_hash, peer-id format/parse, Ed25519 sign/verify, LEB128 varints,
//! base58. std-only, no GC (explicit allocator everywhere), error unions.
//! Re-exported here per profile [layout].module_root = src/root.zig.

pub const cbor = @import("cbor.zig");
pub const varint = @import("varint.zig");
pub const base58 = @import("base58.zig");
pub const hash = @import("hash.zig");
pub const sign = @import("sign.zig");
pub const peer_id = @import("peer_id.zig");

// S3 peer machinery (V7 Layers 1–4 + foundation).
pub const model = @import("model.zig");
pub const wire = @import("wire.zig");
pub const store = @import("store.zig");
pub const identity = @import("identity.zig");
pub const capability = @import("capability.zig");
pub const type_defs = @import("type_defs.zig");
pub const peer = @import("peer.zig");
pub const transport = @import("transport.zig");

pub const Value = cbor.Value;

test {
    // Pull every module's in-file tests into `zig build test`.
    @import("std").testing.refAllDeclsRecursive(@This());
}
