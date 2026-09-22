//! Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3
//! EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR-encoded envelope payload].
//! Reads/writes a full frame over a std.net.Stream; the reader/writer threading
//! lives in transport.zig (A-ZIG-003 std.Thread model).
//!
//! No-GC idiom: builders return owned Entities the caller frees; frame I/O uses a
//! caller-provided allocator for the read buffer (caller frees).

const std = @import("std");
const cbor = @import("cbor.zig");
const model = @import("model.zig");

const Entity = model.Entity;
const Value = model.Value;

pub const max_frame: usize = 16 * 1024 * 1024; // §1.6 SHOULD bound — 16 MiB

pub const Error = error{
    /// EOF at a FRAME BOUNDARY — an ordinary hangup, owed nothing.
    Closed,
    /// A frame that never completed: a partial length prefix, or a prefix declaring
    /// `n` bytes followed by fewer. §4.11's framing arm names this input outright —
    /// "un-parseable, truncated or non-canonical CBOR, or a length prefix that never
    /// completes" -> `400 invalid_request`.
    ///
    /// A SEPARATE ERROR FROM `Closed` BECAUSE THE TWO ARE DIFFERENT EVENTS AND A NAIVE
    /// readExact COLLAPSES THEM (this one did, until 0.8.2.25). A clean EOF at a frame
    /// boundary is an ordinary close; a stream that ends MID-FRAME is a REFUSAL and is
    /// owed a coded frame. Both surface as `read` answering 0, so the distinction can
    /// only be made where the frame boundary is known — and getting it wrong in the
    /// other direction would answer 400 to every peer that simply hangs up.
    Truncated,
    FrameTooLarge,
    WriteFailed,
} || model.Error;

/// Builders allocate but do no I/O — they carry only the codec/entity errors.
pub const BuildError = model.Error;

// ── fd read/write of a full frame ────────────────────────────────────────────

/// Read exactly `buf.len` bytes.
///
/// `at_frame_boundary` says that a close having read ZERO bytes is an ordinary hangup
/// (`error.Closed`) rather than a truncated frame; a close having read SOME is a
/// truncation either way. Only the length-prefix read sits at a boundary.
fn readExact(stream: std.net.Stream, buf: []u8, at_frame_boundary: bool) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const r = stream.read(buf[off..]) catch
            return if (at_frame_boundary and off == 0) error.Closed else error.Truncated;
        if (r == 0) return if (at_frame_boundary and off == 0) error.Closed else error.Truncated;
        off += r;
    }
}

/// Read one length-prefixed frame; returns the owned payload (caller frees).
pub fn readFrame(gpa: std.mem.Allocator, stream: std.net.Stream) Error![]u8 {
    var hdr: [4]u8 = undefined;
    try readExact(stream, &hdr, true);
    const len = (@as(usize, hdr[0]) << 24) | (@as(usize, hdr[1]) << 16) |
        (@as(usize, hdr[2]) << 8) | @as(usize, hdr[3]);
    if (len > max_frame) return error.FrameTooLarge;
    // A ZERO-LENGTH frame is COMPLETE, not truncated: the body read touches no bytes
    // and the empty payload reaches the decoder, which refuses it as bytes that never
    // become an Envelope.
    const payload = try gpa.alloc(u8, len);
    errdefer gpa.free(payload);
    try readExact(stream, payload, false);
    return payload;
}

// ── §4.11 pre-admission refusal classification (0.8.2.25) ────────────────────

/// The (status, code, message) §4.11 assigns a pre-admission failure's CAUSE.
///
/// "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" —
/// a single code for the class would answer an honest caller under the wrong reason and
/// send them to the wrong layer.
///
///   connect-auth proof-of-possession      -> 401 authentication_failed  (§4.6/§4.7, the connect handler's)
///   envelope over the configured maximum  -> 413 payload_too_large      (§4.10(a), N14)
///   resolution integrity (mis-keyed)      -> 400 hash_mismatch          (§5.2a, §1.8)
///   framing / never becomes an Envelope   -> 400 invalid_request        (§4.7, §4.11)
///   root is neither EXECUTE nor RESPONSE  -> 400 invalid_request        (§3.3, §4.11 — in dispatch)
///
/// The messages are a FIXED TABLE, never a rendered internal error: a wire-visible
/// string must stay ASCII (two peers in this cohort have been killed at runtime by a
/// non-ASCII byte in an encoded string), and nothing here echoes attacker-supplied bytes.
pub const Refusal = struct { status: u64, code: []const u8, message: []const u8 };

/// Whether a `readFrame` failure is a REFUSAL owed a coded frame (§4.11) rather than an
/// ordinary end of connection. A closed or reset socket refuses nothing and there is
/// nobody left to answer.
pub fn framingRefusal(e: anyerror) bool {
    return e == error.FrameTooLarge or e == error.Truncated;
}

/// Classify a framing-layer failure. See `Refusal`.
pub fn framingRefusalOf(e: anyerror) Refusal {
    if (e == error.FrameTooLarge)
        return .{ .status = 413, .code = "payload_too_large", .message = "inbound frame exceeds the configured maximum size" };
    return .{ .status = 400, .code = "invalid_request", .message = "frame did not decode into an envelope" };
}

/// The same classification for a failure AT THE DECODER rather than at the framing
/// layer: a COMPLETE frame that never became an Envelope.
///
/// THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
/// non-conformant "on the framing arm" and gives its reason in the same sentence:
/// ENTITY-CBOR-ENCODING "defines that code for CBOR tag-policy violations specifically",
/// which that document still MUSTs at decode time (§6.3). The two rows are disjoint by
/// CAUSE rather than in conflict, and §6.3 says so itself: a tag in a DATA-FIELD
/// position is the policy violation with its own code, while "the envelope and
/// entity-wrapper CBOR shapes are fixed maps and contain no positions where a tag could
/// legally be placed; any tag encountered in those structures is a structurally invalid
/// frame rejected by ordinary decoder validation" — i.e. the framing arm. Everything
/// else this decoder calls non-canonical (a non-minimal head, an indefinite length,
/// mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an Envelope"
/// and takes `invalid_request`.
///
/// §5.2a (0.8.2.24 N4/N5): "A peer that refuses at the decode boundary MUST answer `400
/// hash_mismatch` [MUST]" and, in the same breath, "`400 non_canonical_ecf` is NOT
/// conformant here [MUST]". A mis-keyed `included` entry carries no tag and its encoding
/// IS canonical; what is false is the claim the KEY makes, so the remedy
/// `non_canonical_ecf` selects (*re-encode*) sends an honest caller to the wrong layer.
/// This peer answered `non_canonical_ecf` for every decode-boundary refusal until
/// 0.8.2.24 (measured on the wire: arc-probe B1/B2).
pub fn decodeRefusalOf(e: anyerror) Refusal {
    if (e == error.ContentHashMismatch or e == error.IncludedKeyMismatch)
        return .{ .status = 400, .code = "hash_mismatch", .message = "an entity was addressed by a hash that does not bind to it" };
    if (e == error.TagRejected)
        return .{ .status = 400, .code = "non_canonical_ecf", .message = "CBOR tags are forbidden anywhere in an entity data field" };
    return .{ .status = 400, .code = "invalid_request", .message = "frame did not decode into an envelope" };
}

/// Write a length-prefixed frame. The caller serializes concurrent writes (the
/// transport holds a mutex over the shared stream).
pub fn writeFrame(stream: std.net.Stream, payload: []const u8) Error!void {
    var hdr: [4]u8 = undefined;
    const len = payload.len;
    hdr[0] = @truncate(len >> 24);
    hdr[1] = @truncate(len >> 16);
    hdr[2] = @truncate(len >> 8);
    hdr[3] = @truncate(len);
    stream.writeAll(&hdr) catch return error.WriteFailed;
    stream.writeAll(payload) catch return error.WriteFailed;
}

// ── envelope <-> frame ───────────────────────────────────────────────────────

pub fn frameOfEnvelope(gpa: std.mem.Allocator, env: model.Envelope) BuildError![]u8 {
    return env.encode(gpa);
}

// ── EXECUTE_RESPONSE builder (§3.3) ──────────────────────────────────────────

/// Build an EXECUTE_RESPONSE entity. Takes ownership of `result` (consumed into
/// the response's data tree). Returns an owned Entity the caller frees.
///
/// CONSUMES `result` ON EVERY PATH INCLUDING THE FAILING ONES, so a caller never has a
/// release to make and can never double-free it. `toCbor` used to be a bare `try`, which
/// leaked `result` on OOM and — worse for a reader — made the ownership contract
/// conditional, which is how the `model.ofCbor` double free (b71b940f) happened one
/// module over. A transfer that is true on some paths is not a transfer.
pub fn makeResponse(gpa: std.mem.Allocator, request_id: []const u8, status: u64, result: Entity) BuildError!Entity {
    const result_cbor = result.toCbor(gpa) catch |e| {
        result.deinit(gpa);
        return e;
    };
    result.deinit(gpa);
    errdefer result_cbor.deinit(gpa);

    var pairs = try gpa.alloc(Value.Pair, 3);
    errdefer gpa.free(pairs);
    pairs[0] = .{ .key = try model.textVal(gpa, "request_id"), .value = try model.textVal(gpa, request_id) };
    pairs[1] = .{ .key = try model.textVal(gpa, "status"), .value = .{ .uint = status } };
    pairs[2] = .{ .key = try model.textVal(gpa, "result"), .value = result_cbor };
    return Entity.make(gpa, "system/protocol/execute/response", .{ .map = pairs });
}

// ── EXECUTE builder (§3.2) ───────────────────────────────────────────────────

pub const ExecuteFields = struct {
    request_id: []const u8,
    uri: []const u8,
    operation: []const u8,
    params: Entity, // consumed
    /// optional resource target value (consumed if present)
    resource: ?Value = null,
    author: ?[]const u8 = null,
    capability: ?[]const u8 = null,
};

/// Build an EXECUTE entity. Consumes `params` (and `resource` if present) on EVERY
/// path — see `makeResponse` for why the failing ones matter as much as the rest.
pub fn makeExecute(gpa: std.mem.Allocator, f: ExecuteFields) BuildError!Entity {
    const params_cbor = f.params.toCbor(gpa) catch |e| {
        f.params.deinit(gpa);
        return e;
    };
    f.params.deinit(gpa);
    errdefer params_cbor.deinit(gpa);

    var list: std.ArrayList(Value.Pair) = .empty;
    errdefer {
        for (list.items) |p| {
            p.key.deinit(gpa);
            p.value.deinit(gpa);
        }
        list.deinit(gpa);
    }
    try list.append(gpa, .{ .key = try model.textVal(gpa, "request_id"), .value = try model.textVal(gpa, f.request_id) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "uri"), .value = try model.textVal(gpa, f.uri) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "operation"), .value = try model.textVal(gpa, f.operation) });
    try list.append(gpa, .{ .key = try model.textVal(gpa, "params"), .value = params_cbor });
    if (f.author) |a| try list.append(gpa, .{ .key = try model.textVal(gpa, "author"), .value = try model.bytesVal(gpa, a) });
    if (f.capability) |c| try list.append(gpa, .{ .key = try model.textVal(gpa, "capability"), .value = try model.bytesVal(gpa, c) });
    if (f.resource) |r| try list.append(gpa, .{ .key = try model.textVal(gpa, "resource"), .value = r });
    const pairs = try list.toOwnedSlice(gpa);
    return Entity.make(gpa, "system/protocol/execute", .{ .map = pairs });
}

// ── small result entities ────────────────────────────────────────────────────

/// system/protocol/error result entity (§3.3). Owned.
pub fn errorResult(gpa: std.mem.Allocator, code: []const u8, message: ?[]const u8) BuildError!Entity {
    var list: std.ArrayList(Value.Pair) = .empty;
    errdefer {
        for (list.items) |p| {
            p.key.deinit(gpa);
            p.value.deinit(gpa);
        }
        list.deinit(gpa);
    }
    try list.append(gpa, .{ .key = try model.textVal(gpa, "code"), .value = try model.textVal(gpa, code) });
    if (message) |m| try list.append(gpa, .{ .key = try model.textVal(gpa, "message"), .value = try model.textVal(gpa, m) });
    return Entity.make(gpa, "system/protocol/error", .{ .map = try list.toOwnedSlice(gpa) });
}

/// Empty-params entity (§3.2): primitive/any whose data is the canonical empty map.
pub fn emptyParams(gpa: std.mem.Allocator) BuildError!Entity {
    return Entity.make(gpa, "primitive/any", .{ .map = try gpa.alloc(Value.Pair, 0) });
}

const testing = std.testing;

test "§4.11 refusal codes belong to the CAUSE, not to the class (0.8.2.24/.25)" {
    // "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]."
    // The class is what makes a frame mandatory; the code is what tells an honest caller
    // which layer to go to, so a single code for the whole class is non-conformant.

    // §5.2a (N4/N5): the decode-boundary refusal MUST be hash_mismatch, and
    // non_canonical_ecf is explicitly NOT conformant there. A mis-keyed `included` entry
    // carries no tag and its encoding IS canonical — what is false is the claim the KEY
    // makes. This peer answered non_canonical_ecf for every decode refusal until now
    // (measured on the wire: arc-probe B1/B2).
    try testing.expectEqualStrings("hash_mismatch", decodeRefusalOf(error.IncludedKeyMismatch).code);
    try testing.expectEqualStrings("hash_mismatch", decodeRefusalOf(error.ContentHashMismatch).code);
    try testing.expectEqual(@as(u64, 400), decodeRefusalOf(error.IncludedKeyMismatch).status);

    // THE TAG ARM KEEPS ITS OWN CODE and that is the control: ENTITY-CBOR-ENCODING §5.4
    // defines non_canonical_ecf for CBOR tag-policy violations SPECIFICALLY, which §6.3
    // still MUSTs. Routing every decode refusal to hash_mismatch would be the same
    // defect in the other direction.
    try testing.expectEqualStrings("non_canonical_ecf", decodeRefusalOf(error.TagRejected).code);

    // Everything else that never becomes an Envelope is the framing arm.
    try testing.expectEqualStrings("invalid_request", decodeRefusalOf(error.NonCanonicalEcf).code);
    try testing.expectEqualStrings("invalid_request", decodeRefusalOf(error.DuplicateKey).code);
    try testing.expectEqualStrings("invalid_request", decodeRefusalOf(error.BadEntity).code);

    // §4.10(a) N14 — SHOULD became MUST; the oversize frame is owed a coded 413.
    try testing.expectEqual(@as(u64, 413), framingRefusalOf(error.FrameTooLarge).status);
    try testing.expectEqualStrings("payload_too_large", framingRefusalOf(error.FrameTooLarge).code);
    try testing.expectEqualStrings("invalid_request", framingRefusalOf(error.Truncated).code);

    // AN ORDINARY HANGUP IS NOT A REFUSAL and is owed nothing — there is nobody left to
    // answer. Getting this wrong in the other direction answers 400 to every peer that
    // simply closes, which is why Truncated is a separate error from Closed.
    try testing.expect(!framingRefusal(error.Closed));
    try testing.expect(framingRefusal(error.Truncated));
    try testing.expect(framingRefusal(error.FrameTooLarge));

    // Every wire-visible message is ASCII (AGENTS.md ratified discipline: two peers in
    // this cohort have been killed at runtime by a non-ASCII byte in an encoded string).
    for ([_]Refusal{
        decodeRefusalOf(error.IncludedKeyMismatch),
        decodeRefusalOf(error.TagRejected),
        decodeRefusalOf(error.BadEntity),
        framingRefusalOf(error.FrameTooLarge),
        framingRefusalOf(error.Truncated),
    }) |r| {
        for (r.message) |ch| try testing.expect(ch < 0x80);
        for (r.code) |ch| try testing.expect(ch < 0x80);
    }
}

test "readExact separates a clean hangup from a truncated frame (§4.11)" {
    // Both surface as `read` answering 0, so the distinction can only be made where the
    // frame boundary is known. A naive readExact collapses them, and this one did.
    const gpa = testing.allocator;

    // A length prefix declaring 8 bytes followed by 3: TRUNCATED, owed a coded frame.
    const short = [_]u8{ 0, 0, 0, 8, 1, 2, 3 };
    try testing.expectError(error.Truncated, readFramePipe(gpa, &short));

    // A partial length prefix is also mid-frame.
    const partial = [_]u8{ 0, 0 };
    try testing.expectError(error.Truncated, readFramePipe(gpa, &partial));

    // Zero bytes at a frame boundary: an ordinary close, owed nothing.
    try testing.expectError(error.Closed, readFramePipe(gpa, &.{}));

    // A ZERO-LENGTH frame is COMPLETE, not truncated — the empty payload reaches the
    // decoder, which refuses it as bytes that never become an Envelope.
    const empty_frame = [_]u8{ 0, 0, 0, 0 };
    const payload = try readFramePipe(gpa, &empty_frame);
    defer gpa.free(payload);
    try testing.expectEqual(@as(usize, 0), payload.len);
}

/// Feed `bytes` through a real pipe so `readFrame` sees the same `read`-returns-0 that
/// a closed socket produces. A hand-rolled reader would test the harness, not the peer.
fn readFramePipe(gpa: std.mem.Allocator, bytes: []const u8) Error![]u8 {
    const fds = std.posix.pipe() catch return error.Closed;
    // std.posix.write, not std.net.Stream.writeAll: the Stream writer needs a caller-
    // supplied buffer and this side of the fixture is not what is under test.
    if (bytes.len > 0) _ = std.posix.write(fds[1], bytes) catch {};
    std.posix.close(fds[1]); // EOF for the reader
    const r = std.net.Stream{ .handle = fds[0] };
    defer std.posix.close(fds[0]);
    return readFrame(gpa, r);
}

test "response builder consumes result and is well-formed" {
    const gpa = testing.allocator;
    const result = try emptyParams(gpa);
    const resp = try makeResponse(gpa, "r1", 404, result);
    defer resp.deinit(gpa);
    try testing.expectEqualStrings("system/protocol/execute/response", resp.typ);
    try testing.expectEqual(@as(u64, 404), resp.uintField("status").?);
    try testing.expectEqualStrings("r1", resp.textField("request_id").?);
}
