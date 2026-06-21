# entity-core-protocol-zig — Phase S3 (Peer) Summary

**Status: COMPLETE — peer compiles + smoke-runs GREEN, leak-clean, in-container**

Peer #4 (Zig, distant-idiom systems peer). S3 builds the V7 Layers 1–4 + foundation peer machinery
on top of the green S2 codec (69/69 wire-conformance, commit `2aed485`), in Zig idiom: **no GC /
explicit allocators, error unions, `std.Thread` concurrency, `comptime`-free dispatch**. ~2.9k lines
of new `src/`. The OCaml peer (#3) was the closest precedent (native, spec-first, stdlib-threads); the
seams that differ from it are the no-GC ownership contract and the error-union model.

## What was built (`src/`, on top of the S2 codec)

| Module | V7 layer | Responsibility | LoC |
|---|---|---|---|
| `model.zig`      | foundation | materialized `Entity {type,data,content_hash}` on `cbor.Value` + `Envelope` (§3.1); fidelity-validating `ofCbor` (§1.8); the **caller-frees ownership contract** (`deinit`/`clone`, A-ZIG-004/007) | 341 |
| `store.zig`      | foundation | content store (hash→entity, store-owned dupes) + entity tree (path→hash) + one-level listing (§1.7, §3.9); §6.10/§6.13(c) emit consumer-registration seam (live, zero consumers) | 226 |
| `identity.zig`   | L1 | seed → **canonical identity-multihash peer_id** (§1.5 v7.65; A-ZIG-001, NOT §7.4 SHA-256) / `system/peer` entity / sign (§3.5, §7.3) / verify | 114 |
| `wire.zig`       | L2 | §1.6 framing (4-byte BE length + CBOR envelope), EXECUTE / EXECUTE_RESPONSE / error / empty-params builders; frame read/write over `std.net.Stream` | 157 |
| `capability.zig` | L3 | §5.2 `verifyRequest` (3-way authn/authz verdict, A-ZIG-006), `checkPermission`, §5.4 patterns + `canonicalize` + §1.4 `normalizeUri`, §5.5 chain walk, §5.6 attenuation, §5.7 caveats, §5.1 revocation; **arena-scoped scratch** | 487 |
| `type_defs.zig`  | foundation | §9.5 minimal core-type seed (S3 subset; full 53-type registry deferred to S4 — A-ZIG-008) | 36 |
| `peer.zig`       | L1–L4 | the four MUST handlers (connect/tree/handler/capability), §6.5 dispatch chain (per-request arena → clone-into-gpa), §6.5 signature ingestion, §6.6 backward resolution, §6.9 bootstrap, **§6.9a peer-authority seed bootstrap**, per-connection state | 890 |
| `transport.zig`  | L4 | TCP listener/dialer + per-connection `std.Thread` reader, §6.11 `request_id` demux, §4.8 inbound-on-own-thread, §6.13(b) `Io.outbound` reentry seam, write-serializing mutex; high-level handshake `initiate` + `Session.execute` | 334 |
| `host.zig`       | — | standalone S4-ready host (`--port`, `--debug-open-grants`, `--validate`, `LISTENING` line) | 109 |
| `smoke.zig`      | — | **the S3 smoke runner** — two Zig peers over real loopback TCP, leak-checked GPA | 219 |

## 1. Does the peer compile + smoke-run green in-container?

**Yes.** Built and run inside `entity-core-keystone/zig-toolchain:latest` (Zig 0.15.1, `--network=none`):
- `zig build` — clean, all artifacts (lib, wire-conformance, smoke, host).
- `zig build test` — all unit tests pass **leak-clean** (`std.testing.allocator`); S2 regression unbroken.
- `zig build conformance` — **69/69** wire-conformance (no codec regression).
- `zig build smoke` / `./zig-out/bin/smoke` — **SMOKE: PASS (7 pass, 0 fail)**, EXIT 0, leak-clean
  under a safety-on `GeneralPurposeAllocator`.

The smoke exercises, over two real loopback-TCP Zig peers:
1. **§4.1 handshake** — initiator `hello` → `authenticate`, both legs answered by the responder over
   real frames; session established with its §4.4 initial capability; remote peer_id == responder peer_id.
2. **404** — EXECUTE on an unregistered path → `404 not_found` (no handler resolved).
3. **authority-gated tree get → 200** — granted `system/tree get` on `system/type/system/peer` returns a
   `system/type` entity (the discovery-floor grant minted at authenticate admits it).
4. **capability request → 200** — `system/capability request` mints a bounded child cap.
5. **request_id demux (N7) → 8/8** — 8 EXECUTEs issued from concurrent threads each correlate to their
   own EXECUTE_RESPONSE.
6. **clean teardown** — `shutdown(both)` wakes both reader threads; joins; `io.deinit`; no leak.

## 2. Transport model (A-ZIG-003 validated)

`std.Thread`, std-only, zero deps. One **reader thread per connection** (`transport.readLoop`) demuxes
inbound frames (§6.11): an EXECUTE_RESPONSE routes to the awaiting outbound caller by `request_id` through
a `pending` table (`StringHashMapUnmanaged` guarded by `std.Thread.Mutex` + `std.Thread.Condition`); an
inbound EXECUTE is dispatched on its **own** spawned thread (§4.8). Writes share the stream behind a
per-`Io` write mutex. The §6.13(b) handler-outbound reentry seam is the per-connection `Io.outbound`
(send + await-correlated-reply; close broadcasts all waiters). **A-ZIG-003 is validated**: the smoke's
8/8 concurrent `request_id` demux is the N7 proof. The S1 threaded decision stands (logged RESOLVED in the
ambiguity log). `std.Io` evented model remains the open path if handler-initiated outbound origination
enters the core (extension-only today); the swap is localized to `transport.zig`.

## 3. Capability / bootstrap — owner authority (F27 posture) + detached-signature shape

- **§6.9a peer-authority seed bootstrap** (the F27/Phase-2 v0.5 resolution): at bootstrap (L0) the peer
  materializes a **self-owner capability** — a root cap, full scope over `/{peer_id}/*`, grantee = the
  peer's own identity — in the **§6.9a.0 detached-signature shape**: the cap token at the hex policy path
  `…/policy/{identity_hash_hex}` and its self-signature at the §3.5 invariant pointer
  `…/system/signature/{token_hash_hex}`. A `default` `system/capability/policy-entry` carries the fallback
  scope (the §4.4 discovery floor, or the degenerate `default → *` under `--debug-open-grants`).
- **authenticate-time derivation** unions the matched seed scope with the §4.4 discovery floor via the
  v7.64 dual-form lookup (hex → Base58 → `default`) — **not** a hardcoded initialGrants/openGrants fork
  (which §6.9a declares non-conformant). The seed-entry reader honors **both §6.9a.0 shapes** (verify the
  detached signature before trusting a token-shaped entry; trust a policy-entry scope template directly).
- **Detached-signature uniformity** (the keystone follow-on note): the generator uses the detached-signature
  shape uniformly for self-issued caps — bootstrap owner cap, `register` handler grants, and minted child
  caps all place the signature at `system/signature/{hash}`.
- Mint-time §6.2 subset check (`capability request`/`delegate`) is on the local frame; the dispatch chain
  walk applies the §PR-8/§5.5a per-link granter frame to the resource dimension.

## 4. New spec ambiguities

- **A-ZIG-006 ⚑** — §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403) request-time
  boundary. Implemented as a 3-way verdict (+ §5.5 unresolvable-grantee → 401 carve-out). **Fourth peer to
  independently hit this** (OCaml A-OC-008, arch F20) — strong convergence signal. → arch.
- **A-ZIG-003 RESOLVED** — threaded transport validated (above); S1 decision confirmed.
- **A-ZIG-007** (informational) — the no-GC peer-surface ownership contract (arena-per-request +
  clone-into-gpa); reusable Zig generator guidance, no wire probe.
- **A-ZIG-008** (deferral, not a guess) — full §9.5 53-type registry + the §7a `system/validate/*` handler
  bodies + entity-native dispatch deferred to S4 (S3 seeds a minimal type subset; the `--validate` opt-in
  and bootstrap are wired but bodies land in S4).

(No new *codec* ambiguity; the A-ZIG-001 identity-multihash reading is implemented as the canonical
construction in `identity.zig`.)

## Idiom seams (deliberate, vs C#/TS/OCaml)

- **No GC** — explicit `std.mem.Allocator` everywhere; `Entity`/`Envelope` author a caller-frees contract
  with `defer`/`errdefer`; dispatch uses a per-request arena, response cloned into the long-lived gpa.
  Free-correctness is a **first-class conformance concern** the GC'd peers never had (every test + the
  smoke is leak-checked).
- **Error unions** (`!T` over error sets) — no exceptions (C#/TS), no result ADT (OCaml). Builders carry a
  narrow `BuildError` (codec only); transport carries the I/O errors.
- **`std.Thread`** concurrency (not Task/Promise/eio) — A-ZIG-003.
- Zig naming: `PascalCase` types, `camelCase` fns, `snake_case` values/files.

## Exit criteria

Peer compiles clean · reads as Zig (not transpiled) · smoke green over real TCP · S2 codec regression
unbroken (69/69 + all unit tests leak-clean) · container reproducible (`--network=none`, std-only).
**S3 PASS.**

## What S4 (`--phase verify`) should run first

The **`validate-peer connectivity` category** (TCP connect, hello→authenticate, EXECUTE/EXECUTE_RESPONSE,
request_id echo) — it is the live-oracle superset of this S3 smoke and the cheapest first signal; then
land the full §9.5 53-type registry + byte-diff (the `type_system` category, A-ZIG-008) and the §7a
`system/validate/*` handler bodies + entity-native dispatch before driving `encoding`/`type_system`/`origination`.
