# Phase S1 — Go peer — Profile research + authoring

**Phase:** S1 (profile authoring only — NO podman, NO build, NO toolchain run)
**Peer:** Go (`protocol-generator/go/`) — **clean-room** peer (Go is the oracle's
language; see PROFILE-RATIONALE "Clean-room constraint").
**Spec read:** `spec-data/v7.75` (latest snapshot)
**Status:** ✅ COMPLETE — exit criteria met.

## Deliverables authored

- `protocol-generator/go/profile.toml` — complete, no `TBD` fields.
- `protocol-generator/go/arch/PROFILE-RATIONALE.md` — written, leads with the
  clean-room constraint + the honest limited-signal caveat.
- `protocol-generator/go/status/SPEC-AMBIGUITY-LOG.md` — initialized; 4 author-level
  items (A-GO-001..004), **zero blocking-severity**.
- `protocol-generator/go/status/PHASE-S1.md` — this file.
- Toolchain: **REUSED `containers/go/Containerfile`** as-is (adequate; not
  re-authored).

## Read order honored (per the brief)

1. `shared/lifecycle/PROMPT-CONSTANTS.md`
2. `shared/lifecycle/PHASE-S1-PROFILE.md`
3. Reference profiles: `csharp/`, `typescript/`, `zig/profile.toml` +
   `zig/arch/PROFILE-RATIONALE.md` (also skimmed `elixir/` for the GC-native codec
   shape). Language-neutral — studied WITHOUT touching the Go oracle.
4. `containers/go/Containerfile` — inspected, REUSED.
5. Seeded cohort memory (`MEMORY.md` + topic files: supply-chain pin, zig-peer,
   concurrency-gate-7b, v775-rerun).

## Clean-room discipline (how it was honored)

Read ONLY: the v7.75 spec snapshot, the keystone lifecycle contracts, the
language-neutral sibling profiles, the existing Go Containerfile, and cohort memory.
Did **NOT** open / read / grep / find any file under any `entity-core-go` checkout
(codec, validate-peer, wire-conformance, go.mod — none). Every protocol decision
grounds in a V7 §-pointer from the snapshot, never in oracle source. The oracle
commit `75c532e` (target 576·0F·89skip) is recorded for the S4 **byte-validation**
leg only — allowed; the clean-room rule is about not reading oracle *source* while
building.

## Key decisions

| Surface | Decision | Why |
|---|---|---|
| **Codec strategy** | `native` | A-005 pattern: ECF canonical layer must be owned regardless of any lib; stdlib crypto makes native the lighter (stdlib-only) path. Spike `map_keys.*`+`float.*` at S2 start. |
| **CBOR** | hand-rolled `internal/cbor` (rejected fxamacker/cbor, A-GO-001) | Lib's deterministic mode ≠ ECF's decode-side rejection / Rule-4a float16 / arbitrary-`data` fidelity; byte-exactness must be owned; keeps `go.sum` empty. |
| **Ed25519** | stdlib `crypto/ed25519` | In-tree, audited, RFC-8032 deterministic signing, zero module dep. |
| **Ed448** | DEFERRED (A-GO-002) | Not in stdlib AND not in `golang.org/x/crypto`; same gap as Zig/OCaml; floor unaffected; hybrid FFI-via-cgo when agility lands. |
| **SHA** | `crypto/sha256` (floor) + `crypto/sha512` (SHA-384 agility) | stdlib; native agility hashing (contrast the Ed448 gap). |
| **base58 / varint** | hand-rolled | Not in stdlib; stdlib-only stance; varint owned for §1.5 multi-byte + non-minimal rejection. |
| **Error model** | explicit `(T, error)` returns (`result` style); `%w`-wrapped, `errors.Is/As` discrimination | Go-native; no exceptions; panic = programmer-error only, recovered at goroutine boundary (§4.9 no-crash). |
| **Concurrency** | goroutines + channels; `sync.RWMutex` store; TCP_NODELAY | §6.11 demux by request_id; §4.8 store-safety from S3 (Zig/CL store-race lesson); Nagle-killer pre-resolved. |
| **Integers** | native `uint64`/`int64` | Clean — no BigInt (vs TS F7), no 63-bit trap (vs OCaml); nint band watch-item A-GO-003. |
| **Naming** | gofmt MixedCaps; all-caps initialisms (`PeerID`/`EncodeECF`) | Go style-guide MUST; constants MixedCaps not SCREAMING_SNAKE. |
| **Build/test** | `go` toolchain; stdlib `testing` table-driven | toolchain is the build system; zero test-framework dep. |
| **Toolchain** | REUSE `containers/go/Containerfile` | Adequate as-is (fedora:43 + golang-1.25.10 + git); nothing missing; dnf = reviewed channel → pin-for-repro, age-floor relaxed. |
| **License** | Apache-2.0 | S9 repo default; Go ecosystem mandates none. |
| **Spec** | v7.75 read; `--profile core` 576·0F·89skip target @ oracle 75c532e | latest snapshot; S4 byte-validation target. |

## Pre-resolved cohort traps (carried in, NOT re-burned)

All baked into the profile/rationale, grounded in the v7.75 snapshot:
- **peer_id §1.5** canonical `hash_type=0x00`, raw pubkey for ≤32B (ignore stale
  §7.4 SHA-256-form — §7.4 now parameterizes over the §1.5 table).
- **lowercase `%02x` hex** for §3.4/§3.5 tree-paths (A-CL-009).
- **§5.2 trichotomy** ALLOW / AUTH_DENY(401) / AUTHZ_DENY(403), `unresolvable_grantee
  → 401` carve-out.
- **`data` = arbitrary ECF value** (A-JAVA-010), not necessarily a map — codec
  encodes any ECF value.
- **§4.10** chain-depth pre-check → **400 `chain_depth_exceeded`** (NOT 403; depth
  64); over-size payload → **413 `payload_too_large`** (16 MiB).
- **§7b** data-race-safe `sync.RWMutex` store (§4.8), no blocking syscall under the
  lock, **TCP_NODELAY**.

## Ambiguities logged

A-GO-001 (CBOR lib vs hand-roll — operator), A-GO-002 (Ed448 gap — research/info,
mirrors Zig/OCaml), A-GO-003 (nint uint64-carrier — operator, wire unambiguous),
A-GO-004 (module-path placeholder — operator, publish-time). **None blocking.**

## Limited-signal read (honest)

This peer's idiom **equals** the oracle's (both Go, same stdlib crypto, same
hand-rolled canonical CBOR shape, same goroutine concurrency), so the **spec-
refinement signal is inherently bounded** — a same-language peer cannot stress the
spec along a novel axis the way the distant-idiom peers (Zig/OCaml/Lean/CL) did, and
convergence here is weak evidence (could be language-shared blindness). The value is
deliberately narrower and stated honestly: **(1) independent cross-check** — a
from-scratch Go impl landing byte-identical on the full corpus corroborates that the
*spec* (not an oracle-private convention) determines the bytes; **(2) idiom
completeness** — fills the Go slot with a *generated-from-spec* peer, exercising the
generator's Go output end-to-end. Net-new spec findings are NOT banked on; one would
be a bonus.

## S1 exit criteria — met

- [x] `profile.toml` every field populated (no `TBD`)
- [x] rationale doc written (with clean-room + limited-signal note)
- [x] container exists / specified (REUSED `containers/go`)
- [x] ambiguity log: no blocking-severity items
- [x] NO build / podman / toolchain run (authoring only)

## Next phase (S2 — NOT in scope here)

S2 codec build, in-container, opens with the spike: push `map_keys.*` + `float.*`
(incl. Rule-4a special floats) + `tag_reject.*` vectors through the hand-rolled
encoder/decoder before the full build, then byte-validate against the v7.75 corpus.
