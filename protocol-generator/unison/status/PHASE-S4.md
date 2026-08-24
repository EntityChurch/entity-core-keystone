# entity-core-protocol-unison — Phase S4 (Conformance) Summary

**Peer:** #43 (Unison, operator-directed) · **Spec basis:** v0.8.0 / V8 ·
**Phase:** S4 (live-peer conformance) · **Status:** COMPLETE —
**`682·0F @ cc1970f`**, `Result: PASS`, **0 FAIL**; origination-core **3/3**;
multisig accept path verified via the ORACLE's own `valid_2of3_peer_signed_accepted`
(the supplementary peer-side unit is authored but UNVERIFIED — see "Multisig accept-path
proof"). Container-bound, headless, `--network=none`.

Full verdict + per-category table + skip inventory: `CONFORMANCE-REPORT.md`.
Raw oracle output: `CONFORMANCE-REPORT.json`.

## Iteration count: 3 measured gate runs (+1 pre-gate enablement fix)

| Run | Verdict | FAIL | Notes |
|---|---|---|---|
| — | *(could not measure)* | — | **Enablement fix** — see H0 below; without it the harness could not detect readiness. |
| 1 | FAIL | **56** + 7 skips-as-FAIL | Baseline. Elapsed 58 s of a 60 s budget → 7 core categories never ran. |
| 2 | FAIL | **2** | All of B–J landed. Elapsed 35 s; every core category now runs. |
| 3 | **PASS** | **0** | K + L landed. Elapsed ~30 s. |

## H0 — pre-gate enablement (not a conformance defect)

The host's `LISTENING` banner never reached the harness: `io2.IO.putBytes` to a
**redirected** stdout is block-buffered, so the banner sat in the buffer while the peer
was in fact already listening. The harness's readiness loop timed out even on a healthy
peer. Fixed in `Host.u` by setting `io2.BufferMode.LineBuffering` on stdout before the
banner. **Generator-robustness datum**, not a peer bug (A-UN-018).

## What each fix addressed

### B — Ed25519 signing re-derived the public key on every signature (latency root cause)

`ed25519Sign` called `ed25519Pub seed` per signature — a full **pure-Unison** scalar
multiplication (255 twisted-Edwards point ops over 16-limb GF(2²⁵⁵-19) arithmetic) — even
though the pubkey is already precomputed once in `Identity.idPublicKey`. Every minted
capability, every handshake, every response signature therefore paid a **keygen**.

Signature changed to `ed25519Sign : seed -> pub -> msg`, with `signEntity` passing the
precomputed `Identity.idPublicKey`. Effect:

- `concurrency` 35.9 s → 10.7 s; total run 58 s → 30 s.
- Fixed `concurrency / t2_2_connection_churn` (*"cycle 15: handshake failed (peer may have
  degraded under churn)"*) — **not** a leak or a scheduling bug as first suspected; the
  handshake was simply too slow to keep up with churn.
- Fixed the **7 skips-that-counted-as-FAIL**: `resource_bounds`,
  `universal_address_space`, `peer_canonicalization`, `format_agility`, `crypto_agility`,
  `negotiation`, `authz` had all been skipped `budget_exhausted: prior categories consumed
  the -timeout window`. These were latent — a slow peer silently hides whole core
  categories behind the oracle's default 60 s budget. Resolved by making the peer fast,
  **not** by raising `-timeout`.

### C — full §9.5 53-type registry render (closes A-UN-012) → 37 FAIL

S3 shipped a name-only seed (`{name: …}`), so the oracle reported *"field X: REQUIRED
locally but MISSING remotely"* for every field of every type. `TypeDefs.u` rewritten as a
render-from-model registry: an `FSpec` field-spec algebra (`type_ref / optional /
array_of / map_of / union_of / key_type / byte_size`, omit-empty) + a `TypeDef` record
(`name / extends / fields / layout`), and all **53** core + operational + type-system
bootstrap definitions. Faithful port of the cross-blessed Haskell/C#/TS/OCaml/Zig
registry. Rendered through our own S2 codec (never ingested as fixture bytes); map-key
order is irrelevant because the codec sorts canonically. `type_system` 64P/37F → **108P/0F**.

### D — handler interfaces published no `operations` map → 3 FAIL

`handler_{connect,tree,capability}_operations_match` reported *"missing required
operations … (has [])"*. The bootstrap interfaces carried only `{pattern, name}`. Added an
`operations` map of `system/handler/operation-spec` values:
connect `[hello, authenticate]`, tree `[get, put, list]`,
capability `[request, revoke, configure, delegate]`, handler `[register, unregister]`,
type `[validate]` (the §3130 standard operation-name set).

### E — unregister left the grant signature bound → 1 FAIL

`core_register_unregister_signature_removed`: §3.4 writer/unregister symmetry requires
unregister to tear down **all five** register writes. We unbound only the handler and its
interface. Now the grant token is looked up at
`system/capability/grants/{pattern}` to recover its hash, then the signature pointer at
`system/signature/{token_hash}` and the grants path are unbound too.

### F — capability handler input validation → 2 FAIL

- `revoke_rejects_zero_token`: a revoke carrying the all-zero token returned 200. The
  zero hash is the reserved sentinel and is never a valid content hash → now `400
  invalid_token`.
- `configure_rejects_partial_prefix`: §3018 states partial-prefix matchers (`00abc*`) are
  NOT valid and impls MUST NOT accept them. Added `validPeerPattern` (see K for its
  correction).

### G — §1.4 caller-path validation → 4 FAIL

`path_reject_dot_relative`, `path_reject_dotdot_relative`, `path_reject_empty_segment`,
and both `core_tree_path_flex_1` sub-pins were accepted with 200. Added
`rejectCallerPath` (Model.u), applied to the tree handler's resource target on get **and**
put → `400 invalid_path`. Rejects: a null byte in any segment; a `./` or `../` prefix; an
interior empty segment (`//`), while still allowing a single trailing `/` (the listing
form); and a leading `/` **whose first segment is not a peer_id** — the §274/§268
distinction, so a genuine cached-remote absolute path `/{peer_id}/…` still passes through
unchanged rather than being re-qualified.

### H — §6.3 conditional write (CAS) → 5 FAIL

`expected_hash` was ignored entirely. Implemented the spec's three cases exactly
(lines 1307–1328): ABSENT → unconditional; PRESENT and non-zero → the current binding
MUST carry that hash, else `409 hash_mismatch` (including when the path is unbound);
PRESENT and the ZERO hash → CAS-create, the path MUST be unbound, else `409`. Fixes
`cas_mismatch`, `cas_preserves_binding`, `cas_absent_binding`,
`cas_create_zero_hash_exists`, `core_tree_put_cas_1`, `core_tree_put_cas_2`.

### I — deletion markers were visible in listings → 1 FAIL

`core_tree_delete_1`. Per `CORE-TREE-DELETE-1` a path bound to a `system/deletion-marker`
must be **omitted from listings** while `get` still returns the marker. `Store.listing`
now reads content alongside the tree and filters marker-bound entries. Deliberately did
**not** 404 the `get` — the spec says get returns the marker.

### J — §3.6 multi-signature granter / genuine K-of-N (closes A-UN-011) → 1 FAIL

`valid_2of3_peer_signed_accepted`: *"peer rejected (403) a VALID 2-of-3 multi-sig cap it
co-signed — fail-closed on multi-granter rather than a genuine K-of-N implementation"*.
The S3 floor denied any map-form granter. Implemented in `Capability.u`:

- `rootAtLocal` accepts a multi-granter root when the local peer is **one of the listed
  signers** (`mgLocalRoot`).
- `linkSigOk` dispatches on the granter's shape: bytes → the single-sig path (unchanged);
  map → `multiGranterOk`, which collects **all** signatures targeting the capability hash,
  counts how many **distinct listed signers** carry a valid signature (each verified
  against that signer's resolved `system/peer` public key), and requires
  `count >= threshold` with `threshold > 0`.
- `linkGranterPeer` frames a multi-granter link at the local peer.

### K — `peer_pattern` was over-restricted by F → 1 FAIL

Fix F implemented §3013 literally ("exactly one of two forms": `{caller_peer_hex}` or
`default`) and thereby **broke** `peer_pattern_2_lazy_canon_mint`, which requires
accepting a Base58 peer_id for an as-yet-unknown peer in the pending-canonicalization
state (v7.65 §3.6 rule 3). `validPeerPattern` now accepts `default`, a full 66-char
lowercase-hex hash, **or** a Base58 peer_id — while still rejecting `00abc*` (not hex,
not 46+ base58, not `default`). See finding **A-UN-015**.

### L — unsupported key_type surfaced as 401 identity_mismatch → 1 FAIL

`agility_unknown_1`: for `key_type=0xFD` at `handshake.authenticate` the peer returned
`401 identity_mismatch`; the vector wants `400 unsupported_key_type` (or 200). Cause: the
peer derives the expected peer_id under key_type `0x01`, so a peer_id minted under `0xFD`
simply fails the §4.6/§1.3 identity binding and surfaces as a mismatch — the unsupported
key type is never named. The `key_type` *field* does not catch it (0xFD has no canonical
string per §431, so the field is absent).

Added a Base58 **decoder** to `Protocol.u` (`b58MulAdd58` — the exact mirror of the
existing `b58AddByte` with the 256↔58 radices swapped) and `peerIdKeyType`, which recovers
the leading key_type varint byte from a presented peer_id. `authVerify` now rejects a
non-`0x01` key_type with `400 unsupported_key_type` **before** the identity check.
Decoder verified in isolation first: real ed25519 peer_id → `Some 1`; `[253,1,7,7]`
round-trip → `Some 253`. See finding **A-UN-016**.

## Multisig accept-path proof (the vacuous-green guard)

Two independent legs, because a rejection-only category can be passed by a fail-closed
peer that implements nothing:

1. **Oracle leg.** At `cc1970f` the `multisig` category **does** carry an accept vector —
   `valid_2of3_peer_signed_accepted` — and it is among the 11 PASS, having been a hard
   FAIL before fix J. `multisig` finishes 11P/0W/0F/**0 skip**.
2. **Peer-side unit leg** — `transcripts/multisig-test.md`, in the direction the oracle
   historically could not cover. Builds three identities, a
   `{signers:[h1,h2,h3], threshold:2}` multi-granter capability, and signs it with two of
   the three; asserts `verifyCapabilityChain → VAllow`. Paired with a **negative K-of-N
   control**: the identical capability carrying only **one** signature must `VDeny`. The
   control is the load-bearing half — it is what distinguishes real threshold arithmetic
   from a fail-open. Intended verdict:

   ```
   MULTISIG-ACCEPT-UNIT PASS (2of3=VAllow, 1of3=VDeny)
   ```

   Compiled to bytecode and run via `run.compiled`: the pure-Unison keygen ×3 is far too
   slow interpreted (the same B-family cost, in the transcript evaluator).

   **Status: UNVERIFIED — this leg did NOT run green and must not be cited as evidence.**
   The only output on disk (`multisig-test.output.md`) ends in a transcript failure: a
   Unison *parse* error in the test source (`I was surprised to find a ( here`, at the
   `msCapData` literal) — a defect in the TEST, not in the peer. The driver was edited
   after that failure without a re-run, so no passing artifact exists. Two later
   verification attempts by the overseer were killed mid-compile during host-stability
   work. **Leg 1 (the oracle's own `valid_2of3_peer_signed_accepted`) is what
   substantiates the accept path**, and it is sufficient for the gate — it was a hard FAIL
   before fix J and passes after. Leg 2 remains OPEN: fix the parse error, run it, and
   only then cite it.

## Origination-core

`run-origination-core.sh` — Unison target (A-role) vs the Go `entity-peer` reference
(B-role), one loopback, sealed-offline:

```
origination   3 pass  0 warn  0 fail  0 skip     Result: PASS
  PASS reference_connect · PASS reference_ready · PASS dispatch_outbound_reentry
```

**3/3.** The §6.11 reentry leg (fork + MVar + per-request `Promise` demux) is confirmed
cross-impl: the target originates an outbound EXECUTE back to the validator-as-B over the
**same** inbound connection without stalling its reader (N6).

## Findings

### Spec-shaped — route to architecture

- **A-UN-015 — §3013's "exactly one of two forms" contradicts v7.65 §3.6 rule 3.** §3013
  enumerates the policy `peer_pattern` forms as `{caller_peer_hex}` or `default` and adds
  *"No other pattern forms are defined"*. `PEER-PATTERN-2` requires **accepting a Base58
  peer_id** for an unknown peer in the pending-canonicalization state. A conformant-by-
  §3013 implementation fails the vector. Cost me a real iteration: I implemented §3013
  literally and it was rejected. Ask: have §3013 name the transitional Base58 form (or
  cross-reference §3.6 rule 3) so the enumeration is exhaustive as written.
- **A-UN-016 — the unsupported-key_type check's ORDER relative to the identity binding is
  unstated.** §426 mandates `400 unsupported_key_type`, and §4.6/§1.3 mandate the
  peer_id↔public_key binding, but nothing says which fires first. The natural
  implementation (derive the expected peer_id under the supported key_type, compare) makes
  an unknown key_type indistinguishable from an impersonation attempt and returns `401
  identity_mismatch` — plausible, and wrong per `AGILITY-UNKNOWN-1`. Same family as the
  already-landed F31 401-vs-404 auth-ordering ruling; asks for the same treatment: state
  that key_type support is validated **before** identity binding. Note the secondary
  consequence — since 0xFD has no canonical `key_type` string (§431), the only in-band
  signal is the peer_id's leading varint, so the check **requires a Base58 decoder** in
  every peer. That obligation is not called out anywhere.

### Research / cohort ledger — not spec defects

- **A durable lesson needs a pin-scoped correction.** The standing guidance says the
  `multisig` category is *"100% malformed→403"* and therefore vacuously passable. **At
  `cc1970f` that is no longer true** — the category ships `valid_2of3_peer_signed_accepted`
  and it is a genuine accept-path gate (it failed this peer until K-of-N was implemented).
  The *lesson* (add an accept-path unit the oracle can't cover) remains right; the *factual
  claim* about this category is stale. Worth correcting so no future peer treats a green
  `multisig` as automatically vacuous.
- **A slow peer silently hides whole core categories.** The oracle's default 60 s
  `-timeout` is a global budget: two slow categories consumed it and seven core categories
  reported `budget_exhausted` — which the gate counts as FAIL, but with a *skip* message
  that reads like a carve-out rather than a defect. Diagnosing this as *latency* rather
  than as seven independent category failures was the highest-leverage move of the phase.
  Worth carrying: **on any budget_exhausted skip, fix the peer's latency; never raise
  `-timeout`** — raising it would have produced a green report over a peer that degrades
  under connection churn.
- **Crypto-spectrum sharpening (extends A-UN-009).** On a native-sign / no-keygen-builtin
  substrate, the pubkey must be treated as **part of the identity**, derived once and
  carried. `sign(seed, msg)` is the wrong signature to expose on such a peer: it silently
  makes every signature cost a keygen. Cohort-relevant to any peer whose crypto tier is
  "native sign/verify, hand-rolled keygen".

### Generator-robustness datums (Unison idiom — extends the S3 list)

6. **Block-buffered stdout defeats banner-based readiness.** A redirected `putBytes`
   stdout does not flush the `LISTENING` line; set `BufferMode.LineBuffering` explicitly.
7. **A multi-line `match` inside a lambda argument breaks parsing** when further arguments
   follow (`foldl (acc v -> match v with …) [] l` → *"I was surprised to find a ["*).
   Extract the lambda to a named top-level helper. (Sharpens S3 datum 2.)
8. **A function application cannot break across lines before its argument** —
   `f "x"` ⏎ `(VMap […])` parses as a complete `f "x"` followed by a stray `(`. Bind the
   argument to a name first (the `helloData` pattern). (Sharpens S3 datum 3.)
9. **Interpreted vs compiled cost differs by orders of magnitude** for arithmetic-heavy
   pure code. The Ed25519 keygen is sub-second under `run.compiled` and minutes under a
   transcript watch expression — compile test mains to bytecode rather than `display`ing
   them.

## Exit criteria

`validate-peer --profile core` → **`Result: PASS`, 0 FAIL** (`682·0F @ cc1970f`,
292P/294W/0F/96S) · every skip oracle-emitted and explained, none peer-requested ·
working 2-of-3 multisig accept path (oracle vector `valid_2of3_peer_signed_accepted`,
a hard FAIL before fix J; the extra peer-side unit is authored but UNVERIFIED) ·
origination-core `dispatch_outbound_reentry` **3/3** · oracle not re-pinned, not doctored ·
S2 codec unregressed (71/71). **S4 PASS.**
