<!-- current-pin-banner:c34abcae04c4 -->
> **CURRENT (2026-09-03) — spec snapshot `v0.8.2.3`, executed check set `c34abcae04c4…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **758 total · 317 pass · 336 warn · 0 FAIL · 105 skip** (elapsed 8502 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.
>
> **Everything below this line predates this measurement and is retained as build
> history.** Where it disagrees with the figures above, the figures above win;
> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.

---

# entity-core-protocol-unison — Conformance Report

**Peer:** #43 (Unison, operator-directed) · **Spec basis:** `spec-data/v0.8.0` (V8)

Two gates, both green:

| Gate | Oracle | Verdict |
|---|---|---|
| **S4 live peer** (`validate-peer --profile core`) | `entity-core-go` **`cc1970f`** | **`682·0F @ cc1970f`** — `Result: PASS`, 0 FAIL |
| **S2 codec** (ECF corpus, byte-identity) | `conformance-vectors.cbor` (SHA-pinned) | `71·0F` — 71 PASS / 0 FAIL, unregressed |

---

# Part 1 — S4 live-peer conformance (the gate)

**Verdict: `682·0F @ cc1970f`** — `Result: PASS` (with warnings), **0 FAIL**.

| | Pass | Warn | Fail | Skip | Total |
|---|---|---|---|---|---|
| **`--profile core`** | **292** | **294** | **0** | **96** | **682** |

- **Oracle:** `validate-peer` built from `entity-core-go` **`cc1970f`**
  (`cc1970f448e01b0eea8d8032e076f50b571359ed`), core-gate fingerprint
  `8261a033fe1af56b1973fefb07ba8fcbdfd0867c17707275dbbd453bdc9bf745`, verified against
  `tools/oracle-pin.env`. **Not re-pinned** — measured at the same pin the whole 42-peer
  cohort is certified at, so the number is cohort-comparable.
- **Gate:** `validate-peer -addr 127.0.0.1:7777 -profile core` — the single-flag V7 v7.72
  §9.0 core profile. No hand-maintained category list, and **no `-allow-skip` argument
  was passed**: all 96 skips are *oracle-emitted* §9.0 carve-outs, not peer-requested
  exemptions.
- **Peer:** `peer_id 2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`, launched
  `--name conformance --validate --debug-open-grants`. Elapsed ~30 s.
- Raw oracle output: `CONFORMANCE-REPORT.json`.

Reproduce (in-container, under caps, sealed-offline):

```
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -e INCONTAINER=1 \
  -v "$PWD":/work:Z -w /work/protocol-generator/unison \
  localhost/entity-core-keystone/unison-toolchain:latest \
  sh /work/protocol-generator/unison/run-s4.sh
```

## Honesty statement

- This is the **`--profile core`** gate (core Layers 0–4), **not** `--profile full`. No
  standard extension is implemented; extension categories are carve-out skips.
- The number is **oracle-pinned and reproducible** — never a bare percentage.
- entity-core-protocol-unison is a **keystone-generated peer**: it shares a generation
  lineage with the rest of the cohort. Passing the same author's vectors as 42 sibling
  peers is **cohort-consistent, not independent convergence** — it is not evidence of
  the kind the ground-up `entity-core-{go,rust,py}` implementations provide.
- **294 WARN do not block** and are not hidden: 292 are `type_system` non-§9.5-floor
  (extension) type vocabulary, matched-if-present — a core peer deliberately does not
  pre-publish extension vocabularies. The other two are itemized below.
- Crypto **agility (Ed448 / SHA-384) is deferred** (A-UN-001): Unison's managed runtime
  has neither builtin and no C-FFI escape hatch. `crypto_agility` 4/4 and
  `format_agility` 10/10 pass at the **core floor** (Ed25519 + SHA-256); the agility
  corpus is out of scope for this peer's gate and is counted as neither PASS nor FAIL.

## Core-gate categories (all 0 FAIL)

| Category | Pass | Warn | Fail | Skip |
|---|---|---|---|---|
| `connectivity` | 22 | 0 | **0** | 0 |
| `encoding` | 6 | 0 | **0** | 0 |
| `type_system` | 108 | 292 | **0** | 0 |
| `handlers` | 35 | 0 | **0** | 32 |
| `capability` | 12 | 0 | **0** | 0 |
| `tree_operations` | 24 | 1 | **0** | 31 |
| `security` | 28 | 0 | **0** | 1 |
| `multisig` | 11 | 0 | **0** | 0 |
| `concurrency` | 5 | 0 | **0** | 0 |
| `resource_bounds` | 2 | 1 | **0** | 0 |
| `universal_address_space` | 8 | 0 | **0** | 0 |
| `peer_canonicalization` | 7 | 0 | **0** | 0 |
| `format_agility` | 10 | 0 | **0** | 0 |
| `crypto_agility` | 4 | 0 | **0** | 0 |
| `negotiation` | 4 | 0 | **0** | 0 |
| `authz` | 6 | 0 | **0** | 2 |
| `origination` | 0 | 0 | **0** | 1 |

## Every skip, explained + allow-listed

All 96 skips are emitted **by the oracle itself** under the V7 v7.72 §9.0 profile
carve-out, which reports them as *"exempt from the FAIL gate"*. The peer requested no
exemptions.

| # | Where | Oracle's stated reason | Assessment |
|---|---|---|---|
| 30 | whole categories | `outside --profile core (V7 v7.72 §9.0 — extension-only category)` | Correct: `subscriptions, continuations, revision, auto_version, clock, history, query, local_files, compute, entity_native, attestation, quorum, identity, role, behavioral_role, behavioral_v33, durability, type, content, serving_mode, transport_family, session, published_root, registry, discovery, relay, publish_fetch_http_poll, peer_issued, encryption`, + `origination` (reference-peer-gated — run separately, see below). A core peer implements none of these. |
| 32 | `handlers` | extension-handler probes (`handler_inbox_*`, …) outside core | Correct: these target extension handlers a core peer never registers. The four MUST core handlers are fully covered by the 35 PASS. |
| 31 | `tree_operations` | `EXTENSION-TREE §9 op skipped under --profile core (§9.5a)` | Correct: `snapshot_* / diff_* / extract_* / merge_* / tracking_*` are EXTENSION-TREE ops. The six `CORE-TREE-*` vectors are inside the 24 PASS. |
| 1 | `security` | `targets system/subscription (extension); core peer 404s before §5.4 fires per §6.5 resolution-first` | Correct — and the oracle names its core twin, `handler_scope_denied_core_1`, which **passes**. |
| 1 | `authz` | `targets system/role (extension); core peer 404s before PR-8.2 fires` | Correct; the core twin (`§A4-AUTHZ` scope-exceeds + deny-default) passes. |
| 1 | `authz` | `expects ROLE §5.5 401 capability_revoked (extension vocabulary); core peer's revocation denial is 403 capability_denied (v7.71 §5.2 step-4 default)` | Correct; core twin `authz_revoked_core_1` **passes**. 403 is the core-correct status. |

**No skip masks an unimplemented core primitive.** In particular `multisig` has **0 skips
and 0 warns** — see the accept-path proof below.

## The two non-`type_system` WARNs

| WARN | Oracle detail | Disposition |
|---|---|---|
| `resource_bounds / r3_connection_flood` | *"opened all 256 connections without refusal and peer kept serving — admission likely delegated externally (systemd / proxy / OS); §4.10(c) SHOULD, not gated"* | §4.10(c) is a **SHOULD**, not gated. The peer stayed up and kept serving throughout — the collapse the check guards against did not occur. Same shape as the Go reference peer. |
| `tree_operations / cleanup` | *"failed to remove test entity (non-critical)"* | Oracle-side teardown of its own fixture; explicitly non-critical. No peer defect. |

## Multisig accept path (the vacuous-green guard)

The `multisig` category is largely rejection-only (malformed → 403), so a fail-closed
peer can pass it *without* implementing K-of-N. Two independent pieces of evidence that
this peer's accept path is real:

1. **The oracle exercises it at this pin.** `valid_2of3_peer_signed_accepted` is among
   the 11 PASS. It was a **FAIL** before the §3.6 multi-granter implementation landed
   (`peer rejected (403) a VALID 2-of-3 multi-sig cap it co-signed — fail-closed on
   multi-granter rather than a genuine K-of-N implementation`) and passes after. The
   category is therefore **not** vacuously green here.
2. **A peer-side unit in the accept direction — AUTHORED, NOT YET VERIFIED.**
   `transcripts/multisig-test.md` builds a 2-of-3 multi-granter capability with two valid
   co-signatures and asserts `VAllow`, paired with a **negative K-of-N control**: the same
   capability carrying only ONE signature must `VDeny`. The control is what would prove
   threshold arithmetic rather than fail-open. Intended verdict line:
   `MULTISIG-ACCEPT-UNIT PASS (2of3=VAllow, 1of3=VDeny)`

   **Status: UNVERIFIED.** No passing run of this unit exists on disk. The last recorded
   output (`multisig-test.output.md`) ends in a transcript failure — a Unison *parse*
   error in the test code (`I was surprised to find a ( here`), not a peer defect — and
   the driver was edited afterwards without a re-run. Two subsequent verification attempts
   were killed by the operator before completion (host-stability work). **Leg 1 alone is
   what currently substantiates the accept path**, and leg 1 is sufficient for the gate:
   the oracle's own accept vector passes, and it demonstrably failed before K-of-N landed.
   This leg is belt-and-braces and is tracked as open — do not cite it as evidence until a
   green run exists.

## Origination-core (reference-peer-gated)

`origination` honest-SKIPs in the single-peer `run-s4.sh` (it requires a
`-reference-peer`). Run separately via `run-origination-core.sh` with the Go
`entity-peer` as B-role:

```
origination   3 pass  0 warn  0 fail  0 skip     Result: PASS
  PASS reference_connect
  PASS reference_ready
  PASS dispatch_outbound_reentry     GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2
```

**`dispatch_outbound_reentry` 3/3** — the §6.11 reentry seam (fork + MVar + per-request
`Promise` demux) verified cross-impl against the Go reference.

---

# Part 2 — S2 codec conformance (preserved; unregressed)

**Corpus:** `shared/test-vectors/ecf-conformance/conformance-vectors.cbor` (SHA-256
`9695b1f1…f7c6dc`, MANIFEST-pinned; re-derived + checked in-harness).

```
Result: PASS — 71·0F   (71 PASS / 0 WARN / 0 FAIL / 0 SKIP)
```

Every ECF conformance vector is byte-identical on `encode_equal` (encode / construct ==
`canonical`) and correctly REJECTED on `decode_reject`. The Unison peer is a substrate
the Go `wire-conformance` oracle cannot drive in-process; ground truth is the shared
byte-pinned fixture corpus, asserted by the headless transcript harness
`transcripts/conformance.md` → golden `transcripts/conformance.output.md`
(`"PASS 71/71  sha_ok=true  vectors=71"`, `failIds = []`).

## Per-category breakdown (71 vectors)

| Category | Kind | N | Result |
|---|---|---|---|
| `float` | encode_equal | 14 | 14 PASS — f16/f32/f64 shortest ladder incl. Rule 4a specials (±0, ±Inf, NaN=`f97e00`), f32 boundary (65503→f32), f64 (1.1) |
| `int` | encode_equal | 14 | 14 PASS — major-0/1 minimal head to 2⁶³-1 and negative analogs |
| `map_keys` | encode_equal | 6 | 6 PASS — length-then-lex over ENCODED key bytes (text, byte, mixed, boundary) |
| `length` | encode_equal | 8 | 8 PASS — definite-length only; empty containers |
| `primitive` | encode_equal | 6 | 6 PASS — bool/null; empty string/bytes |
| `nested` | encode_equal | 6 | 6 PASS — deep nesting, entity/envelope carrier, F29 array-of-maps head boundary |
| `tag_reject` | decode_reject | 5 | 5 PASS — tags 0/1/37/55799 + nested-in-`included` (N2 scanner) |
| `content_hash` | encode_equal | 4 | 4 PASS — `varint(fmt)‖SHA256(ECF{type,data})`; incl. synthetic code 128 (2-byte varint, N1) |
| `peer_id` | encode_equal | 3 | 3 PASS — `Base58(varint(kt)‖varint(ht)‖digest)`; incl. synthetic key_type 128 (N1) |
| `signature` | encode_equal | 3 | 3 PASS — deterministic Ed25519 over `ECF{type,data}`; pubkey derived in-band (A-UN-009) |
| `envelope` | encode_equal | 2 | 2 PASS — `system/envelope/v1` root+included, hash-keyed map |

## Pinned invariants (N1–N4 + fixed-width) — covered

Direct unit coverage in `transcripts/selftest.md` → `selftest.output.md` (all PASS),
complementing the corpus vectors that also exercise each:

- **N1** varint LEB128 (not fixed byte): `varintEncode 128 → 8001`, `300 → ac02`, `127 → 7f`;
  corpus `content_hash.4` (fmt 128) + `peer_id.3` (key_type 128).
- **N2** recursive major-type-6 tag reject: top-level `d9d9f7`, inside array elem (`81c001`),
  nested in map value (`a1616bc001`); corpus `tag_reject.1–5` incl. depth-nested `included`.
- **N3** empty map == `0xA0` (and empty array == `0x80`); corpus `length.2`, `content_hash.1`.
- **N4** entity fidelity: decode→encode byte-identical for canonical input (no lossy
  re-serialize); byte strings forwarded verbatim.
- **Fixed-width [2⁶³, 2⁶⁴-1]** (A-UN-003): `VUInt 2⁶³`→`1b8000000000000000`,
  `VUInt 2⁶⁴-1`→`1bffffffffffffffff`; largest nint magnitude `VNInt 2⁶⁴-1`→`3bffffffffffffffff`
  (the -2⁶⁴ case `Int` cannot hold — carried as the wire ARG in a `Nat`).

## Reproduce (headless, offline)

```
. tools/podman-caps.sh
podman run --rm --network=none $PODMAN_RUN_CAPS -v "$PWD":/work:Z \
  -w /work/protocol-generator/unison localhost/entity-core-keystone/unison-toolchain:latest \
  ucm transcript transcripts/conformance.md
# → "PASS 71/71  sha_ok=true  vectors=71",  failIds = []
```
