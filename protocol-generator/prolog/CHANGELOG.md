# Changelog — entity-core-protocol-prolog

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note (A-PL-019):** SWI's pack version grammar (`prolog_pack:is_version/1`) is
> dotted-NUMERIC only — stricter than SemVer AND stricter than RubyGems: it rejects
> `0.1.0-pre`, `0.1.0pre`, `0.1.0_pre`, `0.1.0-alpha.1`, `0.1.0-1` (all INVALID; only
> `0.1.0` is VALID, verified in-container). So `pack.pl` carries the parseable `0.1.0`
> while the release LINE below is `0.1.0-pre`. The `-pre` marker lives here + in README.md,
> NOT in `pack.pl`. (The SWI analogue of CL A-CL-010 / Ruby A-RUBY-010 — the third cohort
> ecosystem whose version grammar disagrees with the SemVer dash, and the strictest.)

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75** (the §6.13 register / §6.9a owner-cap /
§7a peer surface AND the §4.8/§4.9/§4.10 substrate floor); **codec corpus v0.8.0**
(byte-identical v7.56→v7.71 per the MANIFEST). Oracle pin: `entity-core-go @75c532e`.

First release line. **Peer #13 — the cohort's FIRST logic-programming peer** (SWI-Prolog:
SLD-resolution over a Horn-clause database, unification, backtracking, the cut). Derived
spec-first, **codec/crypto floor over the C-ABI** (`strategy = "ffi"`), Prolog owning the
relational core. Not yet published — parked at `-pre` pending architecture v0.1 sign-off +
first external SWI-Prolog consumer (S5 promotion gate).

This peer is the only one in the cohort that expresses the protocol's operational semantics
as a **convergent logic layer** (the operator goal): the §5.5 capability chain as a recursive
relation, the §5.2 trichotomy as guarded clause heads, §6.5/§6.6 dispatch as a multi-head
clause table, and the §3.9 store as the clause database itself. See
`status/IDIOM-FINDINGS-SYNTHESIS.md`.

### Conformance
- `validate-peer --profile core`: **PASS** — **653 / 291P / 269W / 0F / 93S**
  (machine-verified `summary.failed == 0`), oracle `entity-core-go @75c532e`. All 16 core
  categories 0-FAIL. (653 vs the v7.75 8-peer-rerun's 576 = later-oracle extension categories
  that auto-skip under `--profile core`; the FAIL gate + core categories are unchanged.)
- Codec (S2): **69/69** byte-identical to `conformance-vectors-v1`, through the foreign codec.
  Crypto KAT 10/10 (Ed25519/Ed448 RFC-8032 + SHA-256/384).
- §9.5 53-type floor: **53/53** byte-identical (content_hash recomputed by the C-ABI codec
  through the Prolog surface, asserted equal to the Go reference @75c532e — not ingested).
- S3 two-peer loopback smoke: **11/11** (handshake + dispatch + capability + 8-way request_id
  demux + emit hook + §7a echo).
- origination-core: **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).

### Added
- **FFI byte-floor over `libentitycore_codec` (C-ABI v1.1).** Canonical-CBOR (ECF)
  encode/decode, content_hash, peer_id, Ed25519/Ed448 sign/verify/seed→pubkey, SHA-256/384 —
  all sourced from the C-ABI through a SWI foreign-predicate shim (`c/ec_codec_pl.c` →
  `ec_codec_pl.so`, loaded with `use_foreign_library/1`; NO external `ffi` pack). The data-value
  canonical CBOR layer (`ec_cbor.pl`) is owned by the peer (A-PL-013: the C-ABI treats `data`
  as opaque pre-encoded bytes — even an FFI peer owns data-value canonicalization).
- **Determinism discipline (A-PL-005):** every public codec predicate is `once/1`-wrapped — the
  wire is a function, no choice point leaks across the codec boundary.
- §1.5 size-cutoff peer_id construction (Ed25519 → `key_type 0x01`, `hash_type 0x00`
  raw-pubkey identity-multihash; Ed448 → `key_type 0x02`, `hash_type 0x01` SHA-256-of-pubkey),
  following the §1.5 canonical-form table (A-PL-010 / A-PL-012; key_type byte corrected to 0x01
  at S4, A-PL-010a).
- §4.1 handshake; **§6.5/§6.6 dispatch as a MULTI-HEAD CLAUSE TABLE** (`handle_op/4`) — each
  `(handler, operation)` pair is its own clause head, "unknown → 501" is the final catch-all
  clause (the clause DB IS the router; A-PL idiom).
- **§5 verification core as the relational idiom:** §5.5 chain walk as a recursive relation
  (`verify_capability_chain/4` + `verify_chain/3` — conjunction-failure IS the deny), §5.2
  auth/authz trichotomy as guarded clause heads (`verify_request/4`), §4.10(b) chain-depth
  pre-check as bounded recursion → 400 `chain_depth_exceeded` (the v7.75 ruling), §3.6 multisig
  K-of-N as a quorum count over distinct signers, §5.6 attenuation + §5.7 delegation caveats.
- **§3.9 store as the clause database** (`content_fact/3` + `tree_fact/3` dynamic predicates;
  store ops ARE `assertz`/`retract`); every read-modify-write inside `with_mutex/2` (A-PL-007).
  Emit bus (§6.10/§6.13(c)) with live zero-consumer hooks (consumers are themselves clauses).
- TCP transport (L4): one native thread per connection, the §6.11 `request_id → message_queue`
  demux (N6/N7), the §6.13(b) outbound reentry seam (A-PL-018: module-qualified closure term).
- §7a conformance handlers (`--validate`): `system/validate/echo`,
  `system/validate/dispatch-outbound`.

### Known limitations / honest notes
- **The byte-floor reads as "C with `:-`," by design (A-PL-014).** Framed binary TCP I/O
  (`read_frame`/`write_frame`) and the shortest-float ladder are irreducibly imperative — that
  is the FFI floor's job, no different from the C peer. The protocol does NOT resist Prolog;
  only the floor does. This vindicates the revival decision (see IDIOM-FINDINGS-SYNTHESIS.md).
- **Three benign WARNs** (whole-cohort behaviour, not core MUSTs, not FAILs):
  `concurrency.t1_1_concurrent_demux` (no parallel speedup observed — informational, the real
  no-head-of-line MUST `t1_3` PASSes); `resource_bounds.r3_connection_flood` (connection
  admission is an external SHOULD); `tree_operations.cleanup` (the oracle's own teardown).
- **Crypto-agility full MATRIX deferred (cohort-wide).** Ed25519 + Ed448 + SHA-256/384
  primitives are byte-proven (KAT 10/10) and the connect-path agility slice is exercised; the
  M2/M3/M6 key-type × hash-format cross-product harness is the documented non-v0.1 item.
- Public surface is documented, not compiler-enforced — SWI has no module-private keyword
  beyond the module export list; the export lists in `prolog/ec_*.pl` ARE the surface.
- SWI pack `version` cannot carry a pre-release suffix (A-PL-019) — see the version note.
- The C-ABI oracle ELFs (`output/s4-oracles/`) and the built `.so`/`.o` artifacts are
  gitignored (large binaries / byte-built floor), not committed — sources + run scripts are.

### Spec items surfaced (logged in status/SPEC-AMBIGUITY-LOG.md)
- **A-PL-006** (the genuinely-Prolog finding) — the failure-vs-exception boundary: relational
  FAILURE is the idiomatic dominant "deny" channel (the §5.5 walk), but the §5.5 401
  unresolvable-grantee carve-out needs a THROWN term because Prolog failure is mono-valued
  ("no"), it cannot say "no, specifically 401-no". Two-channel split. Developed in the synthesis.
- **A-PL-013** — the C-ABI `ec_encode_ecf` treats `data` as opaque; an FFI peer still owns
  data-value canonical CBOR. (Note for the other FFI peers; routed to arch.)
- **A-PL-011** — the public `ec_content_hash_with_format` rejects forward-compat format_code 128
  that the corpus pins; compose the prefixed hash from public symbols. (ABI-surface note.)
- **A-PL-002 / A-PL-003** (RESOLVED NEGATIVE) — SWI `library(crypto)` 9.2.9 exports NO
  `ed25519_*`/`ed448_*` predicates; the whole signature floor is an FFI obligation (SHA via
  `crypto_data_hash/3` works). This drove `strategy = "ffi"`.
- **A-PL-014 / A-PL-004** — framed I/O + shortest-float are the irreducibly-imperative floor
  ("C with `:-`"); legitimately the C-ABI's job. Paradigm-fit landscape signal.
- **A-PL-007 / A-PL-015 / A-PL-016 / A-PL-017 / A-PL-018** — SWI concurrency/module footguns
  (RMW needs `with_mutex`; cross-module callbacks need `meta_predicate`; global vars are
  thread-local; named-alias mutexes leak under churn → anonymous; the reentry seam must be a
  module-qualified term). Logic-paradigm-specific, recorded so maintainers don't regress them.
- **A-PL-019** (NEW, packaging) — SWI pack version grammar is dotted-numeric only, no
  pre-release channel; the SWI analogue of CL A-CL-010 / Ruby A-RUBY-010. **Owner: operator.**
