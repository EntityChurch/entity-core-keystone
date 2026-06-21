# entity-core-protocol-prolog — Phase S1 (Profile) Summary

**EXPERIMENTAL PROBE** (logic / declarative paradigm — the
FIRST logic-programming peer) · **Status: COMPLETE (authored; container NOT built —
S1 boundary). Idiom-fit verdict: lean DOCUMENT-AND-DEFER.**

## What this S1 is (and is not)

This is a **paradigm probe**, not a committed cohort build. The explicit S1 job was to
(a) author the FULL profile set from real design work, and (b) make an HONEST go/defer
call on whether byte-exact framed-TCP binary I/O + canonical CBOR can be expressed in
SWI-Prolog without the logic-programming idiom being swamped by imperative scaffolding.
Both are done. **The verdict (arch/PROFILE-RATIONALE.md "Does this idiom map?") leans
DEFER** — read that section; it is the deliverable that matters most.

## Preconditions resolved at session start
- **Spec version.** Latest `spec-data` snapshot is now a real **v7.75** snapshot
  (header reads "Version: 7.75" — newer than CL's v7.72 read). Profile + codec derive
  from `spec-data/v7.75`. Codec corpus v7.75; SHA-stability of the codec docs across
  v7.71→v7.75 is an S2 verify (A-PL-009).
- **No-build discipline (S1 boundary).** swipl is NOT runnable at S1 (no podman, no
  build, no toolchain run). SWI-Prolog library availability (library(crypto) ed25519/
  ed448/sha, library(socket/thread/dcg/plunit)) is asserted from SWI documentation and
  flagged for S2 confirmation against the running image (A-PL-002/003/008) — the honest
  posture, same as CL's "confirm the exact ironclad symbol at S2."
- **Cohort-settled traps pre-resolved in the profile** (do NOT re-burn): §1.5 peer_id
  canonical form `hash_type=0x00` raw-pubkey (A-PL-010, confirmed §1.5 line 459);
  lowercase `%02x` hex tree-paths (A-CL-009); §5.2 401/403/401-unresolvable; entity
  `data` arbitrary ECF value not necessarily a map (A-JAVA-010); §4.10 chain-depth
  pre-check → **400 chain_depth_exceeded** (depth 64), 16 MiB → 413 payload_too_large;
  §7b store-race-safety + TCP_NODELAY + no blocking syscalls.

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** floor, **ffi documented + likelier** fallback | FFI more probable here than any prior peer (Ed448 + possible codec) |
| CBOR | **hand-rolled as a DCG** | no SWI pack gives ECF (A-005, 7th peer); DCG idiomatic for structure, NOT for canonical side conditions (A-PL-004) |
| Ed25519 | **library(crypto)** (OpenSSL-3, bundled) | native, no pack dep; S2-verify the predicates (A-PL-002) |
| **Ed448** | **FFI-fallback-likely** (C-ABI) OR library(crypto) if OpenSSL-3 Ed448 exposed | corroborates A-OC-002 / A-ZIG-002 a 4th time (A-PL-003) |
| SHA-256/384 | library(crypto) crypto_data_hash/3 | most certain crypto surface |
| base58 / varint | hand-rolled (varint DCG-described) | dep-minimization |
| Integers | **native GMP bignum** | NO uint64 head-form trap (matches CL/Elixir) |
| Error model | **failure + ISO exceptions** | two-level logic-paradigm seam; det discipline load-bearing (A-PL-005/006) |
| Concurrency | **SWI native OS threads** (library(thread)) | one-thread-per-conn + message-queue demux; store = clause DB + with_mutex RMW (A-PL-007) |
| Naming | snake_case atoms / PascalCase vars | LANGUAGE-ENFORCED (var=uppercase rule), not style |
| Build / pkg | consult + SWI `pack` + hand-rolled harness | plunit bundled, optional |
| License | Apache-2.0 | S9 default |

## Container
`containers/prolog-toolchain/Containerfile` **authored, NOT built** (S1 boundary).
fedora:43 → prefer the distro `swi-prolog` package IF it is on the **9.2.x stable line**
(A-PL-008), else source-build the pinned 9.2.9 tag (commented fallback block).
library(crypto) links the image OpenSSL 3.x. Build asserts: swipl on the 9.2.x line;
library(crypto) floor (sha256/sha384 + ed25519 sign/verify) present and fails closed if
not; ed448 probed and REPORTED present/absent WITHOUT failing (FFI fallback per A-PL-003);
bundled socket/thread/dcg/plunit present. Pins (S11): swipl 9.2.9 (2024-09, ~21mo, stable
LTS line); OpenSSL image-provided (fedora:43 3.x).

## Ambiguity log
10 entries (A-PL-001..010). Headline:
- **A-PL-001** — the probe's core question; full S1 design + the **lean-DEFER verdict**.
- **A-PL-004** — canonical-CBOR side conditions (map-key ordering + shortest-float)
  RESIST the DCG idiom; the load-bearing paradigm finding gating go/defer.
- **A-PL-003** — Ed448 likely needs OpenSSL-via-FFI; 4th corroboration of A-OC-002/
  A-ZIG-002 outside BouncyCastle languages.
- **A-PL-010** — peer_id §1.5 canonical form; SETTLED on v7.75 (v7.73 E1 already
  reconciled §7.4), baked in proactively.

No blocking-severity items.

## Idiom-fit verdict for Prolog (the S1 deliverable that matters)
**Lean DOCUMENT-AND-DEFER.** A core peer is ~70–80% byte-exact I/O + canonical-encoding
side conditions + forced-deterministic locked-store mutation (all irreducibly
imperative), and ~20–30% genuinely-relational logic (CBOR structure as DCG,
chain-walking, unification decode). The relational parts are elegant and a real probe,
but sit on a thick imperative substrate that reads as "C with `:-`", and the two
canonical CBOR guarantees actively resist the one idiom (DCG) that would have carried
the codec. The logic-programming idiom survives in pockets but does NOT characterize the
peer — which fails the experimental question's bar. **Recommendation: DEFER**, with a
narrow GO gated on an S2 `cbor.pl` spike of the `map_keys` + `float` vectors (if those
predicates stay readable, proceed honestly framing the I/O as imperative-by-necessity;
if they dominate, fall back to `codec_strategy = "ffi"` — a defensible but weaker
probe). Defer is a VALID, clean outcome and is the recommended call. Full reasoning in
arch/PROFILE-RATIONALE.md.

## Exit criteria
profile.toml fully populated (no TBD-blocking — only `repository_url` empty,
TBD-on-first-publish, same as OCaml/Elixir/CL) · rationale written WITH the candid
"does this idiom map?" go/defer section · container **authored** (build deferred to S2
per the S1 boundary) · ambiguity log has no blocking-severity items (A-PL-002/003/008/009
are S2 verification tasks gated by Containerfile assertions; A-PL-001 is the go/defer
verdict, an operator decision). **S1 PASS.**

## What S2 (codec) needs to know going in — IF the narrow-GO path is taken
1. **Build the container first** and resolve A-PL-008 (fedora:43 swipl patch on the
   9.2.x line, else source-build) + A-PL-002 (library(crypto) ed25519/sha predicates) +
   A-PL-003 (ed448 present in library(crypto)? — if not, FFI). The build assertions
   catch all three.
2. **Spike `cbor.pl` FIRST — this is the gating decision, not a step.** Hand-roll ONLY
   the CBOR DCG + the two canonical side conditions (length-then-lex map ordering via
   encode→predsort-on-encoded-bytes→emit; shortest-float f16/f32/f64 ladder via IEEE-754
   bit manipulation) and push the `map_keys` + `float` vectors through it. If readable →
   proceed. If those two predicates dominate/get ugly → **fall back to FFI** (consume the
   C-ABI canonical layer; Prolog owns only the relational chain/dispatch logic). This
   spike IS the go/defer confirmation.
3. **Enforce determinism** (`once`/cut/`det`) at every codec/transport entry — the
   wire is a function, the engine's backtracking is a hazard (A-PL-005).
4. **Wrap every store RMW in `with_mutex/2`** (A-PL-007) — the Zig/CL store-race lesson.
