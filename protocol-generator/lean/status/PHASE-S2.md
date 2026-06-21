# entity-core-protocol-lean — PHASE S2 (codec + Track-B proofs) — COMPLETE

**Done by hand** (no sub-agents — the proof-vector peer
warrants direct attention). Builds + runs in `containers/lean-toolchain`
(fedora:43 + Lean 4.29.1), codec `.so` mounted at `/codec`.

S2 delivers both tracks: **Track A** (a conformant ECF codec) and the first slice
of **Track B** (machine-checked codec theorems). Track A is the floor and came
first; the proofs followed.

## Track A — the codec gate: 69/69, first harness run, byte-identical

`./.lake/build/bin/conformance` → **69 pass · 0 fail** against the locked v7.71
corpus (`shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`, sha
`41d68d2d…` re-derived in-harness). All 11 categories green, including Class B:
- `content_hash` — `varint(format_code) ‖ SHA-256(ECF{type,data})`, SHA-256 over
  the FFI boundary (`libentitycore_codec`, provenance `rust 0.1.0 / ecf-c-abi 1.1`).
- `signature` — deterministic Ed25519 seed-sign over `ECF{type,data}` via FFI.
- `peer_id` — `Base58(varint(key_type)‖varint(hash_type)‖digest)`, pure Lean.
- `tag_reject` — recursive major-type-6 rejection (§6.3 Option B) at any depth.

**Architecture (the S1 decisions, realized):**
- **Codec** (`src/EntityCore/Codec/`): pure-Lean canonical ECF. `buildValue` is a
  TOTAL structural encoder (length-then-lex map sort, minimal int head, full
  `UInt64`/-2⁶⁴ range, definite lengths) — and the T2/T3 proof surface. The
  decoder is `partial` (Track A floor; a kernel-reducible decode is a T1 Track-B
  refinement, deferred).
- **Bit-level float** (`Codec/Float.lean`): `Float.toBits`/`ofBits` are the SOLE
  `Float` contact; `widen16/32` + truncate-narrow + widen-compare exact-check are
  pure `UInt` bit arithmetic — the load-bearing S1 decision that makes T3 provable.
- **Crypto** = FFI-hybrid via the C-ABI shim (`ffi/ec_ffi_shim.c`): `ec_sha256`,
  `ec_ed25519_sign`. `@[extern]` opaque — the spec's own trust boundary.
- Two Lake targets: `src/` (peer, mathlib-free, **zero external deps**) and
  `proofs/` (Track B, also mathlib-free so far — core-Lean tactics sufficed).

**Operational review (beyond the 69 vectors — the codec-review-heuristic).**
Conformance-green ≠ bug-free, so I spot-checked the uncovered ranges + the FFI
reality directly (all confirmed):
- **Full integer range** (corpus tops out at `2⁶³-1`): `uint 2⁶⁴-1` →
  `1bffffffffffffffff`, `uint 2⁶³` → `1b8000000000000000`, `nint 2⁶⁴-1`
  (= -2⁶⁴) → `3bffffffffffffffff`, and `uint 2⁶⁴-1` round-trips through decode.
  No `Int`/`Int64` clamp — the uncovered-range trap is handled.
- **Canonical enforcement on DECODE** (not just encode): the decoder *rejects*
  non-canonical map order (`z` before `a`), duplicate keys, and a top-level tag
  (`0xC0…`) — confirmed returning errors, not silently accepting.
- **FFI is genuinely exercised** (not stubbed): the Class-B `content_hash` /
  `signature` vectors pass only because real SHA-256 / Ed25519 ran over the C-ABI
  (`ec_impl_info` printed `rust 0.1.0 / ecf-c-abi 1.1`); the dlopen boundary is live.

## Track B — the proof vector: T3 complete, T2 reflexivity, T1/T2-totality deferred

`lake build EntityCoreProofs` IS the proof check (a `sorry`/failed proof fails the
build). Every theorem's `#print axioms` reports **`[propext, Quot.sound]` only —
no `sorryAx`**. Full per-theorem ledger: `status/FORMALIZATION-REPORT.md`.

- **T3 (headline) — PROVEN, 7 theorems** over `encodeFloatBits` (the kernel-
  reducible bit core; the running encoder is `encodeFloatBits ∘ Float.toBits`):
  - gate soundness (`tryHalf_widens`, `trySingle_widens`): a narrow gate accepts a
    width only when it widens back bit-identically (Rule 4 value-preserve).
  - dispatch (`encode_uses_half/single/double`): exact case characterization — f16
    iff the f16 gate accepts, f32 iff f16 rejects ∧ f32 accepts, else f64.
  - **corollary: the encoder is LOSSLESS** — every emitted form widens back to the
    input bits exactly (the operationally critical property, fully proved).
  - Rule 4a specials (`encode_nan`, `encode_inf`): proven **parametric over the
    whole special class** — *every* NaN bit pattern (any sign/payload) → `F9 7E00`;
    *every* ±Inf → the matching f16. Stronger than sample-byte checks.
  - **The float ladder all nine cohort peers re-derived is now a theorem.**
  - ⚠ **Precision (read `FORMALIZATION-REPORT.md`):** what's proved is *lossless +
    correct dispatch*, NOT *strict minimality* — "narrowest **gate-accepted**"
    width, not "narrowest **possible**". Strict minimality needs gate
    *completeness* (`doubleToHalf (widen16 h) = h`), which holds for truncation +
    is confirmed by the 14 float vectors but is **not yet formalized**. Don't write
    "provably minimal" without that caveat.
- **T2 (reflexivity) — PROVEN, 3 theorems**: `lexCmp_self`, `keyCmp_self`,
  `keyLe_refl` — the canonical key comparator is reflexive (a sort never rejects
  equal keys spuriously). Symmetry-free; needs only `<`-irreflexivity.
- **T2 totality — DEFERRED (time-boxed).** `keyLe a b ∨ keyLe b a` reduces to a
  swap-antisymmetry lemma `lexCmp b a i = (lexCmp a b i).swap`. Routine math
  (byte-trichotomy), but Lean-4.29 `split_ifs`/`simp` would not fire on the
  swapped four-way `if`-nest after `fun_induction`; deferred as a scope boundary,
  not a defect. Totality is independently witnessed by 69/69 conformance (no
  incomparable keys arise) and the cohort.
- **T1 round-trip — DEFERRED.** `Canonical(b) → encode(decode b) = b` needs a
  kernel-reducible (total) `decode`; the shipped decoder is `partial`. A total
  decode (well-founded on unconsumed-input length) is the S3/Track-B refinement.

**No new S2 spec finding.** The proofs *confirm* the spec's float (Rule 4/4a) and
key-ordering rules are sound as written — the keystone-positive outcome for the
codec layer. The 1b candidate findings (A-LEAN-1..4) live in the verdict/
attenuation layer (S3), not the codec; they re-confirm or drop when T4/T5 are
attempted. The decoder tag-tension note (§9.2.2 vs §6.3) is handled by layering,
unchanged.

## Lean/Lake gotchas learned this session (save the next session time)
- `lake-manifest.json` rejects a guillemet/hyphen package `name`; let Lake
  regenerate it (no external deps → empty `packages`).
- **`UInt64` shifts need a `UInt64` shift amount** — numeric *literals* adapt via
  `OfNat`, but a `Nat` *variable* does not (`x <<< (UInt64.ofNat n)`, not `x <<< n`).
  Bare-literal-only shifts (`0x7FF <<< 52`) default to `Nat` → annotate `(… : UInt64)`.
- `where`-bound helpers fight `termination_by`; lift to a top-level `private def`.
  `decreasing_by simp_wf <;> omega` (the `<;>` tolerates simp_wf closing the goal).
  omega proves `n/128 < n` given `¬ n < 128` (it handles div by constants).
- `Array.get!` is gone → use `arr[i]!`; ByteArray too (`bs[i]!`).
- `String.mk` → `String.ofList`.
- `fun_induction f a b i` works for well-founded defs; pairs with the equational
  `rw [f]` to unfold the OTHER (non-inducted) occurrence.
- `#print axioms Foo` is the honesty gate — `[propext, Quot.sound]` = clean;
  `sorryAx` = a hidden hole.
- Container leaves a root-owned `.lake/` (rootless ownership); `podman unshare rm
  -rf .lake` before `git add`. Use the **rust** codec `.so` (self-contained cdylib).

## Next: S3 (peer machinery + verdict) — and the deferred Track-B targets
S3 builds the peer (transport/store/dispatch/verdict) to `validate-peer --profile
core` and proves **T4** (verdict factoring) + **T5** (attenuation monotone + depth
bound) — where the A-LEAN-1..4 findings actually surface. The deferred codec
proofs (T1 total-decode round-trip; T2 totality) are Track-B refinements to revisit
with a kernel-reducible decode. Transport/crypto FFI seams are the 1c spikes.
