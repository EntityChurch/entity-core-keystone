# entity-core-protocol-lean — PHASE S1 (profile + spikes) — COMPLETE

**Done by hand** (no sub-agents — the user's call for this peer:
it's the proof-vector peer, worth direct attention). Peer #10, taken ahead of Prolog.

S1 ran in three sub-phases instead of the usual library survey, because Lean's defining
S1 question is *how do you prove a protocol's invariants*, not *which CBOR/crypto lib*.

## 1a — Lean-as-prover (desk research)
Recorded in the Lean-as-proof-vector exploration. Four findings:
1. **No extraction gap** — a pure total `def` is both proven and compiled ⇒ commit the
   hybrid **stance-1** (codec + verdict proven-and-run; shell unproven).
2. **`Float` is opaque** ⇒ shortest-float must be **bit-level** (`Float.toBits` over `UInt`).
3. **OS thread pool, blocking-only FFI sockets, dedicated threads + `Std.Mutex`** ⇒ §7b
   the OCaml way, not the Swift cooperative-pool trap.
4. **mathlib heavy** ⇒ `proofs/` target only; shipping peer mathlib-free.

## 1b — protocol-provability ledger
Recorded in the Lean-1b provability ledger. Sharpened 5-theorem set
(T1 codec normal-form, T2 key-order lemma, T3 bit-level float, T4 verdict factoring, T5
attenuation-monotone + depth-bound). Surfaced four proof-track findings (A-LEAN-1..4, see
`SPEC-AMBIGUITY-LOG.md`) — the keystone payoff: formal proof finds preconditions nine
agreeing peers shared silently. Nothing locked; swaps allowed as proofs reveal what's clean.

## 1c — environment spikes (hands-on, all GREEN)
`containers/lean-toolchain/` BUILT + verified (fedora:43 + elan v4.2.3 sha256-pinned +
Lean 4.29.1; Lean+Lake run on fedora:43 glibc). Three spikes in `spikes/`:

| Spike | Result | Proves |
|---|---|---|
| `prove-vs-run` | GREEN | round-trip + injectivity proved, `#print axioms` = no axioms (no sorry); compiled `main` runs the SAME `def`. No extraction gap, on real code. |
| `crypto-ffi` | GREEN | links `libentitycore_codec`; SHA-256("abc")=FIPS KAT; Ed25519 keygen+sign+verify; Lake `extern_lib`+`moreLinkArgs` FFI pattern validated for Lake 5.0. |
| `transport` | GREEN | real two-peer TCP loopback echo over an FFI socket shim; blocking `recv` on a dedicated thread; `Std.Mutex`-guarded shared state. Clears the handoff's flagged transport gate. |

## Decisions locked (see `profile.toml`)
- Codec: native pure-Lean ECF, **proven**, **bit-level float** path.
- Crypto: **FFI-hybrid** via the C-ABI (Lean has no native audited Ed25519 — OCaml/Zig gap).
- Concurrency: dedicated-thread-per-connection + `Std.Mutex` store (§7b posture proven).
- Two Lake targets: `src/` (peer, mathlib-free) + `proofs/` (Track B, mathlib here only).
- Stance on unprovable findings: build the peer first; prove what's feasible; can't-prove-
  as-written may → spec change, but only after the peer works (memory `lean-proof-vs-spec-stance`).

## Next: S2 — codec + proofs T1/T2/T3
Build the pure-Lean canonical ECF codec (gate: Appendix-E vectors byte-identical), then
prove the codec headline theorems. Pin Batteries (runtime) + mathlib (proofs/) in
`lake-manifest.json` at S2 entry (S11). The crypto-ffi + transport spikes are kept as
regression seeds and the S2/S3 FFI starting points.
