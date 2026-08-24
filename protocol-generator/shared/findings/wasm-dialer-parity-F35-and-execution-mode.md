# HANDOFF-TO-ARCH — wasm-wat full parity + F35 (reentry-echo skips §5.2) + wasm execution-mode analysis

**Date:** 2026-07-15 · **Owner:** `arch` (probe design + spec clarity; execution-mode is FYI, not
a spec ask) · **Surfaced by:** the hand-authored WASM peer (`protocol-generator/wasm-wat/`) reaching
**true cohort parity** — the §7a `--validate` reentrant dispatch-outbound dialer now RUNs and PASSes.
**Blocks:** nothing (peer is GREEN). **Companion to:** `concurrency-latency-floor-and-cap-sig-coverage.md` (F33 + F34) — read that first; this adds **F35** + the
production-story analysis the user asked for. Findings register: `research/stewardship/SPEC-FINDINGS-LOG.md`.

> Keystone cannot edit `spec-data/**` or the oracle (both boundary/immutable). These are requests
> for arch to weigh on its own schedule. Derived from the **spec** + the oracle's **observable
> behavior** (the peer is already green via legitimate levers — not oracle-matching).

---

## 0. Milestone (context): full cohort parity on the §7a scaffold

`run-s4.sh` → **Result: PASS — 291 pass / 294 warn / 0 FAIL / 97 skip @ oracle `cc1970f`**, with
**no `-allow-skip`** (was 289P/99S under the code-attestation floor). The two previously-deferred
checks are green:
- `t1_2_concurrent_reentry` (concurrency) — *M=8 concurrent reentrant dispatch-outbound calls all
  round-tripped; validator-as-B served 8 inbound echos, exactly-one per dispatch under concurrency.*
- `validate_echo_dispatch` (handlers) — §7a.1 verbatim-echo round-trips the dispatch half.

Implementation note for arch's mental model: the §7a.2a **same-connection reentry** means the peer
never opens a client socket — the outbound echo EXECUTE rides back down the *inbound* fd. On a
single-threaded poll loop this collapses the whole "suspend the request / pump reentrantly / resume"
machinery to *"`dispatch()` returns exactly one frame; the send-loop is unchanged"*, with a small
`pending[echo_request_id → dispatch_request_id]` table. This is a clean substrate result worth
recording: the §6.11 reentry contract does **not** require true concurrency on the peer side when
reentry is same-connection — request_id correlation on one fd suffices.

---

## F35 — the §7a reentry-echo runs ZERO §5.2 verification → outbound-authorization is untested

### The gap

§7a.1 specifies `system/validate/dispatch-outbound` as *"originate ONE outbound EXECUTE via the
§6.11 reentry seam"* carrying the reentry authority — the reference handler passes
`WithCapability(cap)` + `WithIncludedChain([granter, sig])` (`ext/conformance/handler.go`,
`DispatchOutboundHandler.Handle`). The whole point (per the handler's own doc comment) is to give a
black-box validator a wire-reachable trigger for the **§6.13(b) outbound seam** — i.e. to prove the
peer can originate an **authorized** cross-peer EXECUTE (the F25 substrate guarantee).

But the **validator-side counterpart** that receives that outbound EXECUTE — the armed reentry-echo
`handleReentryEcho` (`cmd/internal/validate/conformance_handlers.go` ~L84-140 @ `cc1970f`) — runs
**no verification at all**:

```
execData, _ := types.ExecuteDataFromEntity(env.Root)        // parse only
if ExtractHandlerPath(execData.URI) != PatternEcho { ... }  // match uri + op
st.hits.Add(1)
respData := ExecuteResponseData{ RequestID:…, Status:200, Result: execData.Params }  // echo verbatim
```

No §5.2 author-sig verify, no capability-chain verify, no §5.5 granter check.

### Consequence

A peer whose `dispatch-outbound` emits a **completely unsigned, capability-less** outbound EXECUTE —
`{uri, operation:"echo", params, request_id}` with **no** `author` / `capability` / `included` —
still increments `hits` and round-trips, so **both** `validate_echo_dispatch` and
`t1_2_concurrent_reentry` **PASS**. The §7a probe does not gate the one property the handler exists
to prove: that the peer originated an *authorized* EXECUTE through the seam. Vacuous-green on the
**outbound-authorization axis** — the same "conformance-green can be vacuous" family as F29/F30/F34,
here on the *origination* surface (F34 is the symmetric inbound cap-sig gap).

### What we did (NOT a peer bug)

wasm-wat builds the **full authorized** envelope anyway: author-signed root + `capability:<cap-hash>`
+ `included{author-sig, reentry-cap, granter, cap-sig}` (`serve_dispatch_outbound` in
`src/dispatch.wat`). Building the minimal unsigned frame the probe would accept is exactly the
vacuous shortcut the keystone exists to catch, so we declined it. But the *probe* can't tell the two
apart — that's the finding.

### Recommendation (arch's call)

Have the reentry-echo (or a dedicated sibling probe) run the §5.2 verify ladder on the inbound
reentrant EXECUTE — author-sig over root, capability grantee == the peer, granter-sig over the cap —
and only then echo. Optionally add a **negative arm**: the validator hands the peer a reentry cap
scoped to the *wrong* grantee (or omits it) and asserts the peer's originated EXECUTE is *rejected*
by a verifying B — locking the authorization contract end-to-end. This turns §7a from "did an
EXECUTE with the right shape come back" into "did an **authorized** EXECUTE come back," which is what
§6.13(b)/§6.11 + the F25 substrate guarantee actually require.

---

## Execution-mode / production-story analysis (FYI — not a spec ask)

The user asked us to keep the WebAssembly execution-mode question in view. Consolidated state,
now with a **reproducible pass/fail signal** (sharper than the prior micro-benchmark):

### Measured (WasmEdge 0.17.0, in `containers/wasm-wat-toolchain`, concurrency category, `-timeout 25s`)

| Execution mode | `t2_1_sustained_load` | Category wall | Verdict |
|---|---|---|---|
| **Interpreter** (default) | times out (~60s) | — | crypto ~9 ms/verify; §5.2 does 2/req → 10k reqs blow the budget |
| **AOT** (`wasmedge compile` → run, no JIT flag) | **FAIL @ 22.9s** | 25 s | **native code NOT engaged** — crypto still ~9 ms |
| **JIT** (`--enable-jit`) | **PASS @ 1.3s** | 1.6 s | the working lever (~84 µs/verify, 109×) |

The AOT artifact *does* embed native code (347 KB source wasm → 1.05 MB universal wasm), but WasmEdge
0.17's **runner does not execute it** — running `wasmedge peer_aot.wasm` leaves crypto at interpreter
speed and t2_1 fails identically to the pure interpreter. So **JIT is the only lever on this
runtime**, and it pays a **per-boot** compilation cost (JIT-compiling ~700 KB of merged wasm — peer
+ Rust codec — at every launch). That is fine for conformance runs and light deployments but is not
an ideal production packaging story (no compile-once-run-native).

### The two production paths (both are tooling, not protocol)

1. **Newer WasmEdge.** If a post-0.17 release fixes AOT-runner engagement, `wasmedge compile` → run
   gives compile-once native execution with the *same* socket ABI the peer already uses (WasmEdge's
   `wasi_snapshot_preview1` `sock_*` extension). Lowest-friction path; worth a re-probe when the
   toolchain image bumps.
2. **A different runtime with mature AOT** (Wasmtime `wasmtime compile` → `.cwasm` / Cranelift;
   WAMR). Blocked by a **portability seam**, not the protocol: the peer is written against
   WasmEdge's non-standard socket extension (`sock_open/bind/listen/accept/recv/send`,
   `poll_oneoff` over non-blocking fds). Wasmtime exposes sockets via **wasi-sockets (preview2)**, a
   different ABI — so a Wasmtime port needs a host-import shim (or a preview2 rewrite of `host.wat`'s
   transport layer). The *dispatch interior* (codec, §5.2, handlers, the new dialer) is
   ABI-neutral and would move unchanged; only `host.wat`'s ~15 socket imports are runtime-bound.

### Durable takeaway (the substrate lesson, refined)

For a crypto-heavy per-request protocol on an interpreted host, **the compiled execution mode + its
launch flag are part of the peer's §6.11 conformance contract** — and on the *current* runtime that
mode is **JIT specifically** (AOT is inert on WasmEdge 0.17). The **transport ABI**, not the
protocol logic, is the wasm portability boundary: the same peer is trivially fast under JIT and
trivially portable *except* for its ~15 socket imports. Neither is a spec matter — recording it so
the next wasm/interpreted-substrate peer (or a production deployment) starts from the answer.
(Folded into `research/SUBSTRATE-TAKEAWAYS.md §4`.)

---

## Summary for arch

| Item | Type | Ask |
|---|---|---|
| **F33** (companion doc) | §6.11 T2.1 de-facto throughput floor vs §4.9 "not a perf bar" | distinguish late-vs-lost / model back-pressure / document the floor + compiled-mode requirement |
| **F34** (companion doc) | no tampered-**cap**-sig vector (inbound) | add `tampered_capability_signature`; note sound memoize-by-(hash,sig) |
| **F35** (this doc) | §7a reentry-echo skips §5.2 → outbound-authz untested | verify author+cap on the reentrant echo; optional negative arm |
| Execution mode | FYI | none — JIT is the working lever; AOT inert on 0.17; ABI is the portability seam |

All three findings are **coverage/clarity**, none block conformance. wasm-wat is GREEN at full cohort
parity (291P/0F, no allow-skip). The design remains right: per-request signing + same-connection
reentry are correct; the gaps are in what the *probes* assert, not in the protocol.
