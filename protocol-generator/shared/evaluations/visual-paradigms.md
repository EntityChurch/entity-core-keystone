# Evaluation — visual / dataflow programming environments as protocol substrates

Consolidates the two visual-paradigm probes (**Node-RED #31**, **TurboWarp/Scratch #32**) and
surveys the visual-programming field for whether a **third** probe is worth building. This is the
research-arm companion to the per-probe design docs (`node-red/src/FLOW-DESIGN.md`,
`turbowarp/src/BLOCK-DESIGN.md`) and the durable AGENTS.md visual-paradigm bullet — a single home
for "what did the visual track teach, and is the well dry?"

**TL;DR:** the two dominant visual paradigms (imperative-block + message-flow) are probed and prove
the meta-thesis. The one genuinely-distinct *unprobed* paradigm is **reactive patch/dataflow**, whose
only open, headless, socket-capable representative is **Pure Data**; every other candidate is either
same-family (Snap!/Blockly/n8n/NoFlo) or inaccessible-by-construction (LabVIEW, Max/MSP, Simulink,
Unreal Blueprints — proprietary, no headless server, no raw socket). A Pd probe would add
generator-robustness and a novel *reactive-vs-request/response mismatch* stress, **not** new spec
findings (discovery is substrate-bound — see LANDSCAPE). Recommendation: **treat the visual track as
complete**; hold Pure Data as the single "if the itch returns" candidate.

> **2026-07-15 update — the itch returned; the Pd probe (#33) is BUILT and closed out, and it
> over-delivered on the prediction above.** Outcome: **682 · 287P/299W/0F/96S — Result: PASS @
> `cc1970f`** (0 fail-counting skips), genuine 2-of-3 multisig accept + origination-core reentry
> 3/3, measured **natively on the real Pd runtime over real TCP** — the first visual probe to
> clear the full core gate (the other two are interpreter/bridge-measured and not gate-green).
> The prediction "robustness, not spec findings" held: no new spec ambiguity — but the build
> yielded two **durable cross-language findings** the code-track cohort had silently skirted:
> **A-PD-016** (mint-timestamp precision is a CORRECTNESS parameter on a content-addressed
> protocol — second-truncated `created_at` makes same-scope same-second mints hash-identical, so
> one revoke killed the session cap and 403-cascaded the marathon) and **A-PD-017** (§5.5a makes
> the open seed's bare `*` granter-local, so a debug/open-access seed MUST also carry the
> absolute `/*/*` form to cover foreign namespaces). The reactive-mismatch characterization and
> substrate lessons are in §5a below. The track is now complete WITH the third paradigm probed;
> the well-is-dry verdict stands, now on three-of-three paradigms.

## 1. What we built

| # | Peer | Paradigm | Authored on the canvas | Delegated (seam) | Conformance @ `cc1970f` |
|---|---|---|---|---|---|
| 31 | **Node-RED** | flow-based / message-passing (FBP) | the §6.5 dispatch as a 16-node flow-graph (begin → connect-preauth → author → capability → verify → resolve → permission → handler; each error wire → a shared sink) | leaf crypto/codec (Ed25519, ChainVerifier, Permissions) via `lib/codec-bridge.js` | 249·**2F** (correctness green; 2F = §6.11 sustained-load throughput boundary `A-NR-throughput`) |
| 32 | **TurboWarp/Scratch** | imperative block / control-flow-visible | the §6.5 dispatch **spine** + full §5.2 verify + **all five handler bodies** (echo/tree/handlers/capability/connect) as a dispatch spine that routes to one `define dispatch-<handler>` custom block each | socket + §1.6 framing, canonical CBOR, Ed25519/SHA + chain/permission verdicts, entity read/build, store/CAS — the `ecutils` seam (deliberately **no `dispatch` block**) | 291·**0F** — **solid 5/5 full-marathon** incl. §6.11 t2_1+t2_2 (the earlier churn flakiness was a fixed harness-scheduling bug, see §3 lesson 6) |
| 33 | **Pure Data** *(2026-07-15)* | reactive patch / signal-graph dataflow | the §6.5 **pattern-first dispatch spine** (one named unit per handler, per-handler op-switch), the full §5.2 verify ladder, the §4.6 auth guard ladder, the §6.6 longest-prefix walk — all as canvas objects/wires in `main.pd` | bytes/CBOR/crypto/peer-id/store via `[ecodec]` (a C external on the C-ABI codec) **plus the TCP transport itself** — stock `[netreceive]` broadcasts every reply to all sockets with no per-conn id (A-PD-002, proven at Pd source level) | **682·0F Result: PASS** (287P/299W/0F/96S, 0 fail-counting skips) on the REAL Pd runtime over REAL TCP; multisig 2-of-3 accept + origination reentry 3/3 |

#31 and #32 are **experimental probes, NOT gate-green / not published** (the throughput boundary;
and both delegate crypto so a green result is cohort-consistent, not independent convergence —
ADR-0012). #33 IS gate-green by the full cohort standard but stays in the probe class (its purpose
is paradigm visualization; same cohort-consistency caveat). Their value was never a conformance
number — it was the findings classes below.

## 2. What the entity-core SPEC learned (the keystone payoff)

The probes earned their keep by **surfacing bugs that folded logic had hidden** — the same lesson
twice, from two paradigms:

- **TurboWarp §5.2 decomposition (#32).** Folding `verify_request` into one `capabilityChainValid`
  boolean had masked **three** real conformance defects, each recovered only when the verdict was
  split into per-step blocks with their pinned codes: the single-401 `unresolvable_grantee`
  carve-out (§3.6 PR-3), 400 `chain_depth_exceeded` ordered *before* the 403 authz walk, and
  **unchecked revocation** (a revoked cap wrongly returned 200).
- **Node-RED §6.5 decomposition (#31).** Collapsing the pipeline into one delegated `dispatch(frame)`
  had hidden the same shape of ordering/verdict bug; the 16-node graph made the sequence auditable.
- **The durable meta-finding:** *a folded verdict is a hiding place.* Decomposing protocol logic to
  make it **visible** is a bug-finding technique in its own right — independent of the substrate.
  This generalizes back to every peer: a boolean that fuses several spec steps is a code smell.

(No *new* wire-level spec ambiguity came out of the visual track — consistent with LANDSCAPE's
"discovery is substrate-bound": these peers are novel off-wire, so they yield robustness + the
decomposition findings, not new wire findings.)

## 3. What we learned about VISUAL ENVIRONMENTS as protocol substrates

Reusable across any future visual/low-code probe:

1. **Author in the paradigm; don't wrap.** A peer whose §6.5 collapses to one delegated
   `dispatch(frame)` with a few façade blocks is a *wrapper*, not a paradigm probe. The payoff is the
   logic being **visible and studyable in the language**, not a running peer (a wrapper runs fine).
2. **Draw the FFI seam at what the substrate genuinely can't do** — bytes/maps/sockets/crypto/store.
   Author everything the substrate *can* express: the §6.5/§5.2 sequence, status codes, the op-switch,
   the guard ladders. Values the substrate can't hold (envelopes, entities, hashes) ride as **opaque
   handles** (string ids into a side table); readable fields (uri, request_id, author-present) are
   plain reporters.
3. **Verify without the real runtime via an oracle-driven interpreter of the *actual authored
   artifact*.** TurboWarp's `run-blocks.mjs` executes the genuine `project.json` block graph
   (control_if / control_stop / operator_* / data_* / procedures_call / ecutils_*) against the live
   `validate-peer` oracle. Faithful, low-risk, a real number every iteration. The real-VM run is the
   final confirmation caveat — but the interpreter is what makes iteration possible when the VM is a
   browser sandbox. **This is the single most reusable technique from the whole track.**
4. **Legibility needs decomposition into named units, not just "on the canvas."** One 400-block tower
   under a single hat is exactly as unreadable as the code it replaced. Splitting into a short
   dispatch **spine** + one **custom-block procedure per handler** (Scratch `define …`, warp) is what
   delivered the studyability the exercise was *for*. (`stop this script` inside a procedure is the
   early-return; the spine's `stop` after the call terminates dispatch.)
5. **Frame-cap (§1.6) is load-bearing on single-threaded substrates.** An oversize frame stalls the
   one JS/event-loop peer and **cascades** into dial-timeouts on every later connection — masking
   dozens of unrelated tests. Transport-layer utility whose *absence looks like* higher-level failure.
6. **Cooperative yielding between requests is load-bearing for connection-churn (§6.11 t2_2) on a
   single-threaded interpreter — and a symptom is easy to misdiagnose.** A serial queue-drain (process
   the whole inbound backlog in one burst) flushes *no* responses until it finishes, so under rapid
   open→handshake→close the oracle tears connections down before their response lands → **dropped
   requests → a cascade** of ~1–28 downstream failures (every one of which passes standalone). The
   fix is a one-liner — yield to the event loop between hats (`await setImmediate`, the per-tick model
   real Scratch already uses). **The diagnostic lesson is the durable one:** the failure *looked* like
   a "throughput boundary" and *looked* caused by the newly-authored (heavier) handshake, but it was
   neither — `t2_1_sustained_load` (steady requests, no churn) always **passed**, and reverting connect
   to *delegated* **still failed** `t2_2`. Heavier per-request work only *exposes* a latent scheduling
   bug; prove the root by reverting the suspect and re-measuring, don't infer it from a plausible label.
7. **`t2_1` (sustained load) vs `t2_2` (connection churn) discriminate the failure.** Sustained
   requests on *established* connections skip the handshake and stress raw dispatch rate; churn stresses
   the accept-loop + per-conn lifecycle + response-flush timing. When only `t2_2` fails, look at
   connection *scheduling* (flush/yield), not throughput volume — it is emphatically **not** the 10k
   stress test. (Node-RED's `A-NR-throughput` 2F is a *different*, still-open boundary on its runtime.)

## 4. Field survey — is there a third probe?

The visual-programming landscape by paradigm axis, filtered for probeability (open/free · scriptable
or headless-verifiable · can reach a socket or has an escape seam · a *distinct* paradigm):

| Paradigm | Representatives | Probeable? | Verdict |
|---|---|---|---|
| **Imperative block** (control-flow visible) | Scratch/**TurboWarp**, Snap!, Blockly, MakeCode, App Inventor, Mindstorms | — | **PROBED (#32).** Snap!/Blockly/MakeCode are the *same* family (Blockly is literally Scratch's ancestor) → no new paradigm. |
| **Flow-based / message-passing** (FBP) | **Node-RED**, NoFlo, n8n, Apache NiFi, Temporal/Windmill (workflow) | — | **PROBED (#31).** NoFlo/n8n are the *same* family → no new paradigm. |
| **Reactive patch / signal-graph dataflow** | **Pure Data** (open), Max/MSP, vvvv, TouchDesigner, Reaktor, Blender nodes, Grasshopper | **Pd only** | **UNPROBED, genuinely distinct.** Pd is open, runs headless (`pd -nogui`), has built-in TCP (`[netsend]`/`[netreceive]`) or C externals, text `.pd` patch format. The others are proprietary or have no socket (Blender/Grasshopper = pure geometry compute → wrapper only). **The one real candidate.** |
| **G / instrumentation dataflow** | **LabVIEW**, Simulink | No | Proprietary (NI / MathWorks), no free headless, no raw-socket-in-diagram. *Confirms the operator's LabVIEW instinct — visually "between" our two probes, but inaccessible.* |
| **Game-engine visual scripting** | Unreal **Blueprints**, Unity Bolt/Visual Scripting, Godot VisualScript (removed in 4.x) | No | Engine-bound; no headless server, no listening socket from the graph. Wrapper-only. |
| **Spreadsheet / functional-reactive cells** | Excel, Google Sheets, LibreOffice Calc | Marginal | A genuinely different reactive-cell-graph, but socket I/O = Basic/Python **macros** = a wrapper; the dispatch *verdict logic* could be cell formulas while I/O sits in macros. A stunt, not a clean paradigm probe. |
| **Projectional / structured editors** | JetBrains MPS, Dark (darklang) | Off-axis | AST-editing, not dataflow — a different research question (editor model, not runtime paradigm). Out of scope for this track. |

**The "in between Scratch and Node-RED" intuition is correct and names a real paradigm:** the
**dataflow-patch** family (LabVIEW / Max / Pd) — you wire boxes together and values flow along the
wires, visually sitting between Scratch's stacked control-flow and Node-RED's message routing. Its
*accessible* representative is **Pure Data**; the ones the operator reached for (LabVIEW) are the
*inaccessible* representatives of the same family.

### If a Pd probe were built

- **New signal:** the *reactive-continuous-dataflow ↔ discrete-request/response mismatch* — a peer is
  inherently request/response, and expressing a stateful handshake + guard ladder in a pull/push
  signal graph is the genuine stress (does the paradigm *fight* the protocol? that answer is the
  finding). Third data-race/ordering shape for §6.11/§7b.
- **Expected yield:** generator-robustness + the mismatch characterization; **not** new wire findings
  (off-wire novelty). Same tier of payoff as #31/#32's robustness half, minus the decomposition-bug
  half (which we've now cashed twice — diminishing returns).
- **Seam shape:** Pd's `[netreceive]` gives raw TCP for free (no bridge needed, unlike the browser
  sandbox); CBOR/crypto via a C external or the C-ABI `libentitycore_codec`. Verification would reuse
  the #32 pattern: an oracle-driven interpreter over the `.pd` patch text.

## 5a. Pure Data close-out — what the third paradigm actually taught (2026-07-15)

The reactive-patch probe is complete; the retrospective, in the order the design pressures hit:

1. **The reactive-vs-request/response mismatch is real but SHALLOW once the transport is a seam.**
   Pd's "everything is a bang through a wire" model encodes the §6.5/§5.2 sequence naturally as a
   guard ladder (each rung a `[sel 0 1]` failing to its coded 4xx) — visually it reads BETTER than
   the Scratch tower because Pd wires ARE control flow. The genuinely awkward part was never
   request/response — it was per-request TRANSIENT STATE (the decoded frame, the authz context):
   Pd atoms can't hold bytes (A-PD-003), so per-request state lives in the seam as single-owner
   globals, safe only because dispatch is fully synchronous per frame. That constraint — "one
   frame fully dispatched before the next" — is the reactive twin of TurboWarp's no-thread-locals
   lesson (§3): on BOTH visual substrates the concurrency answer is cooperative serialization, not
   fan-out.
2. **The transport belongs in the seam when the runtime's own primitive is disqualified at source
   level.** Stock `[netreceive]` BROADCASTS every reply to all open sockets and binary mode has no
   per-connection id (`x_net.c netreceive_send`) — structurally non-conformant for §6.11, not
   merely inconvenient. The wrapper-guard survives: what moved into `[ecodec]` is
   bytes/sockets/framing (the legitimate seam list), while dispatch/verdicts stayed on the canvas.
   Post-rework the suite ran 26× faster and unmasked ~35 never-run probes — the third repetition
   of "decomposing/fixing the folded layer surfaces latent misses" (Node-RED #31, TurboWarp #32,
   now Pd #33 at the transport layer).
3. **§6.11 reentry on a single-threaded canvas = a bounded synchronous send+wait on the SAME fd.**
   No reader thread, no correlation map: dispatch-outbound writes the outbound EXECUTE to the
   originating fd, then poll+recv's until the correlated `request_id` response arrives (8s bound),
   handing any non-response frame back to the connection's assembler for post-dispatch peel. The
   oracle's concurrent-reentry probe (t1_2) passes because per-CONNECTION serialization is
   conformant — the §6.13(b) contract pins behavioral presence, not architecture (§9.4).
4. **The two durable findings were AUTHORITY-layer, not wire-layer** (the wire well is dry, as
   predicted): A-PD-016 (ms-precision mint timestamps are a correctness parameter on a
   content-addressed protocol — the second-truncated `created_at` collided a re-mint with the
   session floor cap; only the full marathon exposes it, category runs in isolation stay green)
   and A-PD-017 (the open/debug seed needs `resources: ["*", "/*/*"]` — §5.5a bare-star is
   granter-local, so the naive open seed can't cover foreign namespaces and the
   universal_address_space category silently skips).
5. **The vacuous-green lesson cashed again, at the identity layer:** multisig was 10/10 green
   rejection-only until the peer got a persistent on-disk identity (`EC_NAME`); the accept path
   then ran and required real M3/M4/M6 K-of-N verification. A conditioned/exempt skip is still a
   coverage hole — closing it took ~60 lines and proved the chain walk wrong-shaped (single-sig
   granter assumed).
6. **Verdict on the paradigm question:** reactive-patch can host the full protocol legibly. Of the
   three visual paradigms, Pd gave the cleanest canvas-authoring experience (wires = control flow,
   no dynamic-dispatch workaround needed once the spine is pattern-first) and the only real-runtime
   gate PASS. The cost concentrates entirely in the seam (bytes/crypto/transport/store — ~3k lines
   of C external), which is exactly the FFI story the C-ABI exists for.

## 5. Recommendation

**Treat the visual/dataflow track as complete.** The two probes cover the two dominant visual
paradigms, prove the author-in-the-paradigm thesis, and cashed the decomposition-surfaces-bugs
finding twice (the third time would be diminishing). Every remaining candidate is same-family or
inaccessible — **except Pure Data**, the lone open representative of the third (reactive-patch)
paradigm. Hold Pd as the single documented "if the itch returns" probe; its value is robustness +
the reactive-vs-request/response mismatch characterization, explicitly **not** spec discovery. This
matches the ecosystem's steady-state posture (LANDSCAPE §"discovery is substrate-bound"): the
spec-finding well on new substrates is dry; ongoing value is re-running the existing cohort against
each amendment, not adding paradigm #3.

## Cross-references

- Per-probe design: `protocol-generator/node-red/src/FLOW-DESIGN.md`,
  `protocol-generator/turbowarp/src/BLOCK-DESIGN.md`
- Matrix rows (the ‡ probes): `CONFORMANCE-MATRIX.md` §1 + the 2026-07-13 update note
- Durable lesson: the AGENTS.md "Visual/dataflow paradigms: author the protocol IN the language"
  bullet (this doc is its long-form backing)
- Session diaries: `docs/status/HANDOFF-2026-07-13-{visual-peers,scratch-authored-peer,scratch-capability-handler}.md`
- Forward-looking build queue (Pd + Simulink/spreadsheet/textual-dataflow verdicts): `research/COMPLETENESS-ROADMAP.md`
