# Phase S1 — Pure Data feasibility spike + profile

**Peer #33 · Pure Data (reactive-patch / signal-graph dataflow) · Tier 5 · started 2026-07-14**

Third and final clean visual-paradigm probe, after Node-RED (#31, flow-based) and TurboWarp (#32,
imperative-block). Pd is the ONLY cleanly-probeable member of the **reactive-patch / signal-graph**
class (Max/MSP, vvvv, LabVIEW, Simulink are proprietary / no-headless / no-socket — see
`protocol-generator/shared/evaluations/visual-paradigms.md`). One probe exhausts the accessible surface of the class.

## Honest framing (ADR-0012)

**Not wire-axis discovery** — Pd externals are C, and the wire axis is saturated by the C peer + the
C-ABI codec. The axis is **paradigm + generator-robustness**: the reactive-continuous-dataflow ↔
discrete-request/response mismatch, and a **third §6.11/§7b data-race/ordering shape**. Lands as an
**exploratory ‡ row**, NOT a real/deployable peer. Any conformance pass is **cohort-consistent**
(shared codec lineage via the C-ABI), **not independent convergence** — state it precisely. No matrix
row until it is real (green oracle number).

## The GO gate — RESOLVED: **GO** (2026-07-14)

The one thing that gated everything: does the substrate work headless, with raw binary TCP, in
container? **Proven, and baked into the toolchain image as a reproducible build-time self-test**
(`containers/puredata-toolchain/gogate-selftest.sh`).

| Gate item | Result |
|---|---|
| Pd packaged in fedora:43? | **NO** — `dnf search puredata` → no matches (not under `pd`/`pure-data` either; only fedora/updates/openh264 repos). The handoff's `dnf install puredata` assumption is **wrong**. → source build. |
| Source build headless in-container? | **YES** — pinned tarball `0.55-2` (SHA `2b9cda30…`), `./autogen.sh && ./configure --disable-{alsa,jack,portaudio,fftw,oss} && make -C src`. **Core-only**: the `extra/` DSP externals (`fiddle~`, …) fail on modern gcc (`#define fsqrt sqrt` vs the C `sqrt` prototype) and are **not needed**. |
| `pd -nogui -noaudio` boots + runs a `.pd` patch? | **YES** — no X server; services the network scheduler on the system clock. (`priority NN scheduling failed` is a benign non-root realtime-priority notice.) |
| `[netreceive -b]` raw binary TCP inbound? | **YES** — accepts a TCP connection, emits each received byte as a float, byte-clean incl. `0x00` / `0xFF`. |
| Reply on the SAME connection (bidirectional)? | **YES, stock — no external.** A list sent to `[netreceive]`'s inlet is written back to the connected client. Authoritative: `src/x_net.c` `netreceive_send` (registered via `class_addmethod "send"` + `class_addlist`; guarded "send only works for TCP"). Echo round-trip `[10,20,255,0,42,200,1]` returned byte-identical. |

**Verdict: GO.** And a **strictly better** transport story than #32: TurboWarp is sandboxed (no raw
TCP → needed a WS↔TCP bridge); **stock Pd is a complete bidirectional binary TCP server**, so the Go
`validate-peer` oracle is reachable **directly, no bridge**. The default scope is therefore
**oracle-gated** (not visualize-first-with-optional-gate as #32 was).

## Transport-object decision (the handoff's flagged S1 choice)

The handoff flagged: verify `[netsend]`/`[netreceive]` binary framing, else fall back to an external
(`iemnet`/`mrpeach` `[tcpserver]`). **Decision: stock `[netreceive -b]`. No external.** It is
bidirectional and binary-clean (proven above), which removes the only reason to pull in `iemnet`.
This keeps the shipped peer external-free apart from the one unavoidable codec/crypto seam. **Open
sub-question (→ S3):** how `[netreceive]` targets replies under *multiple concurrent* connections
(§6.11) — whether `send` addresses a specific socket or broadcasts. Logged as **A-PD-002**; it is the
concrete face of the concurrency-shape stress below, resolved when the multi-connection demux is built.

## Authored vs delegated — RESOLVED

- **DELEGATED (a Pd C external `[ecodec]` over `libentitycore_codec`):** canonical CBOR, Ed25519,
  SHA-2, peer-id, and any value Pd atoms can't hold (byte buffers, maps, keys, u64 wire ints). Pd
  atoms are **32-bit floats** — they cannot represent a byte buffer or a 64-bit integer, so these ride
  as **opaque handles** (a C-external-owned pointer or receive-symbol); readable fields (status codes,
  op selectors, small counts) are plain float/symbol atoms on the canvas. The external is the thinnest
  possible `m_pd.h` ↔ `ec_*` wrapper (the Pd analog of tcl's `cffi` seam / #32's browser bundle).
- **AUTHORED (on the canvas — the actual algorithm, not a proxy for it):** §1.6 framing (accumulate
  netreceive's per-byte floats, reassemble on the 4-byte-BE length prefix), the §6.5/§5.2 dispatch
  **sequence**, status codes, the op-switch, the fail-closed guard ladder, and §6.6 handler resolution
  as the **visible longest-prefix-first tree walk** — NOT a hidden `resolve()` seam behind a literal
  `if pattern == …` ladder (the FLOW-DESIGN wrapper-guard; both #31 and #32 proved that folding this
  hides real conformance bugs).

## The reactive mismatch — the hypothesis to characterize (the whole payoff)

Pd executes a **pull/push message + signal graph** with a fixed **right-to-left, depth-first** message
ordering and **no native `await`**. A peer is inherently **request/response** with a stateful,
multi-step lifecycle (connect → hello → authenticate → dispatch → respond → … → close). Expressing
that lifecycle *state machine* in a stateless dataflow graph is where the paradigm **fights** the
protocol:

- **No await** → the handshake's sequential legs must be encoded as explicit **state held between
  messages** (per-socket state, keyed by connection), not as a call stack. Each inbound frame is an
  event that must consult "which leg is this connection on?" and route accordingly.
- **§6.11 multi-connection demux is the sharp edge** (as §6.11 ordering was load-bearing on #32's
  single-threaded interpreter). One `[netreceive]`, many sockets, one message thread → per-connection
  framing buffers + lifecycle state must be **keyed by socket**, and reply targeting must address the
  right socket (A-PD-002). Expect this to be the load-bearing edge.
- **Frame-cap (§1.6) is load-bearing** on a single-threaded substrate — an oversize frame stalls the
  one message thread and cascades into downstream timeouts (the #32 t2_2 lesson). Authored explicitly.

**Characterizing this fight IS the finding** — document how much of the lifecycle stays legible on the
canvas vs how much collapses into opaque per-socket state. This yields the third concurrency-shape
data point for the §6.11/§7b taxonomy: **single-thread reactive message-graph** (vs #31 flow-clone,
#32 single-threaded-block).

## Verification plan (reuse the #32 pattern — no real runtime needed each iteration)

An **oracle-driven interpreter over the real `.pd` patch text** — the Pd analog of #32's
`turbowarp/src/harness/run-blocks.mjs`. The `.pd` format is line-oriented (`#N canvas …`, `#X obj …`,
`#X connect …`), parseable into a box+wire graph an interpreter evaluates against `validate-peer`.
Gives a real conformance number each iteration; a run under the genuine `pd` binary is the **final
confirmation caveat** (same honesty note as #32's pending real-VM run). **Oracle: `validate-peer
--profile core`** — rebuild from `entity-core-go` HEAD per AGENTS.md (`CGO_ENABLED=0 GOWORK=off`) if
the vendored binary is stale; verify new validator vectors compiled before trusting a green.

## Legibility discipline (carried from the visual track)

Named units, not one 400-object tower: a short dispatch **spine** patch + **one `.pd` abstraction per
handler** (the Pd analog of #32's `define dispatch-<handler>` spine + per-handler procedures). One
giant patch is as unreadable as the code it replaced. See `arch/PATCH-DESIGN.md`.

## Status

- [x] GO gate proven (headless boot + native bidirectional binary TCP) and baked as an image self-test.
- [x] `containers/puredata-toolchain/` authored + built (pd 0.55-2, SHA-pinned, self-test green).
- [x] `profile.toml` authored (seam decisions above).
- [x] S1 status + ambiguity log + PATCH-DESIGN scaffolded.
- [x] S2: `[ecodec]` C external authored + smoked — headless pd loads it and reaches
      `libentitycore_codec` (provenance `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71` + a real
      SHA-256("abc")[0]==186 round-trip). Build+gate: `run-s2.sh` / `make smoke`. (A-PD-005: link the
      SHARED codec `.so`, not the static `.a` — distro libsodium.a is non-PIC.)
- [ ] S3: author the dispatch spine + per-handler abstractions + the framing/handshake state machine.
  - [x] S3.1: `[ecodec]` frame primitives (buf_reset/append/read_len/body_len/body_out) — the byte
        store + 4-byte-BE length decode the canvas can't hold.
  - [x] S3.2: `src/frame-assembler.pd` — the §1.6 header→body state machine authored on the canvas
        (phase + count as `[int]` cells; feedback loops; right-to-left trigger ordering). Verified
        byte-exact against real `pd` (`make frametest`: single + back-to-back + binary-clean). First
        A-PD-004 data point logged (~24 objects for a 3-line imperative read).
  - [x] S3.3: **real conditional 404 achieved** (first oracle-meaningful behavior). Full
        receive→decode→dispatch→respond path authored + gated:
    - `decode_frame`/`exec_field` — CBOR reader unwraps §3.1 envelope → dispatch fields (`make decodetest`).
    - `build_response` — canonical-CBOR writer builds a §3.3 EXECUTE_RESPONSE with correct §1.2
      content_hashes; full decode→build→reply round-trip (`make responsetest`).
    - The §6.6 **tree-walk** authored visibly on the canvas (backward longest-prefix loop, the
      `type=="system/handler"` filter, early return) → known prefix resolves (501 placeholder), unknown
      path 404s (`make treewalktest`). Placeholder tree = A-PD-006; Pd route/lone-symbol fix = A-PD-007.
  - [◐] S3.4: §4.1 handshake.
    - [x] Leg 1 (§4.4 hello): identity (Ed25519 → base58 peer_id via `ec_peerid_format`, §7.4) +
          `build_hello`; connect-path operation branch → 200 + `system/protocol/connect/hello`
          {nonce, peer_id, protocols, timestamp} (`make hellotest`). Ephemeral identity = A-PD-008.
    - [ ] Leg 2 (§4.4 authenticate): initial capability grant (token + signature + included map) —
          the big leg. Plus per-socket lifecycle state + §4.2 ordering (hello-before-auth, 409 reconnect).
  - [ ] S3.5: §5.2 guard ladder + one real handler → the accept path.
- [ ] S4: drive **real `pd`** against `validate-peer --profile core` (native transport → no interpreter
      needed, unlike #32's sandboxed `run-blocks.mjs`; real binary IS the per-iteration harness) to 0-F.
