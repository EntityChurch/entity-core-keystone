# Phase S5 — Publish (entity-core-protocol-common-lisp)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 spec-data v7.72 + the v7.73/v7.74
peer-surface closeout (register/outbound/emit §6.13 + §6.9a owner-cap + §7a conformance handlers);
codec corpus v0.8.0.

S5 polishes the S4-conformant peer #5 into a *ready-to-publish* artifact. `/entity-rosetta` never
publishes (lifecycle §Publishing) — this phase produces the artifacts + the runbook; an operator
publishes when arch signs off v0.1. This doc is the release-readiness record + the operator handoff.
The architecture review + the publishing-options decision surface live in
`status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 568 / 284P / 195W / **0F** / 89skip, machine-verified `failed==0`; **re-run GREEN in-container at S5** after the packaging changes (`status/CONFORMANCE-REPORT.{md,json}`) |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`) |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first full run, 0 codec fixes; **re-run GREEN at S5** |
| S3 two-peer loopback smoke | ✅ | 11/11 (handshake + dispatch + capability + 8-way request_id demux); **re-run GREEN at S5** |
| Ed448 RFC-8032 KAT (agility primitive) | ✅ | pubkey + 114-B sig + §1.5 peer_id byte-equal (A-CL-005) |
| ASDF systems load clean | ✅ | `entity-core`, `entity-core/peer`, `entity-core/test` all load warning-free in-container; `:version` `0.1.0` parses (A-CL-010 fix) |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy) |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce) |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.72 + v7.73/v7.74 closeout` |
| Package metadata (`.asd`) | ✅ | `entity-core.asd` — three layered systems, descriptions/author/homepage set, `:version 0.1.0` (dotted-integer; `-pre` line in docs per A-CL-010), `:depends-on ("ironclad")` |
| Toolchain pin (S11) | ✅ | SBCL **2.6.4** (source-built, SHA-256-pinned + GPG); **ironclad 0.61** (pinned Quicklisp dist, pre-installed at container-build, run fully offline). One third-party runtime dep |
| CI config (Podman, offline) | ◑ runnable, not wired | the build/test/conformance runs sealed-offline in `common-lisp-toolchain` today (`run-s2/s3/s4.sh`, `run-origination-core.sh`). A committed CI *workflow* is deferred **cohort-wide** — no peer has one wired; it lands at S10 lift or when arch defines the shared CI home |
| Public API surface | ◑ documented | tiered in `src/peer-package.lisp` (Tier 1 model+identity / Tier 2 full peer / labelled test-client+helper block) + §3 below. Compiler-enforcement deferred (CL has no module-private keyword) — the OCaml `.mli`-deferral analogue |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-CL-002/007/009 routed ⚑ to arch (§5) |
| **Published to a dist / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) — no auto-tag, no push, no dist submission |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not yet met**
(no CL consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **ASDF package** — three layered systems (`entity-core.asd`):
  - `entity-core` — the codec island (package `ENTITY-CORE` / `EC`). Dep: `ironclad`.
  - `entity-core/peer` — the full V7 Layers 1–4 + foundation peer (package `ENTITY-CORE/PEER` /
    `ECP`). Deps: `entity-core`, `ironclad`, `sb-bsd-sockets`.
  - `entity-core/test` — the hand-rolled codec conformance harness (test-op; not a public surface).
- **Crypto: pure-Lisp, no FFI.** `ironclad` supplies Ed25519 **and** Ed448 **and** SHA-256/384 from
  one library — the agility *primitives* are native (the cohort's only zero-FFI both-curve peer).
- **Host executable** (`../host.lisp`, `ENTITY-CORE/HOST`): the S4 conformance driver (`--port`,
  `--debug-open-grants`, `--validate`; emits `LISTENING …`). Test/conformance only — intentionally
  NOT a component of any installed system.

---

## 3. Public API surface (the S5 "settle the surface" decision)

Common Lisp has **no module-private keyword** — a package's exported symbols *are* its public
surface. The export block in `src/peer-package.lisp` is now **tiered** (the CL analogue of pruning
Zig's `root.zig` re-exports):

- **Tier 1 — model + identity** (codec-island / §1.x value-layer consumers): `entity` + accessors,
  `entity-to-cbor`/`entity-of-cbor`, `envelope`, `keypair`/`identity-of-seed`/`identity-peer-id`/…,
  `sign-entity`/`verify-signature`. Plus the codec package `ENTITY-CORE` (`EC`): `cbor-encode`/
  `cbor-decode`, `content-hash`, `peer-id-*`, `ed-sign`/`ed-verify`, the condition lattice.
- **Tier 2 — full peer**: `peer`/`make-peer`/`dispatch`/`bootstrap`, the `store` surface, the §9.5
  `publish-core-types`/`core-type-entities`, the transport server+client (`start-listener`/
  `listen-on`/`accept-loop`/`serve-connection`, `dial`/`client-handshake`/`client-execute`/
  `client-close`, `response-status`/`response-result`).
- **Test-client + address-space helpers (NOT stable API)**: `empty-params`, `resource-target`,
  `grant`, `scope`, `scope-cbor`, `hex`. Exported because the in-repo test execs (`test/smoke.lisp`,
  `test/type-registry.lisp`) are *separate library clients* that use them by name — they may churn
  without a semver bump. They are explicitly labelled in the export block.

**Why the surface is documented, not compiler-enforced** (the honest S5 state, matching OCaml):
hard-pruning the test-client helpers would break the in-repo test build until those tests move
*inside* the system (a test-op-only sub-package) at publish prep. That move is build-risky against
the current all-source-in-repo (S10) layout and best done once the surface is frozen against a first
external consumer — exactly OCaml's `private_modules`/`.mli` deferral rationale and Zig's
`root.zig`-freeze deferral. Until then the tiers are documented in the export block + here.

---

## 4. Packaging notes specific to Common Lisp

- **ASDF version field is dotted-integer only (A-CL-010).** ASDF's `:version` rejects a SemVer
  `0.1.0-pre` (→ NIL + warning), so the three systems carry the parseable **`0.1.0`** and the
  **`0.1.0-pre` pre-release LINE** lives in `CHANGELOG.md` + `README.md` (+ a header note in the
  `.asd`). No other cohort build system (opam, build.zig.zon, package.json, .csproj, mix.exs) hit
  this — a small distant-idiom packaging wrinkle, logged so a future promotion re-applies the split.
- **Dual community dist, both index git repos.** CL has no upload-an-artifact registry: **Quicklisp**
  (monthly, de-facto) and **Ultralisp** (push-rebuild, faster cadence) both register a *git repo*;
  "publishing" = getting the repo into a dist build, then consumers `(ql:quickload :entity-core)`.
  Direct ASDF (`asdf:*central-registry*`) is the third, dist-free, fully-offline path — how the peer
  is consumed today. (See `ARCHITECTURE-REVIEW.md` §B.2.)
- **Single third-party dependency is a packaging advantage.** The peer pulls only `ironclad`
  (BSD-3, pinned 0.61; transitively nibbles + alexandria). Lighter than C#'s multi-provider graph;
  heavier than Zig's std-only zero; **and FFI-free unlike OCaml's agility** — `ironclad` supplies
  *both* curve families natively, so there is no `.so`/C-ABI in the manifest.
- **Crypto-agility — primitives NATIVE, full MATRIX deferred (cohort-wide).** Unlike OCaml (FFI
  Ed448, A-OC-002) and Zig (no Ed448, A-ZIG-002), CL has Ed448 + SHA-384 native and byte-proven
  (RFC-8032 KAT, A-CL-005); the connect-path agility slice is exercised. The agility *full MATRIX*
  harness (the M2/M3/M6 key-type × hash-format cross-product) is the documented non-v0.1 item — no
  FFI or second provider is needed when it lands; only the matrix harness is unwired.
- **`cl:identity` package-lock footgun (resolved, A-CL-008 note).** The L1 identity struct can't be
  named `identity` (`cl:identity` is a locked standard symbol), so it is `keypair` with a
  `(:conc-name identity-)` — public accessors stay `identity-hash`/`identity-peer-id`/… (the cohort
  surface) while the type name dodges the package lock. Implementation detail, not a spec matter.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-CL-* items are resolved-in-peer and routed; none block release. The arch escalation
bundle (full text in `status/SPEC-AMBIGUITY-LOG.md`, retrospective in `ARCHITECTURE-REVIEW.md` §A.2):

- **A-CL-009 ⚑** §3.4/§3.5 address-space hex-case unspecified — **owner: architecture** (NEW;
  high-value interop trap). Tree paths are case-sensitive keys; four lowercase-defaulting stdlibs
  hid it, CL's uppercase default surfaced it. Peer renders lowercase; validated live (S4 0-FAIL).
- **A-CL-002 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: architecture** (high-priority;
  silent-handshake-kill). Peer follows §1.5 identity-multihash; **THIRD spec-first corroboration**
  (after OCaml A-OC-007, Zig A-ZIG-001).
- **A-CL-007 ⚑** ECF format_code 128 construct-vs-receive asymmetry unstated in §4.3/§4.7 —
  owner: architecture. **SECOND independent corroboration** of OCaml A-OC-004.
- **A-CL-008** §6.6 dispatch maps cleanly onto CLOS multiple dispatch — owner: none (idiom-neutrality
  signal; five idioms converge — a tightness signal for the review ledger).
- **A-CL-001** v7.73/v7.74 spec-data snapshot missing — owner: research/arch (byte-provenance gap;
  the oracle check-set IS at HEAD; the peer's v7.73+ behavior is cohort+oracle-sourced).
- **A-CL-003** native sb-thread concurrency — resolved-in-peer (validated S3; bordeaux-threads the
  open path if cross-impl portability is wanted). **A-CL-004** Quicklisp dist pin — resolved.
  **A-CL-005** pure-Lisp Ed448 trust — resolved (KAT byte-equal). **A-CL-006** SBCL source SHA —
  resolved. **A-CL-010** ASDF version field — resolved-in-docs (owner: operator).

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Decide in-repo vs standalone repo** (see `status/ARCHITECTURE-REVIEW.md` §Publishing-options).
   Per-language sibling repos are deferred keystone-wide (S10); current default is in-repo under
   `protocol-generator/common-lisp/`.
2. **Settle the public-surface freeze** (§3): move the in-repo test execs inside a test-op-only
   sub-package so the Tier-1/Tier-2 surface can drop the test-client helper exports, build-verified
   in the `common-lisp-toolchain` image.
3. **Promote version** the `0.1.0-pre` LINE → `0.1.0` in `CHANGELOG.md` + `README.md` once the
   promotion gate (§1) is met (the `.asd` `:version` is already `0.1.0`; A-CL-010 means there is no
   `-pre`-in-`.asd` to bump — only the docs carry the line).
4. **Set `repository_url`** in `profile.toml [publishing]` + the `.asd` `:homepage` (currently the
   keystone repo; point at the per-language sibling repo if Option 2 is taken).
5. **Register the dist entry** — Quicklisp (de-facto) or Ultralisp (faster cadence), or both;
   consumers then `(ql:quickload :entity-core)`. There is no `publish` upload command — the dist
   indexes the git repo. **Tag the release** at the reviewed commit at this point only (lifecycle
   §"no auto-tag").
6. **Wire CI** (`run-s2/s3/s4.sh` + `run-origination-core.sh` in `common-lisp-toolchain`,
   `--network=none`, assert `failed==0`) to the chosen repo's runner, or fold into the keystone-wide
   CI home if arch defines one. No remote/CD is attached today by design.
7. **Pin discipline** (S11): SBCL 2.6.4 + ironclad 0.61 stay exact; re-pinning is deliberate +
   reviewed; the Quicklisp build-dist tag is re-stamped only when ironclad re-pins.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged; `0.1.0`
promotion pending external consumer; public-surface freeze pending; CI authored-offline but not
wired to a remote — by design). Regression re-ran GREEN after packaging (**S2 69/69 · S3 11/11 ·
S4 568 · 284P/195W/0F/89S · origination 3/3**). ASDF systems load clean. Ambiguity log finalized +
owner-routed (A-CL-002/007/009 ⚑ arch). Architecture review + publishing-options written
(`status/ARCHITECTURE-REVIEW.md`). Operator handoff (§6) prepared. **S5 objective met; the Common
Lisp peer #5 is publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off.**
