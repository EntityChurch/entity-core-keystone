# Spec / Profile Ambiguity Log — entity-core-protocol-typescript

Per S3: every guess goes here. Profile-level decisions (A-NNN) and spec-level
ambiguities (logged here, escalate to `research/stewardship/` → arch as proposal
candidates). **No silent guesses.** Severity: blocking / non-blocking.

Cross-language spec findings live in `research/stewardship/SPEC-FINDINGS-LOG.md`
(F-NNN). This log is TS-specific; reference shared findings by number.

---

## Profile decisions (S1)

### A-001 — Crypto provider: `@noble` vs `node:crypto` · non-blocking · RESOLVED (operator ruling)
**Resolved: `@noble`** — operator ruling to **lean browser-compatible** (when options are otherwise close, prefer the browser-runnable one). `@noble/curves` 2.2.0 (ed25519 floor + ed448 agility family, one pure-JS package) + `@noble/hashes` 2.2.0 (SHA-2, audited; March-2026 self-audit covered ed25519/ed448). Pure-JS → codec+crypto run in a browser bundle (the consumable-data-library use case). Cost: +2 zero-transitive runtime deps (3 total with cborg). `node:crypto` (zero-dep, native, Node-only) remains the documented alternative behind the same pluggable agility seam if browser support is later dropped. Pin @noble exact ≥30d at S2 (both 2.2.0, ~2mo old → clear). Rationale: `PROFILE-RATIONALE.md`.

### A-002 — npm package id scope · non-blocking · DEFERRED to S5
Unscoped `entity-core-protocol-typescript` (keystone convention) vs scoped `@entity-core/protocol` (npm idiom). Decide at publish.

### A-003 — `ProtocolErrorError` naming · non-blocking · RESOLVED (S3)
**Resolved: `WireProtocolError`.** C#'s `ProtocolErrorException` → naive TS port stutters to `ProtocolErrorError`. Renamed `WireProtocolError` (it is the §6.12 `protocol_error`/502 transport fault: a response that arrived but was malformed). The rest of the hierarchy ports 1:1 from the C# tree: `EntityProtocolError` (+ `HelloFailedError`, `AuthenticationError`), `EntityTransportError` (+ `RecvTimeoutError`, `ConnectionBrokenError`, `WireProtocolError`). `EntityProtocolError` carries the §3.3 status; the transport errors carry the §6.12 `code`/`status` pairs.

### A-004 — Exact version pins vs S11 30-day rule · non-blocking · RESOLVED (S2 install)
All pins verified in-container (`npm view <pkg>@<ver> time`) ≥30 days old:
`cborg` **5.1.1** (~44d ✓ — now a *dev*-only cross-check, see A-005), `@noble/curves` **2.2.0** (~60d ✓), `@noble/hashes` **2.2.0** (~61d ✓), `typescript` **5.8.3** (✓), `@types/node` **24.12.3** (~35d ✓ — dev-only typings, supplies `TextEncoder`/`node:test` globals). Lockfile committed.
**Node runtime:** fedora:43's dnf `nodejs` stream is **22.22.2, not 24.x** → took the Containerfile's documented fallback: official nodejs.org tarball, SHA-256-pinned. **Node 24.16.0** was only ~21d old (< floor), so pinned **24.15.0** (~57d, LTS "Krypton"). Honors the profile's `runtime = node24` commitment. Detail in `containers/node24/Containerfile`.

### A-005 — Hand-rolled canonical CBOR core vs the profile-named `cborg` · non-blocking · RESOLVED (S2) · escalate: operator/research
**Decision: hand-roll the canonical CBOR codec core (zero runtime deps, pure-JS); keep `cborg` as a DEV-only cross-check.** The profile names `cborg` as `cbor_library` (S6). This deviates — logged here, not silent.
**Evidence (the cborg spike, `test/cborg-crosscheck.test.ts`).** cborg AGREES with the hand-rolled encoder on map-key ordering, minimal-int, the full `bigint`/u64 range (incl. the F7 2⁶³ boundary), byte/text strings, and non-integral floats. But it **structurally cannot serve as the ECF float encoder**: JS `number` erases int-vs-float (`Number.isInteger(1.0)` is true), so `cborg.encode(1.0)` → integer `01`, `cborg.encode(65504.0)` → `19ffe0` — not the canonical floats `f93c00` / `f97bff`. A faithful codec MUST carry an explicit float node in its value model regardless of library; once that value model exists (it must, for R1 `bigint` + N4 splice + R3 decode-minimality too), routing the ~150-line byte-perfect encoder through cborg buys nothing.
**Why hand-roll wins here:** (1) full control of the `bigint` integer surface (R1/F7); (2) the N4 verbatim-splice — cborg's high-level API has no raw-bytes token; (3) decode-side float minimality (R3) — cborg can't enforce it; (4) **zero-runtime-dependency, browser-portable codec core** (the user's dep-minimization stance + the browser lean — the codec core now imports nothing at runtime; only crypto pulls `@noble`).
**Consequence — runtime tree is leaner than the S1 eval projected:** eval said "3 runtime packages (cborg + 2× @noble)"; the codec core is now **zero runtime deps**, total runtime = **2 packages, both @noble (crypto only), zero-transitive.** Result: 69/69 byte-identical, first run.
**Operator option:** cborg is a one-line removal (drop the cross-check test + the devDep) if even a dev cross-check is unwanted; the corpus + FFI already cross-bless the bytes. Kept because an independent encoder is cheap insurance against encoder regressions (extra S8 signal). Profile `cbor_library` field should be updated to reflect "hand-rolled core; cborg = dev cross-check" (research → profile edit).

### A-006 — Core type-registry byte-equality · non-blocking · RESOLVED (S4 precursor, byte-verified)
The 53-type `CoreTypeRegistry` (types/core-type-registry.ts) is rendered natively and seeded at `system/type/*`, ported field-for-field from the C# reference. **`test/type-registry.test.ts` now diffs all 53 rendered `content_hash`es against the Go-rendered `protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor` → 53/53 byte-identical, first run.** A byte-identical content_hash is a hard equality: the TS ECF render of each type's data is byte-for-byte the Go render. This is the precondition the live `type_system` validate-peer category then confirmed (108 pass / 194 warn / 0 fail — the warns are the non-§9.5-floor types, matched-if-present). Escalation: closed (operator).

### A-009 — `origination` reclassified outside `--profile core` by the oracle · non-blocking · RESOLVED (S4 finding)
The lifecycle `PHASE-S4-CONFORMANCE.md` table lists `origination` as an **extension-free category required for v0.1**. The authoritative v7.72 §9.0 oracle (`cb54f5b`) instead **auto-allowlists origination as "outside --profile core — extension-only category."** Exercised under the *full* profile with the Go `entity-peer` as `-reference-peer`: the core-reachable checks **`reference_connect` + `reference_ready` PASS** (TS outbound dispatch to a foreign peer works), while the 3 fails are 100% extension over-demand — `async_202_A` (ASYNC §1 `deliver_to`/202), `rexec_put_b` + `xsub_setup_transport` (NETWORK §10 cross-subscription + a cross-peer capability the harness never grants). So the core verdict's origination skip is **oracle-sanctioned, not a peer gap**, and the lifecycle doc's "required for v0.1 / extension-free" row is now stale vs v7.72 §9.0. C# left this as "needs -reference-peer"; this run resolves the actual reason. Escalation: research → arch (reconcile `PHASE-S4-CONFORMANCE.md` with v7.72 §9.0; candidate shared finding alongside F18). **→ Logged as shared finding F23 and FIXED:** the lifecycle gate doc now defines the gate as `validate-peer --profile core` and reclassifies origination extension-only. Closed.

### A-007 — handlers-handler register/unregister · RESOLVED (Phase B / F1, v7.74 §6.13(a))
The `system/handler` register/unregister handler is now implemented behaviorally (the v7.74 §6.13(a) MUST — a 501 stub is non-conformant). `register` does the five normative writes (manifest / types / grant / grant-sig at `system/signature/{grant_hash}` / interface); `unregister` reverses them with writer symmetry. A dynamically-registered handler resolves by tree walk and dispatches its entity-native body (see A-011). The types handler (`validate`, SHOULD) remains deferred (extension-tier). Verified by `foundations.test.ts` mirroring `entity-core-go/cmd/internal/validate/core_register_gate.go`.

### A-008 — `supports_revocation = false` · non-blocking · RESOLVED (S3, conformant)
The peer advertises no persistent-capability extension, so `supports_revocation = false` is conformant (§5.2). The `revoke` op + the dispatch-time chain-revocation walk are implemented (a revoked link denies with 403 `capability_revoked`), but there is no durable revocation store beyond the in-memory tree. Mirrors peer #1 A-005.

### A-011 — §10.1 register dispatch round-trip pulls compute/entity-native vocab into the core gate · Phase B / F1 · ESCALATE: arch
Cross-impl with C# A-011. The Go `core_register_gate.go` §10.1 round-trip hardcodes Go's *entity-native compute* as the body-binding seam: it puts a `compute/literal(42)` at `<pattern>/expr`, registers with `expression_path`, dispatches op `compute`, and asserts the response round-trips `42`. But `EvaluateExpression` is the **compute extension's** pluggable seam in Go — a pure core peer has nothing wired, so the `--profile core` round-trip can't pass without a core peer evaluating a `compute/literal` (extension vocab pulled into the core gate). Keystone ships the minimal literal-only body-binding seam (`Dispatcher.#runEntityNative` → reads `compute/literal`, emits `compute/result`; type LABELS only, NOT in the §9.5 floor) to keep the round-trip GREEN; richer bodies 501. The five writes (gate steps 1–3, 5) are unambiguous core and fully covered; only step 4 carries the coupling. Options for arch/Go: (a) §10.1 SKIPs step 4 for non-compute peers; (b) a minimal `compute/literal` evaluator is declared core body-binding floor (→ belongs in spec); (c) peer-declared body-binding-seam negotiation. Verified by `foundations.test.ts`.

### A-012 — unregister type-teardown + system-path registration guard · Phase B / F1 · informational
Cross-impl with C# A-012. `unregister` removes manifest, interface, grant, and grant-signature (writer symmetry — the half-removed grant/sig state is the hazard the §10.1 teardown coverage prevents). It does NOT remove installed `system/type/*` entities — types may be shared, so blind removal is unsafe with no spec-pinned ownership/refcount model; left in place. System-path registration is governed solely by the dispatch cap-check on `EXECUTE.resource` (`system/*` scope required), per §6.2's registration-cap examples — no separate user-vs-bootstrap guard.

---

## Spec ambiguities (S2+)
*(none surfaced — the codec authored cleanly from V7 spec-data v7.72 / ENTITY-CBOR-ENCODING v1.5; 69/69 byte-identical first run. **S3 likewise surfaced no new spec ambiguity**: the peer machinery ported faithfully from the V7-grounded C# reference and reached smoke-green; the open items above are profile/scope decisions, not spec gaps. Spec-level findings carried from peer #1 remain F12/F18/F19/F20 — see below.)*

---

## Referenced shared findings (carried from peer #1 — see SPEC-FINDINGS-LOG.md)
- **F7** — corpus tops out at i64::MAX; no `[2⁶³, u64::MAX]` probes. **TS is most exposed** (R1 BigInt surface). Mitigation: author our own boundary vectors; push arch.
- **F12** — §4.6 nonce-echo not mandated (replay risk). Implement the echo check anyway; push arch to make it explicit. Highest-value open security item.
- **F20** — F14 memo "401→403" contradicts oracle + cohort; request-time auth-class sig failure is **401**. Spec-first; do not implement off the stale memo.
