# Architecture Review — entity-core-protocol-go (clean-room peer)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data
**v7.75**; codec corpus v0.8.0. · **Audience:** architecture (spec-tightness feedback) +
operators (publishing decision). · **Status:** `validate-peer --profile core` PASS ·
**653 / 291P / 268W / 0F / 94skip** @ oracle `entity-core-go 75c532e` · codec 69/69 ·
§9.5 registry 53/53 · origination-core 3/3.

This review follows the format/depth of the Zig peer #4 and Common-Lisp peer #5
`ARCHITECTURE-REVIEW.md` (themselves extensions of the three-peer architecture
milestone review). Part A is
the idiom-fidelity + spec-refinement retrospective; Part B is the publishing-options
decision surface; Part C is the one-paragraph arch summary.

**The honesty up front — what this peer is and is not.** Every prior peer in the cohort was
a *different language from the oracle*, so each carried two kinds of value: an independent
conformance cross-check **and** a fresh-idiom spec-refinement probe. **This Go peer carries
only the first.** Go *is* the reference oracle's language (`entity-core-go`). A clean-room Go
peer therefore reaches for the *same idioms the oracle reaches for* — stdlib `crypto/ed25519`,
a hand-rolled canonical CBOR codec, goroutines + channels, `sync.RWMutex`, `(T, error)`
returns. There is **no fresh-idiom axis to probe** here, so the spec-*refinement* signal is
**structurally bounded**: this peer was never going to surface a class of contradiction the
GC-vs-no-GC / exceptions-vs-result / String-model peers surfaced, because its idiom *is* the
baseline. Stating this plainly is the point: **the value of this peer is the independent
cross-check (a from-scratch, stdlib-only Go reimplementation byte-agrees with the Go oracle),
plus idiom completeness — NOT novel spec discovery.** It produced exactly one notable
spec-signal (A-GO-006, a *corroboration*, not a new finding), and that is the honest yield, not
an under-delivery.

---

## PART A — Architecture review

### A.0 The thesis this peer tests

The cohort thesis: *if the spec is tight, independently-derived peers converge on the same
conformance fixed point with no behavioral divergence.* Prior peers tested that thesis across
maximum **idiom distance** (no-GC Zig, CLOS Common-Lisp, ARC Swift, lazy Haskell, BEAM Elixir).
This peer tests a different and arguably sharper corner of the same thesis: **what happens when
an independent implementation is built in the oracle's own language, clean-room?**

If "spec-determines-bytes" is true, then a Go engineer who reads only the V7 spec — never the
oracle source — should produce byte-identical wire output to the oracle, because both are
Go programs encoding the same spec. If instead the oracle's byte output depended on
*Go-specific incidental choices not in the spec* (library quirks, struct field order, map
iteration, float formatting), an independent Go peer would diverge despite sharing the language
— and that divergence would be a spec-tightness defect hiding in plain sight, invisible to
every cross-language peer because they'd each attribute it to "language difference."

**Result: the thesis held, cleanly.** The clean-room Go peer reaches the identical 0-FAIL fixed
point — codec 69/69 byte-identical first run (0 codec fixes), §9.5 53-type registry 53/53
byte-identical first run, full `--profile core` 0-FAIL. **This is the strongest available
evidence that the oracle's bytes are determined by the spec and not by Go-incidental choices:**
a *second, independent* Go program, given only the spec, reproduces them exactly. A
cross-language peer cannot make this claim — it can only show "different language, same bytes,"
which leaves open "would a second same-language impl agree?" This peer closes that question for
Go, the one language where it was open. **That is the independent-cross-check value, and it is
the reason this peer was worth building even though its spec-refinement yield is bounded.**

### A.1 The clean-room constraint — how it was honored end-to-end

Go being the oracle's language makes the clean-room discipline both *harder to keep honest* and
*more valuable when kept*. The discipline, enforced at every phase (full record in
`arch/PROFILE-RATIONALE.md` §Clean-room constraint):

- **S1 (profile/rationale):** read only `spec-data/v7.75` (the SHA-pinned verbatim V7 snapshot),
  the keystone `shared/lifecycle` contracts, the cohort's **language-neutral** sibling profiles
  (csharp/typescript/zig — read for *lifecycle shape*, not Go content), the existing
  `containers/go/Containerfile`, and seeded memory. **Never opened, `cat`/`grep`/`find`'d, or
  referenced any file under any `entity-core-go` checkout** — not its codec, not `validate-peer`,
  not `wire-conformance`, not its `go.mod`. Every protocol-shaped decision grounds in a V7
  §-pointer.
- **S2–S3 (codec + peer):** the Go idioms (hand-rolled canonical CBOR, stdlib crypto, goroutines,
  `sync.RWMutex`, `%w`-wrapped errors, gofmt naming) are what *any* competent Go engineer reaches
  for from the spec's requirements + general Go ecosystem knowledge — **not** observed oracle
  behavior. The codec was byte-green *before the peer existed*, which is itself clean-room
  evidence: if it matched only after seeing the oracle, the timeline would expose that. It didn't.
- **S4 (conformance):** the clean-room rule governs **build-time source isolation** — it does NOT
  forbid validating the peer's *output bytes* against the oracle (that byte-comparison is exactly
  how conformance is proven). The oracle binaries were built from the **committed** snapshot
  `75c532e` via `git archive` into a temp dir **OUTSIDE** the oracle tree, never cd'd into it,
  no build artifact leaked back (verified: `git status` on the oracle tree shows zero new files).
- **S5 (this phase):** **still** no oracle source read. This review frames the peer's value from
  its *own* conformance record and the spec, not from any oracle comparison of *design*.

The payoff of keeping it honest: the byte-agreement is *meaningful*. If the wall had leaked, "a
Go peer matches the Go oracle" would be circular. Because it didn't, the match is the
independent corroboration described in A.0.

### A.2 Spec-refinement value — the honest, bounded yield

The keystone's *end* is spec refinement. This peer's harvest is deliberately small, and small
**for a structural reason** (the same-idiom bound), not for lack of rigor:

**The one notable signal — A-GO-006 (§5.2 401/403 trichotomy), as *independent convergence*.**
§5.2's request-verification pseudocode collapses every failure to a flat "DENY → 403," but §4.6
distinguishes *authentication* (401 — the caller never proved *who*) from *authorization* (403 —
the capability doesn't admit), §5.5 carves out an *unresolvable-grantee* condition, and §4.10(b)
makes chain-depth excess a *structural* 400 (an explicit arch ruling). Built from the spec, this
peer implemented `verifyRequest` as a **4-way verdict** (`authnFail→401`, `authzDeny→403`,
`unresolvableGrantee→401`, `chainTooDeep→400`) rather than the flat ALLOW/DENY the §5.2
pseudocode literally reads. **The finding is the convergence, not the verdict:** a clean-room Go
peer — built from the spec, NOT the oracle — independently lands on the *same trichotomy* the
spec-first cross-language cohort hit (Zig A-ZIG-006, OCaml A-OC-008, Swift A-SW-010, Common-Lisp,
arch F20). The cohort is now **5+ independent peers**, one of them in the oracle's own language,
all reading §5.2's flat DENY as an under-specification and resolving it to the 3-way
authn/authz/unresolvable split + the §4.10(b) 400. **Arch ask:** none new — this entry adds the
Go peer to the convergence count so the count is visible; F20 already tracks the item, and the
cohort's signed-off 576/0F state already *encodes* the trichotomy. The Go data point's specific
weight: it shows the trichotomy is what the spec implies *regardless of language*, since even the
oracle's own language, derived independently, reaches it — closing the "maybe it's a
cross-language artifact" door.

**Why there is no A-GO-001-class headline (the peer-id finding).** The two highest-value spec
defects the cross-language cohort surfaced were the §7.4-vs-§1.5 peer-id construction (OCaml
A-OC-007 / Zig A-ZIG-001) and the 401/403 boundary. This peer **independently reproduces the
correct §1.5-canonical peer-id** (`hash_type=0x00` identity-multihash, lowercase `%02x` hex
tree-paths) — validated live (connectivity 22/0F + `authz` rows). But by S5 the §7.4-vs-§1.5
contradiction was already a **settled, 3-spec-first-peer DECISIVE arch fix**, carried into this
peer as a *pre-resolved cohort trap* in the profile (not re-litigated). A clean-room peer built
*after* the resolution lands on the resolved reading; it does not re-surface the contradiction as
"new." Recording this honestly: the peer corroborates the *fix*, it did not re-discover the
*defect*. That is the same-idiom bound in action — there was no fresh idiom to make the peer trip
the original trap a sixth time.

**No new ambiguities surfaced at S4.** The §9.5 registry render matched the canonical vectors
byte-for-byte on the first run, so no field-shape guesses were needed (contrast peers that had to
guess omit-empty ordering and got caught by the byte-diff). A clean first-run byte-match is itself
a (quiet) corroboration that the §9.5 type-shape spec is unambiguous enough that an independent
Go reading reproduces it exactly.

### A.3 The Ed448 gap — A-GO-002, the one *cross-cohort* contribution that is genuinely new-ish

The peer's most novel non-§5.2 contribution is **negative evidence**, and it is a real cross-cohort
data point: **Go's stdlib has no Ed448, AND `golang.org/x/crypto` has no Ed448 either** (it carries
ed25519-adjacent + NaCl-family primitives, not the Ed448/Goldilocks curve), and **no audited
pure-Go Ed448 exists in a reviewed channel** (Go has no BouncyCastle-equivalent). This is the
**same gap Zig (A-ZIG-002) and OCaml (A-OC-002) hit** — and the Go data point *strengthens* the
cross-cohort finding specifically because Go has the **largest, most-resourced standard library +
official `x/` crypto extensions of any peer in the cohort.** If even Go — the oracle's own
language, with the deepest official crypto surface — lacks a reviewed-channel Ed448, then the
"second managed-crypto provider" route that rescued C# (BouncyCastle) provably **does not
generalize**. Three independent peers now confirm it from three different ecosystems, the third
being the best-resourced.

This does **not** affect the ECF/Ed25519 conformance floor (Ed25519 is native + 69/69 byte-green;
SHA-384 agility hashing is native via `crypto/sha512`); it blocks only the agility *higher bar*
(Ed448 + SHA-384 matrix), which is **out of the v7.75 `--profile core` scope** (the core target is
Ed25519+SHA-256). The recommended shape when agility enters scope is **hybrid**: native Ed25519
(shipped) + **FFI Ed448 only** via cgo (consume `libentitycore_codec` for the one family the
ecosystem can't supply). Go's C-ABI FFI (cgo) is first-class, so this hybrid is clean in Go — and
it is the *same* resolution Zig and OCaml independently recommended. **Explicit non-v0.1 item,
logged not papered over, gated behind the agility scope decision.**

### A.4 Codec / transport / concurrency retrospective

**Codec — convergent, native, tied-lightest in the cohort.** Hand-rolled canonical CBOR (the
A-005 pattern every native peer hit): shortest-float ladder (f16 ⊂ f32 ⊂ f64, narrowest bit-exact
round-trip), length-then-lex map-key sort on encoded key bytes, definite lengths, no-duplicate-keys,
recursive major-type-6 tag rejection on **decode** → `400 non_canonical_ecf`, head-form int carrier
over native `uint64`/`int64`. **69/69 byte-identical, first run, 0 codec fixes.** Go's distinctive
posture: **stdlib-only, zero third-party modules, `go.sum` empty** — `crypto/ed25519` +
`crypto/sha256` + `crypto/sha512` ship in-tree, so the *entire* peer pulls nothing off any registry,
matching Zig as the **lightest supply-chain posture in the cohort** (single S11 pin = the toolchain
version). The one credible Go CBOR library (`fxamacker/cbor`, with a CTAP2/Core-Deterministic encode
mode) was considered and rejected (A-GO-001): its deterministic mode doesn't give ECF's decode-side
guarantees for free anyway (tag rejection, decode-side shortest-float minimality, exact f16
special-value bytes, raw-byte `data` fidelity), byte-exactness for a content-addressing substrate
must be *owned* and proven vector-by-vector, and the hand-roll keeps `go.sum` empty.

**Integers — the cleanest int story in the cohort, tied with Zig.** Native `uint64`/`int64` carry
the §3.2 full range directly — no BigInt (contrast TS F7), no 63-bit trap (contrast OCaml A-OC-001).
The `[-2⁶⁴,-1]` `nint` band needs explicit `uint64` arithmetic on decode (the additional-info value
encodes `|n|−1`), an impl-carrier decision the spec correctly leaves open (A-GO-003); the wire form
is unambiguous. The standing corpus blind-spot (`[2⁶³,2⁶⁴−1]` unexercised, F7 / A-OC-001) applies
here too — Go is correct-by-construction there but the *corpus still doesn't probe it*.

**Concurrency — goroutines + channels, race-safe-from-day-one (the pre-resolved cohort trap).**
The shape is the spec-forced cohort shape: 4-byte BE length-prefix + CBOR @ 16 MiB cap; one reader
goroutine per connection demuxing `EXECUTE_RESPONSE` by `request_id`; each inbound EXECUTE on its
own goroutine so it never blocks outbound (§6.11); transport-agnostic dispatch brain. The §4.8
content store is `sync.RWMutex`-guarded (read-mostly: resolves are reads, binds are writes), with
emit consumers firing **outside** the lock and `SetNoDelay(true)` on every connection. **This was
built race-safe from S3 by design** — the exact §7b store-race + Nagle-throughput traps that
flushed the Zig and Common-Lisp peers under the T2.1 sustained-load probe were *pre-resolved* in
the Go profile (`store_safety = sync.RWMutex`, `tcp_nodelay = true`), so the Go peer never opened
the race window. Validated live: the oracle's `concurrency` category is **5/5 PASS** under
`--profile core` (incl. the T2.1 store-race probe), plus the S3 8-way `request_id` demux smoke.
(`go test -race` did not complete in-env — the cgo race-detector build stalled twice; **non-gating**,
the store safety is *structural* and carried by the live concurrency gate. See PHASE-S4.md.)

**Error model — `(T, error)`, the Go-native result idiom.** Explicit `(T, error)` returns; sentinel
+ typed errors wrapped with `%w`, discriminated via `errors.Is`/`errors.As` (never string-match);
typed error → status code at the dispatcher boundary (400/401/403/413). `panic` only for unreachable
invariants, with `recover` at goroutine boundaries so one bad connection never crashes the peer
(§4.9). This is the Go analogue of the cohort's converged "protocol status is a value record, never
carried by the exception *type* across dispatch."

### A.5 Where this peer sits vs the cohort

| Axis | C# (#1) | OCaml | Zig | Common-Lisp | **Go (clean-room)** |
|---|---|---|---|---|---|
| Derivation | reference | spec-first | spec-first, distant idiom | spec-first, CLOS idiom | **spec-first, *oracle's own language*** |
| Idiom vs oracle | different | different | maximally different | very different | **identical (the point)** |
| Memory | GC | GC | no-GC, allocators | GC | **GC (= oracle)** |
| Error model | exceptions | result ADT | error unions | condition system | **`(T, error)` (= oracle idiom)** |
| Codec | hybrid | hand-rolled | hand-rolled, comptime | hand-rolled | **hand-rolled** |
| Third-party deps | NSec, BouncyCastle | mirage, digestif | ZERO (std-only) | (Ed448 native) | **ZERO (stdlib-only)** |
| Int carrier | native `ulong` | unsigned-`int64` (A-OC-001) | native `u64` + trap | bignum | **native `uint64`/`int64`** |
| Ed448 agility | BouncyCastle | native gap (A-OC-002) | native gap (A-ZIG-002) | native | **native gap (A-GO-002), best-resourced stdlib** |
| Spec-refinement yield | (reference) | A-OC-007 ⚑ + A-OC-008 ⚑ | A-ZIG-001 ⚑ + A-ZIG-006 ⚑ | hex-case ⚑ NEW | **A-GO-006 (corroboration only) — bounded by same-idiom** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |

**Position:** this peer is the cohort's **same-language independent cross-check + supply-chain
floor.** It is the *only* peer that can answer "does a *second* implementation in the oracle's own
language, built clean-room, byte-agree?" — and it does, which is the strongest single piece of
evidence that the oracle's bytes are spec-determined rather than Go-incidental. It re-confirms the
two standing spec defects (peer-id construction, now resolved; 401/403, now 5+ peers) from the
oracle's own idiom, closing the "cross-language artifact" door on both. It is tied for the cohort's
lightest supply-chain posture (stdlib-only, zero third-party modules), and it sharpens the Ed448
cross-cohort finding by showing even the best-resourced stdlib lacks a reviewed-channel Ed448. Its
spec-*refinement* yield is honestly bounded by the same-idiom constraint — and that bound is itself
a documented data point: it tells the keystone that a same-language peer's value is corroboration +
the cross-check, not fresh discovery, which is useful for deciding whether to build more
same-language peers (recommendation: no — the cross-check is a one-time win, now banked).

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/go/` (current keystone default).**
Per-language sibling repos are deferred keystone-wide (S10); all peers live in the keystone
monorepo today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the peer reads
    `../shared/...` directly); cross-peer changes (spec bumps) land atomically; the CI workflow's
    relative paths (`/work/protocol-generator/go/src`) already assume this root.
  - *Against:* a Go consumer `go get`-ing the module pulls by the **module path**, which must
    resolve to a repo where `go.mod` sits at a path the proxy can fetch. Today `go.mod` is at
    `protocol-generator/go/src/go.mod` inside the monorepo — `go get` against the monorepo root
    would need the module path to encode that subdirectory, OR a tag scheme
    (`protocol-generator/go/src/v0.1.0-pre`) the Go tooling supports for sub-module repos but which
    is awkward. **This is the go.mod-path nuance** (see B.2) and is the main reason a standalone
    repo is cleaner for Go than for Zig.

**Option 2 — lift to a standalone `entity-core-protocol-go` repo (S10).**
  - *For:* `go.mod` at the repo root → the module path `github.com/entity-core/entity-core-protocol-go`
    resolves directly, tags are plain `v0.1.0-pre`, `go get module@v0.1.0-pre` just works; a clean
    minimal fetch surface; a natural home for the CI workflow; `repository_url` becomes concrete.
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then need a cross-repo sync; it is an S10 step
    the keystone has **deliberately deferred cohort-wide** — doing it for Go alone fragments the
    uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Go-specific) — the module-path / tag nuance

Go has **no central package-upload registry** (no crates.io/npm/NuGet equivalent). "Publishing" is:
  - **(a) A git tag the consumer `go get`s by module path + checksum (the Go-idiomatic path).** The
    import path *is* the repo URL; the version *is* a SemVer git tag; the checksum is recorded in the
    consumer's `go.sum` + the public `sum.golang.org` transparency log. A consumer adds
    `require github.com/entity-core/entity-core-protocol-go v0.1.0-pre` and `go get` fetches +
    checksum-pins. **Decentralized + checksum-pinned by design** — supply-chain-friendly. No publish
    command, no index submission.
  - **The module-path / tag nuance (document, don't necessarily act):** Go resolves a module path to
    a repo + an *in-repo directory where go.mod lives.* For the **standalone-repo** case (Option 2)
    `go.mod` is at root → tags are plain `v0.1.0-pre`, trivial. For the **in-repo monorepo** case
    (Option 1), `go.mod` is at `protocol-generator/go/src/`, so the module would either need its path
    to encode that subdir (and tags prefixed with the subdir per Go's
    [sub-module tagging](https://go.dev/ref/mod#vcs-version) rule), or — cleaner — the standalone-repo
    lift. **Recommendation: do not git-tag at all for v0.1.0-pre.** A `-pre` release is parked pending
    arch sign-off + a first consumer; tagging is the operator's deliberate final step (lifecycle
    §"no auto-tag"), and is cleanest *after* the in-repo-vs-standalone decision is made, because that
    decision determines the tag form. The version line lives in `CHANGELOG.md` + a `go.mod` comment
    until then.
  - **(b) Git submodule / vendored copy.** A consumer vendors at a pinned commit — coarser than (a)
    but fully offline and audit-friendly; appropriate for a same-supply-chain-stance consumer.
  - **(c) No central-registry submission** exists or is needed (contrast OCaml's optional
    `opam-repository` PR — Go has no analogue; the proxy/checksum-db is automatic, not a submission).

The **stdlib-only posture makes distribution trivial**: zero transitive deps means a consumer
inherits *no* lockfile fan-out — the only pin they take on is the Go toolchain version (`go 1.25`).

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant). Go itself is BSD-3-Clause
    and the ecosystem is mixed, but nothing mandates a license, so the safe Apache-2.0 default stands
    (`profile.toml [license]` — not overridden). No change recommended.
  - **Version: `0.1.0-pre`** (this phase). The cohort-wide pre-release line. **Promotes to `0.1.0`**
    only when (a) S4 fully green [met] AND (b) ≥1 external consumer confirms it works [not yet met].
    `CHANGELOG.md` tracks the spec version literally (`tracks V7 v7.75`); `go.mod` carries the
    spec/oracle pins in a comment.

### B.4 Public-surface freeze (what to prune/freeze before a real publish — document, don't act)

Go's `internal/` already gives compiler-enforced encapsulation — `internal/{cbor,base58,varint}`
are unreachable by consumers and may churn freely without a semver bump (a Go-native advantage no
other cohort language has as cleanly). The freeze surface that *remains*:
  - **Module root `package entitycore`** (Tier 1 codec island: `EncodeECF`, `DecodeECF`,
    `ContentHash`, peer-id format/parse, `NewIdentity`/`Sign`/`Verify`). This is the stable
    consumer contract; an explicit signature audit (do all exported names need to be exported? are
    any leaking internals?) is a mechanical publish-prep pass.
  - **`peer` subpackage** (Tier 2 full peer: `NewPeer`, `Serve`, config, store). Documented via
    godoc, **not yet frozen** with a semver lock — deferred until the surface is settled against a
    first external consumer (mirrors the Zig/OCaml deferral rationale).
  - **Recommendation:** defer the explicit freeze to publish-prep / first-consumer. The honest S5
    state for an all-source-in-repo peer is "surface documented, freeze pending a consumer," not a
    premature lock. Nothing to execute now.

### B.5 Recommendation (operator-decides — not acted on)

**For Go specifically, lean toward the standalone-repo lift (Option 2) *if/when* the cohort does its
S10 per-language-repo split — because the go.mod-path/tag nuance (B.2) makes a root-level `go.mod`
materially cleaner for `go get` than the subdir-in-monorepo form, more so than for any other cohort
language.** Until then, **keep in-repo at `0.1.0-pre`/Apache-2.0, do NOT git-tag** (the tag form
depends on the in-repo-vs-standalone decision, and `-pre` is parked pending arch sign-off + a first
consumer). Promote to `0.1.0` once the external-consumer gate is met. Hold the **Ed448 hybrid-FFI**
(A-GO-002) as an explicit post-v0.1 agility-scope item. **The operator decides; the pipeline does
not publish, tag, or push.**

---

## PART C — Summary for arch (one paragraph)

The clean-room Go peer is the cohort's **same-language independent cross-check**: it is the only
peer that can answer "does a *second*, independent implementation in the oracle's *own* language,
built without ever reading the oracle source, byte-agree?" — and it does, reaching the identical
0-FAIL fixed point with a codec 69/69 byte-identical first run, a §9.5 registry 53/53 byte-identical
first run, and a full `--profile core` 0-FAIL @ `75c532e`. That byte-agreement is the strongest
single piece of evidence that the oracle's wire bytes are **spec-determined, not Go-incidental** — a
claim no cross-language peer can make. Its spec-*refinement* yield is honestly **bounded by the
same-idiom constraint** (no fresh-idiom axis to probe): the one notable signal is **A-GO-006**, the
§5.2 401/403 trichotomy, now corroborated from the oracle's own idiom (5+ independent peers — the
Go data point closes the "cross-language artifact" door); the peer reproduces the resolved
§1.5-canonical peer-id but did not re-discover the §7.4 defect (settled before it was built). Its
genuinely cross-cohort contribution is **negative-evidence A-GO-002**: even Go — the best-resourced
stdlib + official `x/crypto` in the cohort — has **no reviewed-channel Ed448**, strengthening the
Zig/OCaml finding that the second-crypto-provider route does not generalize (hybrid-FFI is the path).
No new arch ask; the actionable items are already tracked (ratify the §5.2 401/403 split per F20;
the Ed448 hybrid-FFI is a non-v0.1 agility item). **The honest verdict: this peer was worth building
for the one-time same-language cross-check + the supply-chain floor, and its bounded spec yield is a
documented feature of building in the oracle's language, not a shortfall.**
