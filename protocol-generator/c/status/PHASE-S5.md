# Phase S5 — Publish (entity-core-protocol-c)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (Makefile `VERSION` + the `make dist` tarball name; the
`pkg-config` `Version:` carries the numeric `0.1.0` per convention — A-CL-010-style split). ·
**Spec basis:** V7 spec-data **v7.75**; codec corpus v0.8.0 (byte-stable v7.71→v7.75). · **Oracle:**
the v7.75 cohort baseline **`b30a589`**.

S5 polishes the S4-conformant peer #10 (the **10th byte-compatible core impl**, the cohort's last
untried memory axis) into a *ready-to-publish* artifact. `/entity-rosetta` never publishes (lifecycle
§Publishing) — this phase produces the artifacts + the runbook; an operator publishes when arch signs
off v0.1 AND a first external C consumer confirms it. C has **no central registry**, so "publishing"
is a `make dist` source tarball + a `pkg-config` `.pc` (distro packaging / vendoring consume them).
This doc is the release-readiness record + the operator handoff. The architecture review +
publishing-options decision surface + consolidated findings ledger live in
`status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **576** / 291P / 196W / **0F** / 89skip, machine-verified `summary.failed == 0` @ the v7.75 cohort oracle `b30a589` (`status/CONFORMANCE-REPORT.{md,json}`). 0 FAIL also at the `62044c5` subset (574) and the `7e5ab04` superset (631) → conformance-safe. `resource_bounds` 2P+1W active; `concurrency` 5/5. |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, 0 codec fixes, **ASan/LSan/UBSan-clean**. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (`make typereg` peer-side dual + live oracle `type_system_match`). |
| S3 two-peer loopback smoke | ✅ | 11/11; peer_id byte-identical to the cohort (seed `0x11` → `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`). |
| Ed25519 RFC-8032 KAT | ✅ | libsodium sign/verify; all-zero-seed → RFC-8032 TEST-1 pubkey KAT passes; sign→verify→tamper-reject passes. |
| `make test` clean | ✅ | conformance 69/69 + 13/13 self-tests, ASan/LSan/UBSan-clean, `-std=c11 -pedantic -Wall -Wextra -Werror` (no warnings). |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0 + libsodium ISC third-party notice). |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + consume + distribution). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre`, literally **"tracks ENTITY-CORE-PROTOCOL-V7 v7.75"**. |
| Package metadata (pkg-config + dist) | ✅ | `entity-core-protocol.pc.in` template + `make pc`/`make install`/`make dist` (source tarball). **No npm/Cargo/Maven manifest — C has no central registry** (§4). |
| Toolchain pin (S11) | ✅ | gcc 15.2.1-7.fc43 + make 4.4.1-11.fc43 + binutils 2.45.1-4.fc43 + **libsodium 1.0.22-1.fc43** — all via the reviewed fedora dnf channel (exact pin for repro; age floor relaxed but met). Zero registry-pulled ecosystem deps. |
| CI config (Podman, offline) | ✅ authored | `.github/workflows/c.yml` — runs `run-s2.sh` (codec 69/69 + sanitizers) + `run-s4.sh` (assert `summary.failed == 0`) + `run-origination-core.sh` (3/3) in the `c-toolchain` image, `--network=none`. Matches the cohort peers that ship a workflow (zig/swift/haskell). Committed for reviewability; not wired to a remote/CD by design. |
| Public API surface (Tier-1 frozen) | ◑ documented | the public header `include/entity_core/protocol.h` freezes the Tier-1 codec/crypto island (`ec_*` ABI, `-fvisibility=hidden` + `EC_API`); the Tier-2 peer/transport surface (driven via the `entity-peer-c` host) is documented in README §Consume but not yet exposed as a stable ABI — freeze deferred to publish-prep / first consumer (the OCaml `.mli` / Zig `root.zig` analogue). |
| Self-contained `.so` (A-C-006) | ◑ documented | Fedora `libsodium.a` is not `-fPIC` → the `.so` links shared `-lsodium` (normal `libsodium.so` `NEEDED`, reflected in the `.pc` `Requires.private`). The `.a` path is already self-contained. A private static libsodium in the `.so` needs a `-fPIC` libsodium build — a release-prep item, NOT a conformance one. |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-C-009 ⚑arch, A-C-008 ⚑mainline/arch, A-C-006 owner research/packaging, A-C-010/011 resolved, A-C-001 deferred — all named-owner-routed (§5 + ARCH-REVIEW Part D). |
| **Published / tagged** | ⛔ **deferred** | operator action — gated on arch v0.1 sign-off + a first external C consumer (§7). No auto-tag, no push, no deploy. (C has nothing to "deploy" to anyway — publishing is hosting the tarball at a tag.) |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external C consumer confirms it works — **not yet met** (no C consumer wired). Stays `0.1.0-pre`
until then.

---

## 2. What this peer ships

- **Static archive** `libentity_core_protocol.a` — fully self-contained (libsodium statically
  linked, `-fvisibility=hidden` + `ec_*` ABI + libsodium symbols localized). The primary C artifact.
- **Shared object** `libentity_core_protocol.so` — links the system `libsodium.so` (A-C-006).
- **Public header** `include/entity_core/protocol.h` — the single umbrella header; the frozen Tier-1
  codec/crypto ABI (`ec_value`, `ec_ecf_encode`/`ec_ecf_decode`, base58/varint/content_hash/peer_id,
  Ed25519 + SHA-256, `ec_random_bytes`).
- **pkg-config** `entity-core-protocol.pc` (rendered from `entity-core-protocol.pc.in` by
  `make pc`/`make install`) → `pkg-config --cflags --libs entity-core-protocol`.
- **Host executable** `entity-peer-c` (the S4 conformance driver: `--port`/`--debug-open-grants`/
  `--validate`, emits `LISTENING …`). Test/conformance only — not part of the published library
  surface.
- **Crypto:** Ed25519 + SHA-256 via libsodium — the one runtime dep, distro-channel. Ed448/SHA-384
  agility deferred (A-C-001; libsodium has no Ed448; the §9.1 floor is fully native).

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the **public header `include/entity_core/protocol.h`** — the Tier-1
codec/crypto island (`ec_value` tree, canonical ECF encode/decode, base58, multicodec varint,
content_hash, peer_id, Ed25519 sign/verify, SHA-256, CSPRNG). `-fvisibility=hidden` + the `EC_API`
export macro hide everything else; libsodium's symbols are localized (objcopy) so an embedder's own
libsodium does not collide. The **Tier-2 full peer/transport** (`Peer`/`Transport`, the store +
capability surface) lives in `src/*.h` and is driven via the `entity-peer-c` host binary — it is
**not** part of the frozen public header at `0.1.0-pre`. Exposing it as a stable Tier-2 ABI (a
second public header or an export pass) is a mechanical publish-prep step, deferred until the surface
is frozen against a first external consumer — the honest `-pre` state (mirrors the OCaml `.mli` / Zig
`root.zig` deferral). Internal units (varint, base58, wire framing, the type-registry render table)
may churn without a semver bump.

---

## 4. Packaging notes specific to C

- **C has no central package registry (no npm/Cargo/Maven/Hex/Hackage/opam manifest).** This is why
  there is no `package.json`/`Cargo.toml`/`pom.xml` here — there is nothing for one to feed. The
  distribution surface is the **`make dist` versioned source tarball + the `pkg-config` `.pc`**, the
  autotools/Make convention, consumed by distro packagers (a Fedora `.spec` / Debian `control` wraps
  the tarball; the `.pc` makes that mechanical) or by direct vendoring. The most decentralized stance
  in the cohort, sibling to Zig's tagged-tarball-by-hash.
- **The `-pre` marker / numeric-`.pc` split (A-CL-010-style).** The `Makefile` `VERSION` and the
  `make dist` tarball name carry the full `0.1.0-pre`; the `pkg-config` `Version:` field is
  dotted-numeric-only by convention, so it carries the numeric `0.1.0` (Makefile `PC_VERSION`). Same
  split Common Lisp hit with ASDF's dotted-integer `:version`. The CHANGELOG/README carry the full
  `-pre`.
- **The self-contained `.so` is the one C-specific release work item (A-C-006).** Fedora's
  `libsodium.a` is not `-fPIC` → it cannot link into the peer `.so` (`R_X86_64_PC32`). The `.a` path
  statically links the distro `libsodium.a` (self-contained); the `.so` links shared `-lsodium`
  (`Requires.private: libsodium` in the `.pc`). A private static libsodium in the `.so` needs a
  `-fPIC` libsodium built from source (the manylinux-style rebuild already flagged for old-glibc
  portability) — a release-prep step, not a conformance one. **Does not block v0.1**; the `.a` path
  already meets the self-contained goal.
- **Simplest supply chain in the cohort.** One audited C lib (libsodium, reviewed distro channel) +
  the toolchain; **zero** registry-pulled ecosystem deps (CBOR/base58/varint/test-harness all
  hand-rolled in-repo). A consumer of the `.a` inherits no transitive runtime deps; a consumer of the
  `.so` takes on only the system `libsodium.so`.
- **Crypto-agility — Ed25519 + SHA-256 NATIVE, Ed448 deferred (A-C-001).** libsodium closes the
  §9.1 floor (69/69 byte-green) but has no Ed448. When agility lands, the dependency-lightest route
  is the sibling FFI codec's vendored Ed448 `.a` (a C-to-C *static link*, not a foreign bridge — novel
  for C) or OpenSSL `EVP_PKEY_ED448`. An explicit non-v0.1 item; does not affect the floor.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-C-* items are resolved-in-peer and routed; none block release. The arch escalation bundle
(full text in `status/SPEC-AMBIGUITY-LOG.md`; consolidated table in `ARCHITECTURE-REVIEW.md` Part D):

- **A-C-009 ⚑** §4.8 shared-entity refcounts MUST be atomic/lock-guarded on a multi-threaded peer —
  **owner: arch** (NEW; the cohort's only *behavioral* §4.8 finding). A plain-`int` refcount raced
  under live §7b load → heap-use-after-free (22 of 31 run-1 FAILs were that one crash cascading);
  fixed with `atomic_int`. Only a no-GC manual-memory peer surfaces it (the GC'd/actor/STM/ARC cohort's
  runtimes own object lifetime). Recommend a §4.8 conformance note. Sibling to A-JAVA-010.
- **A-C-008 ⚑** the 9-peer scorecard's v7.75 oracle label `62044c5` is off-by-one — `b30a589` folds
  `catResourceBounds:true` into core and yields the recorded 576·0F·89S — **owner: mainline/arch**.
  Verified read-only; 0-FAIL at the 574 subset / 576 baseline / 631 superset → conformance-safe; the
  correction is bookkeeping. Surface so the scorecard's recorded oracle commit reads `b30a589`.
- **A-C-006** Fedora `libsodium.a` not `-fPIC` → self-contained `.so` is an S5/publish concern —
  **owner: research/packaging**. The `.a` path is already self-contained; non-blocking.
- **A-C-010** clock-nonce cross-connection replay (F12) — **owner: peer**, RESOLVED (CSPRNG nonce).
- **A-C-011** §4.5 negotiation / §1.4 path validation / §2.6 delegate-501 / §6 ops-match — **owner:
  peer**, RESOLVED (peer bugs, spec-clear).
- **A-C-001** Ed448 native gap — **owner: research/agility**, DEFERRED (3rd+ peer; sibling-FFI-`.a`
  route novel for C). Does not affect the §9.1 floor.
- **A-C-002 / -003 / -007** spec-snapshot header / §7a-§7b scaffolding source / oracle-HEAD
  provenance — **owner: research/operator**, non-blocking notes.
- **A-C-004 / -005** pthreads / native-codec — **owner: operator**, RESOLVED local decisions.
- The §1.5-vs-§7.4 peer-id contradiction is built-to-§1.5 (PRE-RESOLVED P1); the **5th+ spec-first
  corroboration** — no new ask, corroboration from the most-distant memory idiom.

---

## 6. The provenance-correction handoff item (A-C-008) — for the orchestrator

**The single item for the orchestrator's merge/handoff to surface upstream** (full treatment in
`ARCHITECTURE-REVIEW.md` §A.5). The 9-peer cohort scorecard records its v7.75 oracle as `62044c5`,
but that is **off-by-one-commit**: at `62044c5` `resource_bounds` SKIPs under `--profile core`
(`catResourceBounds` absent from `coreProfileCategories` → 574·0F·90S, exactly what this peer scored
there); the **next commit `b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds
enumerated") adds `catResourceBounds: true` → `resource_bounds` becomes ACTIVE → **576·0F·89S**, the
figure the scorecard records. So `b30a589` is the true v7.75 cohort oracle. **For the merge
decision:** the C verdict is **0 FAIL at the 574 subset, the 576 baseline, AND the 631 superset** →
conformance-safe regardless of which label is canonical; the correction is bookkeeping for the
scorecard, not a re-cert. Surface the off-by-one to mainline/arch so the recorded oracle commit reads
`b30a589`.

---

## 7. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar AND an
external C consumer confirms the peer:

1. **Decide in-repo vs standalone repo** (see `ARCHITECTURE-REVIEW.md` §B.1). Per-language sibling
   repos are deferred keystone-wide (S10); current default is in-repo under `protocol-generator/c/`.
2. **Resolve the self-contained-`.so` `-fPIC` libsodium question (A-C-006)** if a private-static `.so`
   is wanted — build a `-fPIC` libsodium from source to bundle, or accept the shared-`libsodium.so`
   `NEEDED` (the `.a` path is already self-contained). This is the one C-specific release work item.
3. **Settle the Tier-2 public-surface freeze** (§3): add a second public header (or an export pass)
   exposing the locked `Peer`/`Transport`/store surface, build-verified in the `c-toolchain` image.
4. **Promote version** `0.1.0-pre → 0.1.0` in the Makefile `VERSION` (+ `PC_VERSION` stays `0.1.0`)
   + `CHANGELOG.md` once the promotion gate (§1) is met.
5. **Set `repository_url`** in `profile.toml [publishing]` + the `.pc` `URL:` (currently the keystone
   repo; point at the per-language sibling repo if Option 2 is taken).
6. **Publish** — `make dist` produces `entity-core-protocol-c-<version>.tar.gz` (sources + header +
   `.pc.in` + LICENSE/README/CHANGELOG). Host it at a **tagged release**; optionally wrap in a distro
   `.spec`/`control`. There is no registry to submit to. **Tag the release** at the reviewed commit at
   this point only (lifecycle §"no auto-tag").
7. **Wire CI** (`.github/workflows/c.yml`: `run-s2.sh` + `run-s4.sh` assert `summary.failed == 0` +
   `run-origination-core.sh` in `c-toolchain`, `--network=none`) to the chosen repo's runner, or fold
   into the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): gcc 15.2.1 + make 4.4.1 + binutils 2.45.1 + libsodium 1.0.22 stay exact
   (reviewed distro channel); re-pinning is deliberate + reviewed. **Re-confirm 576·0F against a
   clean `b30a589` oracle** if the oracle is rebuilt (the `git archive` extract is reproducible).

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged — gated on
arch v0.1 + a first external C consumer; `0.1.0` promotion pending that consumer; Tier-2 surface
freeze pending; self-contained-`.so` `-fPIC` libsodium documented as release-prep; CI authored-offline
but not wired to a remote — by design). Regression GREEN (**S2 69/69 ASan/LSan/UBSan-clean · S3 11/11
· S4 576 · 291P/196W/0F/89S @ b30a589 · origination 3/3 · 53-type 53/53 · `make test` clean**).
Ambiguity log finalized + owner-routed (A-C-009 ⚑arch, A-C-008 ⚑mainline/arch, A-C-006/010/011/001
owners). Architecture review + publishing-options + consolidated findings ledger written
(`status/ARCHITECTURE-REVIEW.md`). The A-C-008 oracle-provenance correction stated for the
orchestrator (§6). Operator handoff (§7) prepared. **S5 objective met; the C peer #10 (10th
byte-compatible core impl, the cohort's last untried memory axis) is publish-ready and parked at
`0.1.0-pre` pending arch v0.1 sign-off + a first external C consumer.**
