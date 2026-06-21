# Phase S5 — Packaging + idiom-findings synthesis (entity-core-protocol-prolog)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **SWI pack version:** `0.1.0` (A-PL-019 — the pack
grammar is dotted-numeric only). · **Spec basis:** V7 spec-data **v7.75**; codec corpus v0.8.0. ·
**Oracle pin:** `entity-core-go @75c532e`.

S5 polishes the S4-conformant peer #13 — the cohort's **first logic-programming peer** — into a
*ready-to-publish* artifact AND writes **the idiom-findings synthesis**, which is the actual point of
the whole Prolog peer (the operator goal). `/entity-rosetta` never publishes — this phase produces the
artifacts + the runbook + the synthesis; an operator publishes when arch signs off v0.1.

> **THE DELIVERABLE is [`IDIOM-FINDINGS-SYNTHESIS.md`](IDIOM-FINDINGS-SYNTHESIS.md)** — what the
> protocol-as-a-logic-layer reveals. The §7 verdict below summarizes it; that file develops it with
> code excerpts. Read it first if you read one thing in this phase.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **653 / 291P / 269W / 0F / 93S** @ `entity-core-go @75c532e`, machine-verified `summary.failed == 0`. All 16 core categories 0-FAIL. **Re-ran GREEN in-container at S5.** ([`CONFORMANCE-REPORT.{md,json}`](CONFORMANCE-REPORT.md)) |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`) — proven at S4, the §6.11 seam |
| S2 lower bar (codec byte-identical) | ✅ | **69/69** vs `conformance-vectors-v1` through the foreign codec + **10/10** crypto KAT. **Re-ran GREEN at S5.** |
| §9.5 53-type floor byte-identical | ✅ | **53/53** (content_hash recomputed via the C-ABI codec through the Prolog surface, asserted == Go @75c532e). **Re-ran GREEN at S5.** |
| S3 two-peer loopback smoke | ✅ | **11/11** (handshake + dispatch + capability + 8-way request_id demux + emit hook + §7a echo). **Re-ran GREEN at S5.** |
| Ed25519 + Ed448 crypto KAT | ✅ | 10/10 — Ed25519 floor + Ed448 RFC-8032 (57-B pubkey, 114-B sig, §1.5 peer_id) byte-equal, via the C-ABI (A-PL-002/003: SWI library(crypto) has neither) |
| SWI pack loads + version validates | ✅ | `pack.pl` consults clean; `version('0.1.0')` passes `prolog_pack:is_version/1` in-container (swipl 9.2.9); `0.1.0-pre` is INVALID — A-PL-019 |
| LICENSE present (Apache-2.0, S9) | ✅ | [`LICENSE`](../LICENSE) (peer-local Apache-2.0; `profile.toml [license]`) |
| README + conformance line | ✅ | [`README.md`](../README.md) — build/run in-container, the FFI-floor architecture, the convergent-logic framing, the result line, the reproduce/version-gotcha |
| CHANGELOG (spec-version pinned) | ✅ | [`CHANGELOG.md`](../CHANGELOG.md) — `0.1.0-pre tracks V7 spec-data v7.75`; the A-PL-019 version-spelling note carried |
| Package metadata (`pack.pl`) | ✅ | name/title/version/author/home/requires/provides/keywords set; `download/0` deliberately unset (unpublished); version `0.1.0` (A-PL-019) |
| CI config (Podman, offline) | ✅ committed, ◑ not wired | [`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml) — the 3 gates sealed-offline in `prolog-toolchain`, asserting `failed==0`. Matches the zig/haskell/swift cohort pattern; **deliberately not wired to a remote/CD** (operator decides; common-lisp/ruby carry none) |
| Toolchain pin (S11) | ✅ | SWI-Prolog **9.2.9** (9.2.x stable line, A-PL-008) on fedora:43, image OpenSSL 3.5.4. The C-ABI floor (libentitycore_codec 1.1) is built in-container, gitignored. Zero runtime pack deps (crypto/socket/thread/dcg ship in the distribution) |
| Public API surface | ◑ documented | the module export lists in `prolog/ec_*.pl` ARE the surface (SWI has no module-private keyword beyond the export list); `ec_host.pl` is the conformance driver, not a stable surface |
| Ambiguity log finalized (owner + status) | ✅ | [`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md) — A-PL-006/013/014 → research/arch; A-PL-019 → operator; all S1–S5 items resolved-in-peer |
| Idiom-findings synthesis | ✅ | [`IDIOM-FINDINGS-SYNTHESIS.md`](IDIOM-FINDINGS-SYNTHESIS.md) — **the deliverable** |
| **Published / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6). No auto-tag, no push, no pack-registry submission |

**Promotion gate `0.1.0-pre → 0.1.0`:** (a) S4 fully green ✅ AND (b) ≥1 external consumer confirms it
works — **not yet met** (no SWI-Prolog consumer wired). Stays `0.1.0-pre` (pack version `0.1.0`) until then.

---

## 2. What this peer ships

- **SWI pack** — `pack.pl` (name `entity_core_protocol`, version `0.1.0`, Apache-2.0). The module set
  under `prolog/` is the source; **zero runtime pack dependencies** (`library(crypto/socket/thread/dcg)`
  all ship inside the SWI distribution). The C-ABI byte-floor (`libentitycore_codec` + the SWI foreign
  shim `c/ec_codec_pl.c` → `ec_codec_pl.so`) is **byte-built** by `run-s2.sh` in-container — gitignored,
  not shipped as source; only the C source + the build script are committed.
- **The FFI-floor architecture** (README §FFI floor): the Prolog relational core
  (`ec_capability`/`ec_peer`/`ec_store`/`ec_transport`/`ec_cbor`) over the C-ABI byte-floor via the
  deterministic (`once/1`) `ec_codec.pl` seam. No external `ffi` pack.
- **Host driver** (`prolog/ec_host.pl`): the S4 conformance target (`--port`/`--debug-open-grants`/
  `--validate`; emits `LISTENING …`). Test/conformance tooling only — not a stable surface.

---

## 3. Packaging notes specific to SWI-Prolog

- **SWI pack version grammar is dotted-NUMERIC only (A-PL-019, NEW).** `prolog_pack:is_version/1`
  splits on `.` and requires every component to `number_string` — so it rejects `0.1.0-pre`,
  `0.1.0pre`, `0.1.0_pre`, `0.1.0-alpha.1`, `0.1.0-1` (all verified INVALID in-container, swipl 9.2.9);
  only `0.1.0` is VALID. `pack.pl` carries `0.1.0`; the `0.1.0-pre` LINE lives in CHANGELOG/README.
  **This is the exact distant-idiom shape as Common Lisp's A-CL-010 (ASDF dotted-integer-only) and
  Ruby's A-RUBY-010 (RubyGems treats `-pre` as `.pre.pre`)** — the *third* cohort ecosystem whose
  version grammar disagrees with the SemVer dash, and the **strictest of the three** (SWI has no
  pre-release channel at all, where RubyGems at least accepts dotted `0.1.0.pre`). On promotion to
  `0.1.0`, `pack.pl` needs no change — only the docs drop the `-pre`. **Escalation: operator.**
- **Zero runtime pack dependencies.** Everything the peer uses from the SWI side ships in the
  distribution; the only external is the C-ABI floor, built in-container (not a pack dep). Lighter than
  the OO peers' multi-provider graphs.
- **Distribution = the pack registry.** `pack_install(Name)` resolves by name to a registered git URL /
  tarball, or installs from a URL directly; "publishing" registers the pack or sets `download(URL)` to
  the release archive at the reviewed tag (git-indexed, closer to CL's Quicklisp than to RubyGems'
  upload). Consumed today via `attach_packs/2` from the worktree, fully offline.
- **No compile gate (sharper than CL's).** SWI is dynamically typed with no static coverage pass — an
  undefined predicate isn't caught until it is *called*. Correctness rests entirely on the conformance
  corpus; the gates run from a clean `swipl` each time (no saved-state image).

---

## 4. Crypto-agility — primitives byte-proven, full MATRIX deferred (cohort-wide)

Ed25519 + Ed448 + SHA-256/384 are byte-proven via the C-ABI (KAT 10/10 — Ed448 RFC-8032: 57-B pubkey,
114-B sig, §1.5 SHA-256-form peer_id all byte-equal to the v7.71 pins), and the connect-path agility
slice is exercised (format_agility 10/10, crypto_agility 4/4, negotiation 4/4 in the S4 run). The
agility **full MATRIX** harness (the M2/M3/M6 key-type × hash-format cross-product end-to-end) is the
documented non-v0.1 item, deferred cohort-wide — no FFI or second provider is needed when it lands
(the C-ABI already carries both curve families). Does NOT affect the §9.1 floor (69/69 byte-green).

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-PL-* items are resolved-in-peer and routed; none block release. There are **no new ⚑ arch
*defect* asks** (the well was drained by the prior spec-first peers — the same dry-well-corroboration
result Ruby reported), but Prolog contributed the cohort's most distinctive *paradigm-fit* finding and a
useful FFI-peer note (full text in [`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md)):

- **A-PL-006** (the genuinely-Prolog finding) — the two-channel error model: relational failure for the
  dominant "deny", a thrown term only where the status class must diverge (the §5.5 401 carve-out, vs
  403). **Owner: research** (paradigm-fit landscape signal). Developed in `IDIOM-FINDINGS-SYNTHESIS.md` §2.
- **A-PL-013** — the C-ABI treats `data` as opaque; an FFI peer still owns data-value canonical CBOR.
  **Owner: arch** + note for the other FFI peers.
- **A-PL-011** — the public `ec_content_hash_with_format` rejects the forward-compat format_code 128 the
  corpus pins; compose from public symbols. **Owner: arch** (ABI-surface note; same class as A-OC-004/A-CL-007).
- **A-PL-010a** — Ed25519 `key_type = 0x01` (not 0x00); caught only by the cross-impl oracle.
  **Corroboration** of the standing §1.5 peer-id ask (OCaml A-OC-007, Zig A-ZIG-001, CL A-CL-002).
- **A-PL-002 / A-PL-003** (RESOLVED NEGATIVE) — SWI library(crypto) has no Ed25519/Ed448; whole signature
  floor → FFI. **Owner: research** (4th corroboration: OpenSSL-via-FFI is the recurring escape).
- **A-PL-014 / A-PL-004** — framed I/O + shortest-float are the irreducibly-imperative floor ("C with
  `:-`"); the C-ABI's job. **Owner: research** (paradigm-fit; expected, not a problem).
- **A-PL-007 / A-PL-015 / A-PL-016 / A-PL-017 / A-PL-018** — SWI concurrency/module footguns
  (resolved-in-peer; recorded so maintainers don't regress). **Owner: none** (impl discipline).
- **A-PL-019** (NEW, packaging) — SWI pack version grammar dotted-numeric only. **Owner: operator.**

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 bar AND an external consumer
confirms the peer:

1. **Decide in-repo vs standalone repo** ([`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md) §B.1).
   Per-language sibling repos are deferred keystone-wide (S10); current default is in-repo under
   `protocol-generator/prolog/`.
2. **Settle the public-surface freeze** (the module export lists): prune `ec_host`/test predicates from
   the shipped surface; build-verified in `prolog-toolchain`.
3. **Promote version** `0.1.0-pre → 0.1.0` in CHANGELOG/README. `pack.pl` `version('0.1.0')` is already
   correct (A-PL-019 means there is no `-pre`-in-`pack.pl` to bump).
4. **Set `download(URL)` in `pack.pl`** + `repository_url` in `profile.toml [publishing]` to the release
   archive at the reviewed tag.
5. **Register the pack** (the SWI pack registry, or distribute the git URL / tarball). There is no upload
   step distinct from registering the source location. **Tag the release** at the reviewed commit then.
6. **Wire CI** (`.github/workflows/conformance.yml` — the 3 gates in `prolog-toolchain`, `--network=none`,
   assert `summary.failed == 0`) to the chosen repo's runner, or fold into the keystone-wide CI home if
   arch defines one. No remote/CD attached today by design.
7. **Pin discipline** (S11): SWI 9.2.9 + the C-ABI 1.1 floor stay exact; re-pinning is deliberate + reviewed.

---

## 7. Phase exit — verdict

Release-readiness checklist green except the deliberately-deferred lines (published/tagged; `0.1.0`
promotion pending external consumer; public-surface freeze pending; CI committed-offline but not wired to
a remote — by design). **Regression re-ran GREEN in-container at S5:** S2 **69/69 + 10/10 KAT** · S3
type-registry **53/53** + smoke **11/11** · S4 **653 · 291P / 269W / 0F / 93S @ 75c532e** (machine-verified
`failed == 0`). The SWI pack loads clean and `version('0.1.0')` validates. The idiom-findings synthesis is
filed ([`IDIOM-FINDINGS-SYNTHESIS.md`](IDIOM-FINDINGS-SYNTHESIS.md)) and cross-linked from the README, the
CHANGELOG, and the architecture review.

**The synthesis verdict (developed in full in the deliverable):** the protocol expressed as a convergent
logic layer — the §5.5 chain as a recursive relation where *conjunction-failure IS the deny*, the §5.2
trichotomy as guarded clause heads, §6.6 dispatch as a multi-head clause table (the clause DB as router),
the §3.9 store as the clause database itself. The one place the logic idiom is genuinely too weak is
A-PL-006 (the §5.5 401 carve-out needs a thrown term because Prolog failure is mono-valued). The byte-floor
reads as "C with `:-`" (A-PL-014) and is legitimately the C-ABI's job (A-PL-002/004/013). **The protocol
does NOT resist Prolog — only the floor does. The revival was right.**

**S5: GREEN — 0.1.0-pre parked, synthesis filed**
