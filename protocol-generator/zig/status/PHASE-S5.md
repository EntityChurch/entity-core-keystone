# Phase S5 — Publish (entity-core-protocol-zig)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 spec-data v7.72 + v7.74
(§10.1 core-register + §9.5a CORE-TREE) closeout; codec corpus v0.8.0.

S5 polishes the S4-conformant peer #4 into a *ready-to-publish* artifact. `/entity-rosetta`
never publishes (lifecycle §Publishing) — this phase produces the artifacts + the runbook; an
operator publishes when arch signs off v0.1. This doc is the release-readiness record + the
operator handoff. The architecture review + the publishing-options decision surface live in
`status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 568 / 284P / 195W / **0F** / 89skip, machine-verified `failed==0` (`status/CONFORMANCE-REPORT.{md,json}`); re-run green in-container at S5 |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, 0 codec fixes |
| S7 higher bar (validate-peer core) | ✅ | same fixed point as C#/TS/OCaml, reached spec-first |
| `zig build test` leak-clean | ✅ | `std.testing.allocator` — codec 69/69 + A-ZIG-008 byte-diff + deletion-marker + §7a echo |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy) |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, std-only story, verdict + reproduce) |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.72 + v7.74 closeout` |
| Package metadata (`build.zig.zon`) | ✅ | std-only, `.dependencies = .{}`, version `0.1.0-pre`, `minimum_zig_version 0.15.1`, spec/oracle pins recorded; build-verified in-container |
| Toolchain pin (S11) | ✅ | Zig **0.15.1** (≥30-day, ~10mo); `containers/zig-toolchain` (official tarball SHA-256 + minisign-verified). Zero registry-pulled deps → supply-chain trivial |
| CI config (Podman, offline) | ✅ authored, not wired | `.github/workflows/conformance.yml` — runs the 3 gates in `zig-toolchain`, `--network=none`, asserts `failed==0`. **No remote/CD attached** (operator/arch decides the CI home — §6) |
| Public API surface | ◑ documented | re-exported from `src/root.zig`; README §Use Tier-1/Tier-2. Explicit semver lock deferred to publish-prep / first consumer |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-ZIG-001/005/006 routed to arch (§5) |
| **Published / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) — no auto-tag, no push, no registry submission |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not
yet met** (no Zig consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **`build.zig` package** `entity_core_protocol_zig` — one static library (`entitycore_codec`)
  + host/smoke/conformance executables (test/conformance only, not the library surface).
- **Library:** Zig module root `src/root.zig`, exposed as `entitycore_codec`. Pure-Zig, native
  codec, no FFI. **Zero third-party packages** — `std.crypto` (Ed25519 + SHA-2), `std.Thread`,
  `std.testing` all ship with Zig 0.15.1. `zig build` runs fully `--network=none`.
- **Host executable** (`src/host.zig`): the S4 conformance driver (`--port`,
  `--debug-open-grants`, `--validate`; emits `LISTENING …`). Test/conformance only.

---

## 3. Public API surface (the S5 "settle the surface" decision)

Zig has no `pub`-less-module privacy keyword beyond per-decl `pub`; the module boundary is
`src/root.zig` (only `pub` re-exports are reachable). The stable contract is the README §Use
two-tier table — **Tier 1** codec island (`Model`, `cbor`, `Hash`, `PeerId`, `Identity`,
`Sign`) and **Tier 2** full peer (`Peer`, `transport`, `Store`, `Capability`). Internal units
(`varint`, `base58`, `wire`, `type_defs`, `type_defs_data`) are implementation detail and may
churn without a semver bump. An explicit signature freeze (pruning `root.zig` re-exports to the
locked surface) is a mechanical publish-prep pass, deferred until the surface is frozen against
a first external consumer — the honest S5 state for an all-source-in-repo peer (mirrors the
OCaml `.mli`-deferral rationale).

---

## 4. Packaging notes specific to Zig

- **No central registry.** Zig has no crates.io/npm/opam equivalent. A package is a git repo;
  consumers add it to *their* `build.zig.zon` as a `.url` + `.hash` (content hash) dependency.
  "Publishing" = a git tag at a reviewed commit; consumers pin by hash. This is decentralized
  and hash-pinned **by design** — a supply-chain-friendly property (a consumer's build fails
  if the fetched bytes don't match the pinned hash). No index submission step exists or is needed.
- **std-only is a packaging advantage.** Because the peer pulls zero third-party packages, there
  is no transitive lockfile to audit and no `.url`/`.hash` fan-out — the only pin a consumer
  inherits is the Zig toolchain version. The single S11 pin is `zig 0.15.1`.
- **Ed448 / crypto-agility higher bar is OUT of S5 core scope** (A-ZIG-002): `std.crypto` has
  no Ed448, no audited pure-Zig Ed448 exists, and Zig has no BouncyCastle-equivalent. When
  agility enters scope the design is **hybrid** — native Ed25519 (shipped) + FFI Ed448 via
  `libentitycore_codec`. That introduces a C-ABI dependency (`@cImport`/`extern`) + an
  `ec_abi_version` pin in `build.zig.zon` (lifecycle §Version-pin, codec_strategy=ffi clause).
  Documented now so the manifest doesn't silently claim agility it doesn't have.
- **`build.zig.zon` identifier vs package name:** the manifest name is `entity_core_protocol_zig`
  (Zig snake_case identifier; no hyphens allowed) while the human/repo name is
  `entity-core-protocol-zig`. Expected and fine — the hyphen form is the repo/README name.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S4 A-ZIG-* items are resolved-in-peer and routed; none block release. Carried to arch as
spec-refinement candidates (full text in `status/SPEC-AMBIGUITY-LOG.md`):

- **A-ZIG-001 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: architecture** (high-priority;
  silent-handshake-kill trap). Peer follows §1.5 canonical identity-multihash; validated live
  (connectivity 22/22 + `authz_grantee_1`). **Independently corroborates OCaml A-OC-007.**
- **A-ZIG-006 ⚑** §5.2 401/403 request-time boundary — owner: architecture (corroborates F20 /
  OCaml A-OC-008 from a fourth, distant-idiom peer; ratify the 401/403 split). Validated live.
- **A-ZIG-005** peer_id corpus coverage gap (opaque digests, `hash_type=0x01` only) — owner:
  architecture (vector request: add a real-pubkey `hash_type=0x00` peer_id vector).
- **A-ZIG-002** Ed448 native gap — resolved-by-deferral (hybrid-FFI when agility in scope).
- **A-ZIG-003** threaded transport — resolved-in-peer (validated at S3; `std.Io` evented model
  the open path if origination enters core).
- **A-ZIG-004 / A-ZIG-007** no-GC ownership contract — resolved-in-peer (arena-per-request +
  clone-into-gpa; leak-clean). Informational for arch (spec's memory-ownership silence is fine
  for GC peers but leaves the no-GC peer to author a richer contract).
- **A-ZIG-008** 53-type registry — resolved (53/53 byte-identical).

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Decide in-repo vs standalone repo** (see `status/ARCHITECTURE-REVIEW.md` §Publishing-options).
   Per-language sibling repos are deferred keystone-wide (S10); current default is in-repo under
   `protocol-generator/zig/`.
2. **Settle the public-surface freeze** (§3): prune `src/root.zig` re-exports to the locked
   Tier-1/Tier-2 surface, build-verified in the `zig-toolchain` image.
3. **Promote version** `0.1.0-pre → 0.1.0` in `build.zig.zon` + `CHANGELOG.md` once the promotion
   gate (§1) is met.
4. **Set `repository_url`** in `profile.toml [publishing]` (currently empty — the per-language
   sibling repo is deferred per S10).
5. **Tag the release** at the reviewed commit (only at this point — lifecycle §"no auto-tag").
   For Zig that tag *is* the distribution: consumers add `.url = "<repo>/archive/<tag>.tar.gz"`
   + the `.hash` to their `build.zig.zon`. There is no `publish` command to run.
6. **Wire CI** (`.github/workflows/conformance.yml`) to the chosen repo's runner, or fold it into
   the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
7. **Pin discipline** (S11): the toolchain pin stays exact (`zig 0.15.1`); re-pinning is
   deliberate + reviewed. No registry-pulled deps to re-age.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged;
`0.1.0` promotion pending external consumer; public-surface freeze pending). CI authored
(reproducible-offline) but not wired to a remote — by design. Ambiguity log finalized +
owner-routed. Architecture review + publishing-options written (`status/ARCHITECTURE-REVIEW.md`).
Operator handoff (§6) prepared. **S5 objective met; the Zig peer #4 is publish-ready and parked
at `0.1.0-pre` pending arch v0.1 sign-off.**
