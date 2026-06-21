# Phase S5 — Publish (entity-core-protocol-elixir)

**Status:** **documented + packaged, NOT published** (per the OCaml
precedent: document and understand the publish phase; we are not publishing yet). · **Version
line:** `0.1.0-pre` · **Spec basis:** V7 v7.74 head (Phase B extensibility boundary + §7a).

S5 polishes the S4-conformant peer into a *ready-to-publish* Hex artifact. `/entity-rosetta`
never publishes (lifecycle §Publishing) — this phase produces the artifacts and the runbook;
an operator runs `mix hex.publish` when arch signs off v0.1. This doc is the release-readiness
record + the operator handoff. Twin of the OCaml `PHASE-S5.md` (opam track).

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 568 / 284P / 195W / **0F** / 89skip, machine-verified `failed==0` (`status/CONFORMANCE-REPORT.{md,json}`) |
| §10.1 register + §10.2 origination gates | ✅ | 10/10 + 3/3 (incl. `dispatch_outbound_reentry` over real TCP) |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run |
| S7 higher bar (validate-peer core) | ✅ | same fixed point as C#/TS/OCaml |
| Crypto-agility higher bar | ✅ | Ed448 + SHA-384 **native** (35/35 byte-pins) — no FFI, no opt-in sub-library (contrast OCaml A-OC-002) |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy) |
| README + conformance badge | ✅ | `README.md` |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.74` |
| Package metadata (Hex) | ✅ | `mix.exs` `package/0` (name `entity_core_protocol`, Apache-2.0, files allow-list, links, maintainers); `description/0`; `docs/0`. `mix hex.build` green sealed-offline |
| Public API surface settled | ◑ documented | tiers documented (§3) + buildable tarball. `@moduledoc false` on internals + HexDocs *generation* deferred to publish-prep (ex_doc is a dev-only dep we have not pulled — see §4) |
| CI (Podman) | ◑ runnable, not wired | `run-s3.sh` / `run-s4.sh` / `run-origination-core.sh` run sealed-offline in the `beam` image today. A committed CI *workflow* is deferred **cohort-wide** — no peer has one; it lands when the per-language repos lift out (S10) or arch defines the shared CI home |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-ELX-* + corroborated A-OC-* routed to arch (§5) |
| **Published to Hex** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) at least one external consumer confirms it works — **not yet met** (no Elixir consumer
wired yet). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **Hex package:** `entity_core_protocol` (one OTP application + one escript host).
- **Library:** module prefix `EntityCore` (e.g. `EntityCore.Cbor`). Pure-Elixir, native codec,
  native crypto. **Zero runtime Hex dependencies** — `:crypto` is OTP stdlib; CBOR / Base58 /
  varint / the peer layer are hand-rolled. `mix deps.get` pulls nothing. Toolchain: Elixir
  `1.18.4`, OTP `27.3.4` (both S11-pinned ≥30d).
- **escript host** (`EntityCore.Host` → `./entity_core_protocol`): the S4 conformance driver
  (`--port`, `--debug-open-grants`, `--validate`; emits `LISTENING …`). Built by
  `mix escript.build`, **excluded from the Hex tarball** (`package.files` allow-list) — it is a
  test/conformance artifact, not library surface.

The native-crypto choice means the published package has **no system-package `depext`** and no
opt-in agility split: the single `entity_core_protocol` package carries the full crypto-agility
higher bar (Ed448, SHA-384) with no FFI — leaner than the OCaml hybrid (which carries Ed448 in
an opt-in C-ABI-linked sub-library).

---

## 3. Public API surface (the S5 "settle the surface" decision)

Elixir hides internals with `@moduledoc false` (and, optionally, by not documenting functions).
The package is buildable under the Hex name today (`mix.exs` `package/0`; `mix hex.build` green).
The stable contract is the tier table below. Two *enforcement* mechanisms remain as publish-prep:

- **`@moduledoc false` on the internal modules** (§ "Internal" below) — low spec-risk, but the
  in-repo test modules under `test/` are S10 library clients that reach `Varint`/`Base58`/`Wire`
  directly, so the hard hide is a mechanical pass best done once the surface is frozen and the
  tests move behind the package boundary.
- **HexDocs generation (ex_doc)** — the `@moduledoc`/`@doc` attributes are already authored
  (`doc_attrs = true`); ex_doc renders them on `mix hex.publish docs`. It is a **dev-only dep we
  have deliberately not pulled** (zero-dep + sealed-offline stance, S1/S11), so HexDocs are
  *authored but not yet rendered* — the honest S5 state for an all-source-in-repo (S10) peer.
  `mix.exs` `docs/0` is wired so adding ex_doc at publish-prep is one `deps` line.

Until then the surface is *documented, not compiler-enforced*.

**Tier 1 — Codec island (S7 lower bar; shared-data-library consumers).** The minimum surface a
non-peer consumer needs to encode/verify ECF:

| Module | Stable entry points |
|---|---|
| `EntityCore.Cbor` | `encode/1`, `decode/1`, `decode!/1` (ECF value `t`) |
| `EntityCore.Entity` / `EntityCore.Model` | `Model.make/3`; field accessors `field/2`, `text_field/2`, `bytes_field/2`, `uint_field/2`; `to_cbor/1`, `of_cbor/1`; `envelope_to_cbor/1`, `envelope_of_cbor/1`, `included_get/2` |
| `EntityCore.Hash` | `content_hash/2`, `resolve_format/1`, `resolve_wire_format/1`, `to_string/1` |
| `EntityCore.PeerId` | `from_public_key/2`, `format/3`, `parse/1`, `resolve_key_type/1`, `key_type_code/1` |
| `EntityCore.Identity` | `of_seed/1`, `peer_id_of_pubkey/1`, `peer_entity_of_pubkey/1`, `sign_entity/2`, `verify_signature/2` |
| `EntityCore.Signature` | `sign/3`, `verify/4`, `public_key/2`, `sign_raw/3`, `verify_raw/4` (Ed25519 + Ed448 via `curve` arg) |

**Tier 2 — Full peer (S7 higher bar).**

| Module | Stable entry points |
|---|---|
| `EntityCore.Peer` | `create/2` (`open_grants:`/`conformance:`), `dispatch/3`, `outbound_dispatch/3`, `mint_token/4` |
| `EntityCore.Transport` | `listen/1`, `accept_loop/2` |
| `EntityCore.Store` | content store + entity tree GenServer (`put_entity/2`, `bind/3`, `bind_cas/4`, `get_at/2`, `listing/2`, `register_{content,tree}_consumer/2`) — mostly internal-driven |
| `EntityCore.Capability` | grant/scope model + chain verification (advanced; mostly internal-driven) |

**Internal (`@moduledoc false` candidates — not part of the stable surface):** `EntityCore.Varint`,
`EntityCore.Base58`, `EntityCore.Wire`, `EntityCore.TypeDefs`, `EntityCore.TypeDefsData`,
`EntityCore.Error`, `EntityCore.Connection`, `EntityCore.Conformance`, `EntityCore.Agility`,
`EntityCore.Host`. Implementation details (LEB128, Base58 long-division, frame codec, the
in-code type-registry override table, the §7a conformance handlers, the escript entry point);
hiding them keeps the install surface honest and lets them churn without a semver bump.

---

## 4. Packaging notes specific to Elixir

- **Hex package id vs keystone peer id:** the Hex registry id is the idiomatic snake_case
  `entity_core_protocol` (a Hex package IS a BEAM package — the "elixir" suffix is implicit);
  the keystone peer id remains `entity-core-protocol-elixir`. Confirm availability / no
  squatting on hex.pm before first publish (`profile.toml [publishing]`).
- **Zero deps, sealed-offline build:** `mix hex.build` runs in the `beam` image with
  `--network=none` (the image pre-populated `MIX_HOME` with hex+rebar at build time). No
  `deps.get` is needed. This preserves the **zero-runtime-Hex-dep** headline and the offline
  seal — the packaging advantage of the native-codec + native-crypto choice.
- **ex_doc deferred (not absent):** `doc_attrs` are authored throughout; `docs/0` is wired in
  `mix.exs`. ex_doc + dialyxir are dev-only and pinned-when-added at publish-prep; not pulling
  them now keeps the build dep-free and offline. (OCaml made the same call deferring odoc/`.mli`.)
- **Crypto-agility carried in the core package — no FFI, no split.** Unlike OCaml (Ed448 in an
  opt-in `entitycore_agility` C-ABI sub-library), Elixir's Ed448 + SHA-384 are native OTP
  `:crypto`, so the single `entity_core_protocol` package ships the full higher bar with no
  system-package `depext` and no optional dependency. `profile.toml [codec].ed448_library`
  records `strategy = "native"`.
- **escript excluded from the tarball:** `package.files` is an explicit allow-list
  (`lib mix.exs README.md CHANGELOG.md LICENSE`) — `priv/` (test fixtures), `test/`, `status/`,
  the `run-*.sh` harnesses, `tools/`, and the built `entity_core_protocol` escript are not
  shipped to consumers.

---

## 5. Ambiguity-log finalization (owner + escalation status)

No NEW spec ambiguity surfaced in S1–S4; Elixir corroborates the cohort's findings from a
fourth, distant-idiom peer. None block release.

- **A-OC-007 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: architecture** (high; corroborated).
- **A-OC-008** §5.2/§4.6 401/403 request-time boundary — owner: architecture (corroborated).
- **A-011 / A-013** §7a conformance-handler coupling — **RESOLVED** (native `system/validate/*`
  handlers; in-band cap convention, Go-ruled). No longer open.
- **A-ELX-005** root_cap §3.6 byte-pins — resolved-in-peer (first independent verification).
- **A-ELX-006** actor-model concurrency placement — resolved-in-peer (operator-reviewed).
- **A-ELX-007** emit-delivery async fork — **deferred design item** (compute-readiness seam,
  §9.4-permitted); resolve when the emit-consumer surface is built. Tracked, non-blocking.

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Hide internals + render docs:** add `@moduledoc false` to the §3 internal modules and add
   `ex_doc` (dev-only, pinned ≥30d, S11) so `mix hex.publish docs` renders the authored
   `@moduledoc`/`@doc` — build-verified in the `beam` image.
2. **Promote version** `0.1.0-pre → 0.1.0` in `mix.exs` (`@version`) + `CHANGELOG.md` once the
   promotion gate (§1) is met.
3. **Set `repository_url`** in `profile.toml [publishing]` + the `mix.exs` `package.links`
   (currently the keystone repo subpath; the per-language sibling repo is deferred per S10).
4. **Dry-run the package** in-container, sealed-offline:
   `mix hex.build` (tarball) — already green; re-confirm after the version bump.
5. **Publish:** `mix hex.publish` — an operator action, reviewed, never automated, never from
   `/entity-rosetta`. Tag the release only at this point (lifecycle §"What you do NOT do": no
   auto-tag).
6. **Pin discipline on the published manifest** (S11): any dev deps added (ex_doc/dialyxir) stay
   exact; re-pinning is deliberate + reviewed.

---

## 7. Phase exit

Release-readiness checklist green except the two deliberately-deferred lines (published-to-Hex;
`0.1.0` promotion pending external consumer) and the publish-prep mechanical pass (`@moduledoc
false` + ex_doc render). Ambiguity log finalized + owner-routed. Operator handoff (§6) prepared.
**S5 documentation objective met; Elixir peer is publish-ready and parked at `0.1.0-pre` pending
arch v0.1 sign-off.** This completes the S1→S5 lifecycle for peer #4.
