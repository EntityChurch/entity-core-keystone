# Phase S5 — Publish (entity-core-protocol-ocaml)

**Status:** **documented + packaged, NOT published** (per user: "document and understand the publish phase, we're not publishing yet"). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 v7.72 head + v7.73 §PR-8 + Amendment-1 closeout.

S5 polishes the S4-conformant peer into a *ready-to-publish* opam artifact. `/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts and the runbook; an operator runs `opam publish` when arch signs off v0.1. This doc is the release-readiness record + the operator handoff.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 558 / 274P / 195W / **0F** / 89skip, machine-verified `failed==0` (`status/CONFORMANCE-REPORT.{md,json}`) |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run |
| S7 higher bar (validate-peer core) | ✅ | same fixed point as C#/TS |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy) |
| README + conformance badge | ✅ | `README.md` |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.72 + v7.73 closeout` |
| Package metadata (opam) | ✅ | `entity-core-protocol-ocaml.opam` (hand-pinned, S11); `src/dune` `public_name` set; `dune build @install` + `opam lint` green in-container |
| Public API surface settled | ◑ documented | tiers documented (§3) + library installable under the package name. `private_modules`/`.mli` *enforcement* deferred to publish-prep (the in-repo test execs are S10 library clients of `Base58`/`Type_defs`) |
| CI (Podman) | ◑ runnable, not wired | the build/test/conformance commands run sealed-offline in the `ocaml-toolchain` image today (`run-s4.sh`, the `dune build` dev-loop, `test/conformance.exe`). A committed CI *workflow* (`.github/` or equivalent) is deferred **cohort-wide** — no peer has one yet; it lands when the per-language repos lift out (S10) or arch defines the shared CI home |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-OC-* routed to arch (§5) |
| **Published to opam** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) at least one external consumer confirms it works — **not yet met** (no OCaml consumer wired yet; the C#-class "Avalonia confirms" analogue). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **opam package:** `entity-core-protocol-ocaml` (one library + one host executable).
- **Library:** dune-wrapped, module prefix `Entitycore_codec` (e.g. `Entitycore_codec.Cbor`). Pure-OCaml, native codec, no FFI, no libsodium. Deps (all S11-pinned ≥30d): `digestif 1.3.0`, `mirage-crypto-ec 2.1.0`, `mirage-crypto-rng 2.1.0`, stdlib `unix` + `threads.posix`. Toolchain: ocaml `5.2.1`, dune `3.23.1`.
- **Host executable** (`bin/host.ml`): the S4 conformance driver (`--port`, `--debug-open-grants`, emits `LISTENING …`). **Not installed** — test/conformance only, excluded from the install set.

---

## 3. Public API surface (the S5 "settle the surface" decision)

OCaml has no `internal` keyword. The library is now installable under the opam name (`src/dune` `public_name entity-core-protocol-ocaml`; `dune build @install` + `opam lint` green). The stable contract is the tier table below. Two *enforcement* mechanisms remain as publish-prep, both deferred because they are build-risky against the current S10 in-repo layout:

- **`(private_modules varint base58 wire type_defs type_defs_data)`** would hide internals from consumers — but the in-repo test executables (`test/conformance.ml`, `selftest.ml`, `type_registry.ml`) are *separate library clients* and currently use `Base58` and `Type_defs` directly, so making them private breaks the test build until the tests move under the library (a `(package)` test stanza) at publish time.
- **Per-module `.mli` interface files** are the finer-grained signature lock — low spec-risk, build-verified, but a mechanical pass best done once the public surface is frozen.

Until then the surface is *documented, not compiler-enforced*. That is the honest S5 state for an all-source-in-repo (S10) peer.

**Tier 1 — Codec island (S7 lower bar; shared-data-library consumers).** The minimum surface a non-peer consumer needs to encode/verify ECF — the OCaml analogue of TS's `./codec` subpath and C#'s public `EntityCodec`/`PeerId`:

| Module | Stable entry points |
|---|---|
| `Cbor` | `type t`; `encode : t -> string`; `decode : string -> t`; `exception Decode_error` |
| `Model` | `type entity`, `type envelope`; `make ~typ`; `to_cbor`/`of_cbor`; `envelope_to_cbor`/`envelope_of_cbor`; field accessors (`field`, `text_field`, `bytes_field`, `uint_field`) |
| `Hash` | `sha256`, `sha384`, `content_hash ?format_code ~typ ~data ()`, `ecf_of_entity` |
| `Peer_id` | `type components`; `format`; `parse` |
| `Identity` | `type t`; `of_seed`; `peer_id_of_pubkey`; `peer_entity_of_pubkey`; `sign_entity`; `verify_signature` |
| `Sign` | `sign ~seed`, `verify ~pub ~signature ~msg`, `public_of_seed` (low-level Ed25519) |

**Tier 2 — Full peer (S7 higher bar).**

| Module | Stable entry points |
|---|---|
| `Peer` | `type t`; `create ~seed ~open_grants`; `dispatch` |
| `Transport` | `listen ~port`; `accept_loop`; `serve_connection` |
| `Store` | content store + entity tree (CAS, listing) |
| `Capability` | grant/scope model + chain verification (advanced; mostly internal-driven) |

**Internal (private_modules — not part of the stable surface):** `Varint`, `Base58`, `Wire`, `Type_defs`, `Type_defs_data`. These are implementation details (LEB128, Base58 long-division, frame codec, the in-code type-registry override table); hiding them keeps the install surface honest and lets them churn without a semver bump.

---

## 4. Packaging notes specific to OCaml

- **opam, not dune-release auto-gen:** the `.opam` is hand-written (not `generate_opam_files`) so the S11 dependency pins are explicit and reviewable in one manifest, matching the rest of the cohort's "explicit lockfile" stance.
- **`depext` / system deps:** none beyond the OCaml toolchain — no libsodium, no C bindings (mirage-crypto-ec is pure-OCaml-over-fiat-C, vendored by opam). This is a packaging *advantage* of the native-codec choice: `opam install entity-core-protocol-ocaml` pulls no system packages.
- **Ed448 / crypto-agility higher bar — BUILT** (A-OC-002 resolved, option (a) hybrid FFI). The design landed as documented: native Ed25519 + SHA-256/384, FFI Ed448 (`key_type 0x02`) via `libentitycore_codec` (C-ABI v1.1). It is an **opt-in sub-library** `entitycore_agility` (`src/agility/`, dune-guarded by `EC_AGILITY=1`) — the shipped Ed25519+SHA-256 core peer **stays self-contained and FFI-free** (`opam install entity-core-protocol-ocaml` still pulls no system packages; the agility higher bar is a separate, explicitly-linked surface). Byte-verified 25/25 vs the agility corpus (`run-agility.sh`, harness `test/agility.ml`), against both the C and Rust FFI impls (byte-interchangeable). The C-ABI dependency + `ec_abi_version` (1.1) are recorded in `profile.toml [codec].ed448_library` (codec_strategy=ffi clause). Publish note: the core opam package does NOT depend on the `.so`; a future `entity-core-protocol-ocaml-agility` opam package (or an optional depopt) would carry it when the agility surface is published — deferred until an external consumer needs the higher bar.
- **Module-prefix vs package-name mismatch:** consumers write `Entitycore_codec.Cbor` though the package is `entity-core-protocol-ocaml`. Acceptable (common in opam); a future rename of the wrapped library to `Entity_core_protocol` would align them but touches `bin/dune` + tests — deferred, not worth a churn before first external consumer.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S4 A-OC-* items are resolved-in-peer and routed; none block release. Carried to arch as v7.74 proposal candidates (see the three-peer architecture milestone review §5):

- **A-OC-007 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: architecture** (high-priority; silent-handshake-kill trap). Peer follows §1.5; logged.
- **A-OC-004 ⚑** format_code emit/receive asymmetry — owner: architecture (clarifying sentence, §4.7).
- **A-OC-008** 401/403 request-time boundary — owner: architecture (corroborates F20; ratify 401).
- **A-OC-001** unsigned-Int64 carrier — resolved-in-peer; corpus u64-range gap is a standing vector request (with F7).
- **A-OC-002** Ed448 native gap — **RESOLVED** (hybrid FFI built; opt-in `entitycore_agility` sub-lib, 25/25 byte-verified). No longer a deferral.
- **A-OC-003-revised** eio→stdlib-threads — resolved-in-peer (operator-reviewed).
- **A-OC-006** type-registry render-from-model — resolved (53/53 byte-identical).

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an external consumer confirms the peer:

1. **Settle final `.mli` files** (the deferred mechanical step in §3) for the Tier-1/Tier-2 modules, build-verified in the `ocaml-toolchain` image.
2. **Promote version** `0.1.0-pre → 0.1.0` in `.opam` + `CHANGELOG.md` once the promotion gate (§1) is met.
3. **Set `repository_url`** in `profile.toml [publishing]` + the `.opam` `homepage`/`dev-repo`/`bug-reports` fields (currently TBD — the per-language sibling repo is deferred per S10; until then point at the keystone repo subpath).
4. **Dry-run the package** in-container:
   `opam lint entity-core-protocol-ocaml.opam` and `dune build @install`.
5. **Publish:** `opam publish` (or open a PR to `opam-repository`) — an operator action, reviewed, never automated, never from `/entity-rosetta`. Tag the release only at this point (lifecycle §"What you do NOT do": no auto-tag).
6. **Pin discipline on the published manifest** (S11): the `.opam` `depends` constraints stay exact (`= 2.1.0`), re-pinning is deliberate + reviewed.

---

## 7. Phase exit

Release-readiness checklist green except the two deliberately-deferred lines (published-to-opam; `0.1.0` promotion pending external consumer). Ambiguity log finalized + owner-routed. Operator handoff (§6) prepared. **S5 documentation objective met; OCaml peer is publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off.**
