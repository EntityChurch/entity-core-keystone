# Changelog — entity-core-protocol-haskell

All notable changes to the Haskell core protocol peer (peer #8). Versioning is held at
`0.1.0-pre` until the promotion gate is met (S4 green — done — **and** an external consumer
confirms the peer); the cabal manifest carries `0.1.0.0` for build purposes.

## 0.1.0-pre (unreleased) — tracks ENTITY-CORE-PROTOCOL-V7 **v7.74**

Spec basis: spec-data **v7.74** (register / outbound-closure / emit / peer-owner-cap / §7a
conformance handlers head). ECF codec corpus v0.8.0 (byte-stable to v7.74 except the §7.73 E3
decode-side erratum, which carries no wire change). Oracle: Go `validate-peer` @ go HEAD
`749e57e`.

### Conformance

- `validate-peer --profile core` → **PASS** · 573 total · 289 pass · 195 warn · **0 fail** ·
  89 skip — first oracle run, **zero peer-correctness fixes** (the cleanest S4 in the cohort;
  two GHC-mechanics fixes only).
- §10.1 core-register gate **10/10** (incl. grant-sig at `system/signature/{grant_hash}` +
  unregister symmetry + the §7a `validate_echo_dispatch`).
- §10.2 origination-core **3/3** (incl. `dispatch_outbound_reentry` over real two-peer TCP via
  `run-origination-core.sh`).
- §7b concurrency gate **5/5** with no per-check fix (the structural STM/green-thread win).
- `type_system` 53/53 byte-identical to the Go-rendered registry vectors.
- Codec self-conformance: 69/69 byte-identical to `conformance-vectors-v1`, first build,
  0 codec-logic fixes (the 8th consecutive native-peer confirmation).

### Codec & crypto

- Native hand-rolled canonical ECF CBOR encode/decode (zero CBOR dependency): shortest-float
  ladder (f16/f32/f64), length-then-lex map-key sort over encoded bytes, recursive major-type-6
  tag rejection on decode, full `Word64`/n-int range, raw-byte fidelity.
- LEB128 varint primitives; Base58 (Bitcoin alphabet); content_hash; peer-id format/parse/derive
  (§1.5 identity-multihash).
- **Native full crypto-agility, no FFI:** Ed25519 + **Ed448** + SHA-256/384/512 from `crypton`
  (one audited C-backed library). Haskell is the **first native-full-agility peer** — the §1.5
  `key_type 0x02` higher bar is reached in the default build with no opt-in sub-library
  (contrast OCaml's hybrid FFI; Zig/Swift's deferral).
- `Either CodecError a` pure error model; the strict-ByteString / UTF-8-byte-length laziness
  discipline (A-HS-002 — purity makes the codec laziness-immune; one UTF-8 string-length trap).

### Peer (V7 L1–L4 + v7.74 live hooks)

- Identity/peer-id (§1.5), STM-`TVar` content store + tree (§1.7) + §6.10 emit, capability core
  (§5.2/§5.4/§5.5/§5.5a §PR-8 granter frame/§5.6/§5.7/§5.1), wire framing (§1.6) +
  EXECUTE/EXECUTE_RESPONSE, the four MUST handlers + §6.5 dispatch + §6.6 resolution + §6.9
  bootstrap.
- v7.74 live hooks: §6.13(a) register/unregister (five writes, grant-sig at the §3.5 pointer),
  §6.13(b) handler outbound closure, §6.9a Peer Authority Bootstrap (owner cap + seed policy).
- §7a conformance handlers (`system/validate/{echo,dispatch-outbound}`) behind the `--validate`
  opt-in (off by default); §6.11 reentry dispatch-outbound.
- Concurrency: GHC green threads (`forkIO`) + STM (`TVar`) — a 3rd data-race-free store shape;
  `-threaded` RTS sidesteps the cooperative-pool/blocking-syscall trap; `TCP_NODELAY`;
  request_id↔reply demux via STM `retry`.
- §9.5 53-type registry rendered from the in-code model (A-HS-009), 53/53 content_hash
  byte-identical to the Go vectors first run.

### Packaging & supply chain

- `crypton 1.0.4` pinned (LTS 23.27 set; `memory 0.18.0` / `basement 0.0.16` constrained); the
  full transitive closure is pinned by a committed `cabal.project.freeze` **derived from
  Stackage LTS 23.27** (GHC 9.8.4) + a pinned Hackage `index-state` — a
  single dated snapshot is the S11 ≥30-day age floor (no per-dep manual audit). Transport adds
  GHC-boot `network`/`stm`/`time`/`containers` (A-HS-012: confirm `network 3.2.8.0` clears the
  30-day floor at the next deliberate re-pin).
- `-Werror` moved behind the manual `dev` cabal flag (default off) for the distributed build;
  `-Wall` stays. `category:` / `synopsis` / `description` set; `CHANGELOG.md` + `README.md` in
  `extra-doc-files`; `license: Apache-2.0` + `license-file: LICENSE`.
