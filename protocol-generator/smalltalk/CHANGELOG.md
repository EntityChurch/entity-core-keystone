# Changelog — entity-core-protocol-smalltalk

All notable changes to this peer. Spec-version tracked literally per the keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note:** Pharo/Smalltalk has no binary package registry and no version-grammar field
> to satisfy — distribution is a git repo + a Metacello baseline. The `0.1.0-pre` marker lives
> here + in README.md only; there is nothing analogous to a `Cargo.toml`/`package.json` version
> field to carry it (a Metacello baseline is a load recipe, not a versioned manifest). `make dist`
> stamps the tarball name from `VERSION` (default `0.1.0-pre`).

## [0.1.0-pre]

**Tracks Entity Core v0.8.0 (V8)** spec-data (`protocol-generator/shared/spec-data/v0.8.0/`);
**codec corpus v0.8.0**. The core wire contract is byte-unchanged across the V7→V8 cutover.
Oracle pin: **`entity-core-go @cc1970f`**.

First release line. **Peer #26 — the cohort's first pure-object / live-image / message-passing
probe** (Pharo 13.0: everything is an object, all control flow is message-sends, the program is a
persisted memory image). Derived spec-first as an **FFI-hybrid**: **pure-Smalltalk canonical
CBOR** (the peer owns the whole ECF byte-layer as a polymorphic `encodeOn:` double-dispatch over
tagged `EcValue` objects), crypto + SHA over the codec C-ABI (`libentitycore_codec`) via Pharo's
**in-process** UFFI `ffiCall:module:`. Not yet published — parked at `-pre` pending architecture
v0.1 sign-off + a first external Pharo consumer (the S5 promotion gate).

The probe's payoff is **generator robustness down to a pure-object / message-passing model**
(A-ST-000: corroboration — the recursive canonical-CBOR encoder/decoder and the §5 capability
chain-walk read as native message-sends, not a translated procedure), plus the **S4 code-bug
findings** the alien substrate flushed out (below). Exact `--profile core` parity with the Rexx
(#24) and Forth (#25) peers.

### Conformance
- `validate-peer --profile core`: **Result: PASS** — **682 total · 291P / 295W / 0F / 96S**
  (all 96 skips are §9.0 auto-allowlisted extension carve-outs; 0 fail-counting), oracle
  `entity-core-go @cc1970f` (core-gate fingerprint `8261a033…`, fingerprint-verified current).
  **Exact parity with Rexx (#24) and Forth (#25) — `682·0F`.**
- Codec (S2): **69/69** byte-identical to `conformance-vectors-v1` — pure-Smalltalk ECF; content_hash
  + signature legs cross the C-ABI for SHA/Ed25519. Bignum uint64 `[2^63, 2^64-1]` boundary
  self-test (carried FREE on the arbitrary-precision integer substrate — no fixed-width tax).
- §9.5 53-type floor: **53/53** byte-identical (render-from-model over the peer's own data model,
  asserted equal to the Go reference — not ingested).
- S3: foundation self-test **25/25** + two-peer loopback smoke **6/6** (in-process native Sockets +
  UFFI crypto; no co-process daemon).
- origination-core §10.2: **3/3** over a real two-peer connection (`dispatch_outbound_reentry` —
  the §6.11 reentry pump cross-impl wire-proven against the Go `entity-peer` reference).
- multisig: genuine 2-of-3 M3+M4+M6 with a positive accept-path (`valid_2of3_peer_signed_accepted`)
  + a 4/4 in-image accept-path unit test (`make multisig-accept`).

### Added
- **Pure-Smalltalk canonical CBOR / ECF byte-layer** (`src/EntityCore-Codec/`: `EcCborEncoder`,
  `EcCborDecoder`, `EcValue`, `EcVarint`, `EcBase58`, `EcPeerId`, `EcContentHash`,
  `EcFloatBits`): a polymorphic `encodeOn:` double-dispatch per tagged value class (int-vs-float,
  bytes-vs-text intent lives in the object's CLASS — `EcInt`/`EcFloat`, `EcByteString`/
  `EcTextString`), shortest-float ladder (f16/f32/f64 — f32/f64 assembled from NATIVE IEEE bits
  via `Float asIEEE64BitWord`/`asIEEE32BitWord`; only the f16 leg + shortest-form ladder are
  hand-rolled bit arithmetic), recursive major-type-6 tag reject at every node (N2), length-then-
  lex key sort, minimal-head re-validation, full-consume, N4 entity byte-fidelity (forward
  original wire, never re-encode). Bignum uint64 carried FREE (arbitrary-precision integers).
- **In-process UFFI C-ABI crypto binding** (`src/EntityCore-Crypto/EcLibEntityCoreCodec.st`):
  Ed25519 sign/verify/seed→pubkey, SHA-256/384 over `libentitycore_codec` (C-ABI v1.1, libsodium
  1.0.22) via `ffiCall:module:` — a genuine in-process libffi call, **no subprocess / FIFO /
  co-process** (the same clean shape as Forth's libcc; Rexx's transport pain does not arise).
  Provenance via `ec_impl_info()`.
- **Native BSD Sockets + single-event-loop serve pump** (`src/EntityCore-Peer/EcNet.st`,
  `EcPeer.st`): §6.5/§6.6 dispatch, §5 capability chain-walk + authz trichotomy, §4.10(a)/(b)
  floor, §6.11 request_id reentry demux — all in-process over the Pharo VM SocketPlugin (single
  green process on one OS thread → §7b store-safety is structural).
- §7a conformance handlers (`--validate` / `EC_PEER_VALIDATE=1`): `system/validate/echo`,
  `system/validate/dispatch-outbound` (`src/EntityCore-Peer/EcValidate.st`).
- **`handler` register/unregister full protocol** (the 5 spec writes) + the render-from-model
  53-type §9.5 core floor (`src/EntityCore-Peer/EcCoreTypes.st`) + tree put/CAS/deletion-marker +
  listing + `system/capability` request/configure/revoke (`EcPeerHandlers2.st`).
- The §5.2/§5.5 chain verifier (`src/EntityCore-Capability/EcCapAuthz.st`) — a NATIVE message-send
  port over `EcEntity`/`EcValue` objects: root single-sig + multisig M3/M4/M6, per-link signature +
  grantee + §5.6 validity + attenuation subset, §5.4 canonicalization + `/*/`/`/*` pattern + scope,
  §5.7 caveats, §5.1 revocation, the §5.2 permission gate, §6.2 mint-bounded.
- `bin/peer.st` host driver: `EC_PEER_PORT`, `EC_PEER_NAME` (Ed25519 identity from
  `~/.entity/peers/NAME/keypair`), `EC_PEER_SEED` (keypair-free test convenience),
  `EC_PEER_VALIDATE`, `EC_PEER_OPEN_GRANTS`. Prints `LISTENING <port>` on stdout.
- **SUnit** conformance mirror (`tests/EntityCore-Tests/EcCodecTest.st`) — Pharo ships the
  original xUnit in the base image at zero dependency cost (unlike the rest of the FFI-hybrid
  cohort, which hand-rolled a harness).
- **`make dist`** source-tarball packaging (the profile `package_command`) + `LOAD.md` load stub +
  a Metacello baseline load convention (documented in `LOAD.md`).

### Fixed (S4 — code bugs in the generated peer, not relaxed vectors)
- **A-ST-016 (the headline):** dispatch caught only `EntityCoreError`, so a live
  `doesNotUnderstand:` (`ByteString>>#tokenize:` — the right selector is `findTokens:`) deep in
  `pathFlexOk:` escaped the frame and crashed `serveForever` → every subsequent request broke →
  **229 cascaded FAILs from one bug.** Fix: `handleExecute:` catches `Error` (→ 500),
  `serveConn:`/`onFrame:` catch `Error` (→ swallow + keep serving). On a no-static-check substrate
  the resilience frame MUST be the language's ROOT error class — a generator-robustness lesson for
  any future dynamic/live-image peer.
- **A-ST-014:** per-connection nonce counter → cross-connection handshake replay (F12,
  `handshake_replay_cross_connection`). Fix: a PEER-GLOBAL monotonic `nonceCounter`.
- **A-ST-015:** uppercase hex on revocation/signature tree paths (`printPaddedWith:to:base:` is
  uppercase; the §3.4/§3.5 convention is lowercase) → `revoke_happy_path` /
  `revoked_cap_denied_on_use` 404-after-200. Fix: force `asLowercase`.
- **A-ST-017:** the single-event-loop 1s blocking accept-poll starved throughput (tree/concurrency
  i/o timeouts). Fix: NON-BLOCKING accept poll (`waitForAcceptFor: 0`), drain every ready
  connection each tick, 2ms `Delay` only when idle; `concurrency` went from collapsed to 5/5 PASS.
  Plus §4.10(c) admission (error-safe `tryAccept:` against the transient ExternalSemaphoreTable
  socket-registration race + a bounded backlog) so the r3 connection flood is a spec-allowed WARN,
  peer stays alive.
- §4.5 negotiation key_type reject (`helloKeyTypeBad:`); root single-sig granter (== our id_hash)
  resolution via injecting our own peer entity into the inbound envelope's included set.

### Known limitations / honest notes
- **Ed448 / SHA-384 agility deferred** (cohort-wide): the Ed25519 + SHA-256/384 floor is
  byte-proven; Ed448 is available over the same C-ABI (`ec_ed448_*`) but not yet wired — a
  documented non-v0.1 item, not a gap.
- **The crypto floor is a C-ABI FFI call, by design** — no audited native Ed25519 in the Pharo
  base image; Smalltalk owns the *codec* byte-layer (pure-Smalltalk ECF), the C-ABI owns the
  *crypto* primitives (SHA-256 is unified there too, though the base image's Cryptography package
  has it — A-ST-009, one audited source).
- The C-ABI oracle ELFs (`output/s4-oracles/`) and the built `.so` are gitignored (byte-built
  floor), not committed. The saved `.image` / `.changes` / `.sources` are build artifacts
  (regenerated by `make image`), also gitignored — sources + run scripts are committed.
- No binary package registry / no version-grammar field (see the version note).

### Spec items surfaced (logged in status/SPEC-AMBIGUITY-LOG.md)
All 18 items **A-ST-000..017** are RESOLVED at their stage or research-owned
(generator-robustness); **none are open spec findings**. On the current saturated wire surface
the pure-object probe surfaced no fresh spec-precision issue — clean corroboration end to end,
which is the answer the profile was built to get. Durable cross-Smalltalk lessons banked:
A-ST-000 (the codec IS idiomatic double-dispatch, not translated), A-ST-012 (a distinguished-object
absent sentinel needs `isAbsent` polymorphic on the `EcValue` supertype, else a DNU faults),
A-ST-016 (catch the ROOT error on a no-static-check substrate), A-ST-010/011/013 (live-image
single-doit class-visibility + headless-driver hygiene). **Owner: operator/research** (no arch
escalation outstanding).
