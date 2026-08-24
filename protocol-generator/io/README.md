# entity-core-protocol-io

A full **entity-core protocol** core peer (V8 / v0.8.0, Layers 0–4) written in
**Io** — the pure prototype-based object language (Steve Dekorte). Peer target
`io`; the cohort's **prototype-OO paradigm probe**.

> **Status: exploratory paradigm probe (Tier: probe).** Not a deployable-tier
> peer. The payoff is the §6.6-as-delegation rendering and the substrate lessons
> (see `arch/PROFILE-RATIONALE.md` and `status/SPEC-AMBIGUITY-LOG.md`), not a
> production deployment.

## The probe — §6.6 handler resolution IS the language's dispatch

Io has no classes: every object is `clone`d from a prototype, inheritance is
**differential** (an object stores only its diffs and delegates the rest up the
proto chain), and everything is a message send. The entity-core §6.6 handler
resolution is a **longest-prefix delegation walk** over the path tree — the same
shape as Io's own dispatch. So this peer authors §6.6 IN the language:
`src/Store.io` builds a **network of `DispatchNode` prototypes mirroring the path
tree** (the node for `/a/b/c` is a `clone` of `/a/b`); binding a `system/handler`
entity DEFINES `handlerPattern` on that node, and §6.6 resolution is just
`deepestNode(path) handlerPattern` — Io's delegation lookup returns the nearest
(= deepest-prefix) definition. The protocol's dispatch is the language's dispatch.
The handlers (`src/Handlers.io`) are the same idea: a base `Handler` prototype
with the unknown-op→501 default, each handler a `clone` overriding only its
`op_<name>` methods.

## Architecture

- **Codec/crypto seam** — the `EntityCodec` Io C addon (`src/entitycodec/`) over
  `libentitycore_codec` (the C-ABI): canonical ECF in the addon C (hand-rolled,
  byte-identical to the 71-vector corpus), Ed25519 + SHA + peer-id via the C-ABI.
  Compiled exactly like the Socket addon (the S1-proven addon-build pattern).
- **Everything else in Io** — framing, envelopes, the §5 capability algebra
  (chain walk, attenuation, caveats, revocation, genuine §3.6 K-of-N multisig),
  §6.5 dispatch, the store, the §6.9/§6.9a bootstrap + seed policy.
- **Transport** — a single-coroutine non-blocking poll loop over the Socket
  addon's async primitives (`asyncAccept`/`asyncStreamRead`/`asyncStreamWrite`),
  the Pd/Scratch single-threaded-event-peer model. §6.11 reentry is a bounded
  synchronous send+wait on the same fd.

## Value model (the double-typed-number answer)

CBOR's type distinctions do not survive Io's value model uninstructed, so the
addon uses explicit wrappers: `EcMap` (ordered, byte-or-text keys), `EcBytes`
(mt2, the byte-vs-text seam), `EcBig` (integers beyond the double-exact range —
the uint64 tower carrier, `Number` alone always means an exact integer),
`EcFloat` (mt7, with a `negZero` slot for −0.0), `EcNull`.

## Build & run (container-bound)

Everything runs inside `containers/io-toolchain/` (Io frozen at the permanent
native tag `2026.04.20-native-final`; Socket + EntityCodec addons; the C-ABI codec):

```
./run-s2.sh                 # S2: build the addon + wire corpus 71/71 gate
./run-s4.sh                 # S4: validate-peer --profile core (the live gate)
./run-s4.sh -category connectivity
./run-origination-core.sh   # §10.2 origination-core (Io A-role, Go B-role) 3/3
make s2                     # (inside the container) codec gate
io src/main.io --port <p> --name <NAME> [--validate] [--debug-open-grants]
```

`--name NAME` loads the persistent Ed25519 identity from
`~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed).
`--validate` enables the `system/validate/*` conformance handlers (off by default).

## Conformance

See `status/CONFORMANCE-REPORT.md` for the oracle-pinned P/W/F/S breakdown
(`validate-peer @ cc1970f`). Codec: **71/71** byte-identical. Type floor:
**53/53** byte-identical to the oracle (render-from-model, 0 drift).

## License

Apache-2.0 (`LICENSE`). Io itself is BSD-3.
