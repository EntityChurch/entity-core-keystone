# entity-core-protocol-unison

A **core** [Entity Core protocol](https://github.com/entity-church) peer written in
[Unison](https://www.unison-lang.org/) — peer #43 of the `entity-core-keystone` cohort.

[![conformance](https://img.shields.io/badge/validate--peer%20--profile%20core-682%C2%B70F%20PASS-brightgreen)](status/CONFORMANCE-REPORT.md)
[![codec](https://img.shields.io/badge/wire--conformance-71%2F71-brightgreen)](status/CONFORMANCE-REPORT.md)

| | |
|---|---|
| **Gate** | `validate-peer --profile core` → **`Result: PASS`**, **`682·0F @ cc1970f`** (292P/294W/0F/96S) |
| **Codec** | ECF corpus **71/71**, byte-identical |
| **Spec** | Entity Core **v0.8.0 (V8)**, core Layers 0–4 |
| **Version** | `0.1.0-pre` |
| **License** | Apache-2.0 |

Full report: [`status/CONFORMANCE-REPORT.md`](status/CONFORMANCE-REPORT.md).

## What this is

A complete **core-protocol** peer: substrate, identity, interaction, capability, and
bootstrap. It speaks the wire protocol, verifies capability chains, and dispatches to
handlers.

It is **not** a standard-extension implementation. TREE, CONTENT, IDENTITY, ATTESTATION,
QUORUM, REGISTRY, RELAY and friends are out of scope — the extension surface stops at the
dispatcher interface, and a community installs handlers above that boundary.

## What makes the Unison build unusual

**Zero third-party dependencies.** The codec, crypto, hashing, byte handling and TCP
sockets all sit on UCM runtime builtins, with CBOR/base58/varint hand-rolled on top. The
peer's only runtime is UCM itself, and it builds and runs fully offline.

**Hand-written Ed25519 key derivation.** UCM ships `crypto.Ed25519.sign.impl` and
`verify.impl` — but no key derivation. `sign.impl` requires the public key explicitly, and
Unison is a managed runtime with **no general C FFI**, so the shared `libentitycore_codec`
escape hatch that OCaml/Zig/Swift used is structurally unavailable. The public key
therefore had to be derived in pure Unison: GF(2²⁵⁵−19) field arithmetic in base-2¹⁶ `Nat`
limbs, twisted-Edwards scalar multiplication, and point compression (`src/Ed25519.u`).

**Content-addressed source.** Unison code lives in a content-addressed codebase, not in
text modules compiled by a build step. Everything here is driven headlessly through UCM
transcripts, which also double as the committed golden-output drift signal.

**Concurrency via abilities.** Store safety is structural rather than bolted on: all store
state lives behind a single `MVar`, and every mutation is `take → pure fn → put`, which
serializes access through one cell — an actor-like guarantee expressed through the ability
system.

## Layout

```
src/                     Codec, Protocol, Ed25519, Model, Wire, Identity, Store,
                         Capability, SeedPolicy, TypeDefs, Peer, Transport, Host
transcripts/             headless UCM drivers (+ committed golden .output.md)
status/                  phase reports, conformance report, ambiguity log
profile.toml             the authority on every library / idiom / packaging choice
run-s4.sh                conformance harness (validate-peer --profile core)
run-origination-core.sh  reference-peer-gated origination probes
```

## Build & test

Everything runs inside the pinned toolchain container, offline, under mandatory resource
caps. Never launch a container uncapped — see `RESOURCE-CAPS.md`.

```sh
. tools/podman-caps.sh

# codec conformance (71/71)
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  -w /work/protocol-generator/unison \
  localhost/entity-core-keystone/unison-toolchain:latest \
  ucm transcript transcripts/conformance.md

# peer smoke (8/8)
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  -w /work/protocol-generator/unison \
  localhost/entity-core-keystone/unison-toolchain:latest \
  ucm transcript transcripts/smoke.md
```

Conformance gate and origination probes:

```sh
cd protocol-generator/unison
INCONTAINER=0 sh run-s4.sh                 # → Result: PASS, 682·0F
INCONTAINER=0 sh run-origination-core.sh   # → 3/3
```

> **Note on cost.** The pure-Unison Ed25519 keygen is CPU-intensive; compile the peer to
> bytecode (`ucm run.compiled`) rather than running it interpreted. Keep the resource caps
> on — this peer will happily saturate a core for minutes at a time.

## Running a peer

```sh
ucm run.compiled output/peer.uc -- --name mypeer --port 7777
```

- `--name NAME` — load the Ed25519 identity from `~/.entity/peers/NAME/keypair`
  (entity-core PEM = base64 of a 32-byte seed).
- `--validate` — enable the `system/validate/*` conformance handlers. **Off by default**;
  this is a conformance surface, not a production one.
- `--debug-open-grants` — the degenerate seed policy `default→*`. Deprecated; test use only.

## Known gaps

Stated plainly rather than buried — see the conformance report for the full accounting.

1. **Ed448 / SHA-384 agility is deferred.** Neither is a UCM builtin, and with no C FFI
   there is no hybrid path. The core crypto floor (Ed25519 + SHA-256) is native.
2. **§4.10(c) connection admission is not implemented** — a SHOULD. `r3_connection_flood`
   WARNs, matching the Go reference peer's own behaviour.
3. **The supplementary peer-side multisig unit is unverified** (a parse error in the test,
   not the peer). The accept path is carried by the oracle's own
   `valid_2of3_peer_signed_accepted`, which suffices for the gate.

## Honesty

This peer is **keystone-generated** and shares a generation lineage with the rest of the
cohort. Passing the same author's vectors as 42 sibling peers is **cohort-consistent, not
independent convergence** — it is not the kind of evidence the ground-up
`entity-core-{go,rust,py}` implementations provide. The certification is `--profile core`,
not `--profile full`. And conformance-green is not a proof of correctness: it means the
gate passed, not that the code is free of bugs.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
