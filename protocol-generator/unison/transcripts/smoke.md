# entity-core-protocol-unison — S3 smoke runner

Boots two peers in-process over real loopback TCP and drives the lifecycle
scenario (handshake both ways, 401/404 auth-ordering, authority-gated get, cap
request, request_id demux, register, dispatch-outbound reentry). Green = the peer
talks the wire correctly. Runs `--network=none` (builtins-only + loopback).

```ucm
scratch/main> builtins.mergeio
scratch/main> load src/Codec.u
scratch/main> add
scratch/main> load src/Protocol.u
scratch/main> add
scratch/main> load src/Ed25519.u
scratch/main> add
scratch/main> load src/Model.u
scratch/main> add
scratch/main> load src/Wire.u
scratch/main> add
scratch/main> load src/Identity.u
scratch/main> add
scratch/main> load src/SeedPolicy.u
scratch/main> add
scratch/main> load src/Store.u
scratch/main> add
scratch/main> load src/TypeDefs.u
scratch/main> add
scratch/main> load src/Capability.u
scratch/main> add
scratch/main> load src/Peer.u
scratch/main> add
scratch/main> load src/Transport.u
scratch/main> add
scratch/main> load src/Smoke.u
scratch/main> add
scratch/main> run smokeMain
```
