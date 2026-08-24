# entity-core-protocol-unison — S4 peer compile transcript

Loads the full peer library (`src/*.u` incl. `Host.u`) into a fresh codebase and
compiles `main` (the standalone host) to `output/peer.uc` — the offline-launchable
bytecode blob the S4 conformance harness (`run-s4.sh`) drives with
`ucm run.compiled`. Self-contained: `builtins.mergeio` + `add` per module, no
network, no external codebase.

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
scratch/main> load src/Host.u
scratch/main> add
scratch/main> compile main output/peer
```
