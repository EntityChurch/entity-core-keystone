# entity-core-protocol-unison — build transcript

Headless build: load the `src/*.u` source into the content-addressed codebase in
dependency order and `add` (typecheck == build). Runs fully `--network=none`
(builtins-only floor; A-UN-002/006).

```ucm
scratch/main> builtins.mergeio
scratch/main> load src/Codec.u
scratch/main> add
scratch/main> load src/Protocol.u
scratch/main> add
scratch/main> load src/Ed25519.u
scratch/main> add
```
