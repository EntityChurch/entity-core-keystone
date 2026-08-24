# entity-core-protocol-rexx — load & run (the Rexx "package")

Classic Rexx (Regina 3.9.6, ANSI — **not** ooRexx) has **no package registry and no module
system**: there is no CPAN/PyPI/crates analogue and no `import`. The distribution is
therefore a **source tarball** (`make dist`) of the `.rex` routine tree plus the two C
external-process recipes, and the "package" a consumer runs is a **single concatenated
`.rex` file** — the main program first, then the routine library, so Rexx's global labels
resolve across the whole file. That pre-concatenated file, `entity-core-peer.rex`, ships in
the tarball ready to run.

## Dependencies

- **Regina Rexx** 3.9.6+ (`rexx` on `PATH`).
- **`libentitycore_codec.{so}`** — the codec C-ABI (canonical CBOR + Ed25519/SHA over
  libsodium), from `ffi-generator/c-abi/entity-core-codec-ffi-c` in the keystone repo (or any
  interchangeable `entity-core-codec-ffi-*` build). The two C ext processes link it. Build
  once with its CMake; point `LD_LIBRARY_PATH` at the resulting `build/` dir.
- **gcc** — to compile the two C ext recipes below. No compile step for the Rexx itself
  (interpreted).

## Build the two C ext processes

```
make ext            # src/ext/eccrypto  — the OFFLINE crypto helper (hex stem-pipe)
make net            # src/ext/ecnet     — the networked co-process daemon (sockets +
                    #                     select() + §1.6 de-framing + §9.1 crypto)
```

(Both `gcc … -lentitycore_codec`; the Makefile does it. `libentitycore_codec` is built
automatically by the `codec` prerequisite if absent.)

## Run

**The peer** (networked host — the S4 CLI):

```
LD_LIBRARY_PATH=<codec-build> rexx entity-core-peer.rex \
    --port 7777 --name mypeer --net src/ext/ecnet --base /tmp/ecnet.$$ [--validate] [--debug-open-grants]
```

It loads the Ed25519 identity from `~/.entity/peers/<name>/keypair` (an entity-core PEM =
base64 of a 32-byte seed), prints `LISTENING <port>`, and serves on the single-threaded
select-pump. `entity-core-peer.rex` is `bin/peer.rex` concatenated ahead of the routine
library; rebuild it from source with `make s4peer` (writes `/tmp/rexx-peer.rex`) or just
`cat bin/peer.rex <library-files> > entity-core-peer.rex` in the Makefile's `S3LIB` order.

**Conformance / smoke** (reproduce the gates, container-bound + sealed-offline):

```
./run-s2.sh                 # codec corpus 69/69
./run-s3.sh                 # two-peer loopback smoke 8/8 + foundation self-test 31/31
./run-s4.sh                 # validate-peer --profile core (0 FAIL @ oracle cc1970f)
./run-origination-core.sh   # §10.2 two-peer origination probe (Go entity-peer as B)
```

## Publish

No registry step (none exists for classic Rexx). Publishing = tag a git release carrying
this tree + the tarball; a RexxLA-archive/script-collection listing is a later, review-gated
community step. `0.1.0-pre` until first tagged release.
