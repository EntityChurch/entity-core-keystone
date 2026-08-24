# entity-core-protocol-forth — load & run (the Forth "package")

Forth (gforth 0.7.3) has **no package registry and no module system** — no CPAN/PyPI/crates
analogue, no `import`. A peer is a directory of `.fs` files a consumer `require`s. The
distribution is therefore a **source tarball** (`make dist`) of the `.fs` tree + `bin/peer.fs`
+ the run/conformance scripts + this stub + the `libentitycore_codec` build recipe (a runtime
dependency, documented, **not** bundled as a binary). To run the peer you `require` the umbrella
`src/peer-all.fs` (which `bin/peer.fs` already does) after building the codec `.so`.

## Dependencies

- **gforth** 0.7.3+ (`gforth` on `PATH`) — the interpreter/compiler + the `libcc` FFI wordset.
- **gcc / cmake** — to build the codec C-ABI recipe below (no compile step for the `.fs`; it is
  interpreted/incrementally-compiled). `libcc` also generates + compiles a tiny crypto wrapper
  `.so` on the first `c-library … end-c-library` load — warmed by `make ffi`.
- **`libentitycore_codec.so`** — the codec C-ABI (Ed25519/SHA over libsodium), built from
  `ffi-generator/c-abi/entity-core-codec-ffi-c` in the keystone repo (or any interchangeable
  `entity-core-codec-ffi-*` build). Build once with its CMake; the header
  (`entitycore_codec.h`) and the `.so` must be reachable at load time (see the env below).
- **libsodium** 1.0.18+ (the codec links it).

## Build the codec floor (`make ffi`)

```
make ffi     # builds libentitycore_codec.so (its CMake, offline) and warms the libcc crypto
             # wrapper by loading the c-library once. The .so is built into
             # ../../ffi-generator/c-abi/entity-core-codec-ffi-c/build/ (its canonical dir).
```

`libcc` binds the codec at load time; it needs three env vars pointing at the codec build dir +
the C-ABI header dir (the Makefile's `FFI_ENV` sets these for every gate target):

```
export LIBRARY_PATH=<codec>/build          # link the libcc wrapper
export LD_LIBRARY_PATH=<codec>/build       # dlopen at runtime
export C_INCLUDE_PATH=<c-abi>/spec         # the \c #include "entitycore_codec.h"
export CPATH=<c-abi>/spec
# GOTCHA A-FT-005: clear the libcc wrapper cache before each run, or a stale .so silently binds
# old symbols:  rm -rf $HOME/.gforth/libcc-named $HOME/.gforth/libcc-tmp
```

## Run

**The peer** (networked host — the S4 CLI):

```
gforth -d 64M -r 64M -l 16M bin/peer.fs \
    --port 7777 --name mypeer [--validate] [--debug-open-grants]
```

It loads the Ed25519 identity from `~/.entity/peers/<name>/keypair` (an entity-core PEM =
base64 of a raw 32-byte seed), prints `LISTENING <port>` on stdout, then serves on the
single-thread select-pump (native BSD sockets + in-process crypto — no co-process daemon). The
enlarged `-d/-r/-l` stacks matter under the concurrency/sustained-load categories (A-FT-025).

Keypair-free smoke (no `~/.entity` needed — the test convenience path):

```
gforth -d 64M -r 64M -l 16M bin/peer.fs --port 7825 --seed ab   # → LISTENING 7825
```

(This is exactly the `make dist` verification: extract the tarball into a clean dir, build the
codec floor, and boot with `--seed` → `LISTENING`.)

**Conformance / smoke** (reproduce the gates, container-bound + sealed-offline):

```
./run-s2.sh                 # codec corpus 69/69 + crypto accept-path + uint64 boundary
./run-s3.sh                 # foundation self-test 20/20 + two-peer loopback smoke 6/6
./run-s4.sh                 # validate-peer --profile core (0 FAIL @ oracle cc1970f)
./run-origination-core.sh   # §10.2 dispatch_outbound_reentry (Go entity-peer as B)
```

## Publish

No registry step (none exists for Forth). Publishing = tag a git release carrying this tree +
the tarball; a Forth-community listing is a later, review-gated step. `0.1.0-pre` until the
first tagged release. `/entity-rosetta` never publishes — this is an operator decision after
review.
