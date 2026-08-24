# entity-core-protocol-oz

A full **entity-core** protocol peer for **Oz 3** on the **Mozart 2.0.1**
Programming System. Peer target `oz` — the **fourth structural §7b concurrency
shape: single-assignment dataflow variables** (declarative concurrency). A thread
reading an unbound variable blocks until another thread binds it; synchronization is
automatic — no locks, no channels, no retry loops.

**Conformance:** `validate-peer --profile core` → **Result: PASS, 0 FAIL** @
oracle `cc1970f` (`682 · 285P/301W/0F/96S`). Origination-core 3/3; genuine multisig
K-of-N accept-path unit test PASS. See `status/CONFORMANCE-REPORT.md`.

## What's distinct about this peer

- **§6.11 reentry is a dataflow variable.** The out-of-order-reply demux collapses
  into one `{Wait Var}` per pending request: a connection's reader thread routes
  every frame (response frames bind the pending var; request frames each dispatch in
  their own worker thread), so a handler-originated outbound EXECUTE just sends and
  waits — no correlation-map pump, no serial-drain yield. The reader never blocks on
  dispatch, so reentry cannot deadlock. (The payoff axis — A-OZ-006.)
- **§4.8 store-safety by construction.** The content store + tree index, the
  per-connection pending map, the per-connection writer, and the crypto-daemon pipe
  are each a **port agent** (one owning thread folding over a dataflow stream). No
  locks anywhere.
- **Native `Open.socket` transport, hand-rolled canonical ECF in pure Oz.** Bignum
  integers carry the uint64 tower free; IEEE floats ride as exact bit patterns in
  pure-integer arithmetic (no VM float on the wire — A-OZ-002).
- **Crypto/clock/entropy via a co-process** (`entity-codec-daemon`) over `Open.pipe`
  — the Mozart RPM ships no headers, so a native-functor FFI is out. The seam is a
  small C program linking `libentitycore_codec`; the framing convention is
  documented once in `src/daemon/DAEMON-PROTOCOL.md`.

## Layout

```
src/            one Oz functor per module (codec → identity → store → capability → peer → transport)
src/daemon/     eccodecd.c + DAEMON-PROTOCOL.md (the crypto co-process seam)
test/           conformance.oz (71-vector S2), multisig_accept.oz (K-of-N accept)
status/         PHASE-S*.md, CONFORMANCE-REPORT.{md,json}, SPEC-AMBIGUITY-LOG.md
arch/           PROFILE-RATIONALE.md
profile.toml    the authority on every library/idiom/packaging choice
Makefile        build / s2 / host / multisig-accept / dist
run-s2.sh run-s4.sh run-origination-core.sh
```

Toolchain image: `containers/mozart-toolchain/` (Mozart 2.0.1 release RPM,
SHA-256-pinned, with a baked GO-gate self-test: headless ozc/ozengine + dataflow
threads + bignum boundary + byte-clean `Open.socket` echo + byte-clean `Open.pipe`).

## Build & test (container-bound)

```
# codec conformance (71/71)
podman run … entity-core-keystone/mozart-toolchain:latest \
  bash -lc 'make -C protocol-generator/oz s2'

# core-profile conformance gate
./run-s4.sh                       # drives podman for you

# origination-core (needs the Go entity-peer reference)
./run-origination-core.sh

# multisig K-of-N accept-path unit test
podman run … make -C protocol-generator/oz multisig-accept
```

## Run a peer

```
ozengine build/host.ozf --port 4040 --name alice --daemon build/eccodecd
#   --name NAME   identity from ~/.entity/peers/NAME/keypair (PEM = base64 32-byte seed)
#   --validate    enable the §7a system/validate/* conformance handlers (off by default)
```

## License

Apache-2.0. `libentitycore_codec` is a runtime dependency (the daemon links it), not
bundled.

## Status

v0.1.0-pre — tracks ENTITY-CORE-PROTOCOL V8 / v0.8.0. Provided as a conformance-
anchor peer; not published to a registry (none exists for Oz).
