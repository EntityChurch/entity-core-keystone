# entity-core-protocol-cpp — Phase S3 (Peer machinery) Summary

**Release "reach" peer** (C++23 — RAII / `std::expected` / `std::span` /
`std::shared_ptr` store / threads idiom; systems/games/embedded coverage; corroboration-only) ·
**Status: COMPLETE — peer compiles GREEN on BOTH g++ 15.2.1 AND clang++ 21.1.8 under `-Wall -Wextra
-Werror -pedantic`, ASan/LSan/UBSan-clean; smoke 13/13 (incl. §6.11 reentry), type-registry 53/53
byte-identical, multi-sig accept-path 9/9. No new spec defect (well stays dry).**

## Result

L1–L4 + foundation built on the S2 codec, idiomatic C++23:

- **Two-peer loopback smoke 13/13** over real localhost TCP, ASan/LSan/UBSan-clean, on both
  compilers. Handshake both directions (§4.1 hello→authenticate); 404 on an unregistered path;
  granted tree-get → 200 returning a `system/handler/interface`; capability-request → 200
  (mint-bounded); **8/8 interleaved request_id-correlated** (N7 / §6.11 demux); §6.13(a) handler
  register → 200 (live, not 501); §6.13(c) emit hook fired; §7a echo → 200 verbatim; **§6.11 reentry
  dispatch-outbound → 200** (the S4 origination-core surface, smoke-tested below). The peer_id is
  `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (seed `0x11`×32) — the **cohort-standard** value,
  confirming wire interop.
- **Type-registry 53/53 byte-identical** (`test/typereg.cpp`) — render-from-model: each of the §9.5
  53-type core floor's `data` maps (generated from the shared `type-registry-shapes.json` by
  `tools/gen-typedefs.py` → `src/core_typedefs.cpp`) is materialized as a `system/type` entity whose
  content_hash, computed by our own S2-green codec, matches the canonical
  `type-registry-vectors-v1.cbor` exactly (decoded with our own decoder — a free decoder cross-check).
- **Multi-sig accept-path 9/9** (`test/multisig_accept.cpp`) — **GENUINE §3.6 K-of-N built the first
  time** (see "Genuine multi-sig" below). 2-of-3 (incl. local) → ALLOW; M3/M4/M6 deny-flips
  (n<2, threshold>n, threshold<2, duplicate signers, has-a-parent, only-1-of-2-sigs, local-not-in-
  signers); single-sig superset still ALLOWs.
- **Both compilers, `-Werror -pedantic`, sanitizers clean.** The A-CPP-010 `Box` recursive-variant
  discipline held across the whole peer layer on g++ AND clang++. 10× smoke stress (deadlock/race
  check) all green.

## What was built (modules)

| Layer | File(s) | Notes |
|---|---|---|
| Entity + envelope | `entity.{hpp,cpp}` | immutable `Entity` held by `std::shared_ptr<const Entity>` (A-C-009 pre-resolved structurally); §3.1 envelope, §1.8 content_hash fidelity (N5) |
| Identity (L1) | `peer_identity.{hpp,cpp}` | Ed25519 keypair → §1.5 peer_id, `system/peer` entity, §3.5 sign/verify (signs the full 33-byte content_hash) |
| Store (foundation) | `store.{hpp,cpp}` | content + tree maps under a `std::shared_mutex` (§4.8 many-reader/one-writer); §6.13(c) emit bus (live, zero consumers) |
| Wire (§3.2/§3.3) | `wire.{hpp,cpp}` | EXECUTE / EXECUTE_RESPONSE / error / empty-params / resource-target; 16 MiB frame bound |
| Capability (L3) | `capability.{hpp,cpp}` | §5.4 patterns, §5.2 trichotomy, §5.5 chain + **genuine §3.6 multi-sig K-of-N**, §5.6 attenuation, §PR-8 granter frame, §4.10(b) depth pre-check |
| Type registry | `core_typedefs.{hpp,cpp}` + `tools/gen-typedefs.py` | §9.5 53-type render-from-model (generated, byte-diffed) |
| Dispatch brain | `dispatch.cpp` (`peer.hpp`) | §6.2 connect/tree/handler/capability + §9.5 type handler, §6.5 chain, §6.6 resolution, §6.9a bootstrap + seed policy, §7a conformance handlers, §6.13(b) reentry |
| Transport (L4) | `transport.{hpp,cpp}` | one `std::thread` reader per connection, §6.11 demux (mutex + condvar slots), §4.8 inbound-concurrent-with-outbound dispatch, §7b TCP_NODELAY, the §6.13(b) reentry seam, listener/dialer/session+handshake |

## Idiom (how the §4.8/§7b store-safety is achieved)

- **Error model:** `std::expected<T, EcfError>` value-channel throughout (the profile's `result`
  idiom); the dispatcher maps a verdict → wire status at the boundary; **no exceptions on the
  dispatch path**.
- **Memory:** RAII + value semantics. The materialized entity is **immutable** and held by
  `std::shared_ptr<const Entity>` everywhere it is shared. The only thread-shared mutation is the
  refcount, which `shared_ptr`'s control block makes atomic by the C++ standard — the C peer's
  hand-rolled `atomic_int` (A-C-009) is **free** here, and immutability removes the pointee-mutation
  hazard entirely (A-CPP-011). No raw `new`/`delete` in peer code.
- **Store-safety (§4.8):** a `std::shared_mutex` guards both store maps (RAII `std::shared_lock` /
  `std::unique_lock` — no manual unlock); reads dominate the dispatch path, so the shared_mutex
  beats a plain mutex. Entity *lifetime* is `shared_ptr`-atomic, the store *maps* are mutex-guarded
  → §4.8 is structural, not bolted-on. Witnessed by 8-way concurrent demux + 10× stress, ASan-clean.
- **Concurrency (§7b):** one OS `std::thread` reader per connection — a blocking `recv` only blocks
  that connection's own thread (the Swift cooperative-pool-starvation trap is sidestepped
  structurally). Each inbound EXECUTE is dispatched on its own detached thread (§4.8 inbound-
  concurrent-with-outbound). **TCP_NODELAY** is set on every connection socket (the Zig Nagle
  finding). A per-connection write mutex serializes the shared stream.
- **Reentry (§6.11 / §6.13(b)):** the reader demuxes EXECUTE_RESPONSE by `request_id` via a
  condvar-slot table; an inbound EXECUTE on a session connection dispatches on its own thread
  (reentry B-role). `dispatch-outbound` originates an EXECUTE back to the caller over the **same
  inbound connection** and awaits the correlated response — proven over real two-peer TCP (smoke
  scenario 3).

## Genuine multi-sig K-of-N (the keystone S3 mandate)

The closest analog — the native **C** peer (#10) — ships **no** genuine multi-sig (its `verify_chain`
is single-sig only; the cohort multi-sig closeout post-dates the C build). Per the S3 brief, C++
built it **right the first time** (A-CPP-012), porting the canonical C# `ChainVerifier.
VerifyMultiSigRoot` contract:

- the `granter` is a **union** (single `system/hash` | `{signers, threshold}` map, **root-only**);
- at the chain root, `verify_multi_sig_root` runs **§3.6 M3 structure** (parent-null, n≥2,
  2≤threshold≤n, distinct signers) **before** signature counting, then **§5.5 M6** (local ∈ signers)
  + **M4** (**distinct**-signer valid-sig count over the cap's content_hash ≥ threshold — the K-of-N
  replay defense);
- multi-sig is root-only (off-root multi-granter denies); single-sig is a **strict superset**.

The **accept-path unit test** (`test/multisig_accept.cpp`, 9/9) exercises the direction the
rejection-only validate-peer `multisig` category cannot: a real 2-of-3 quorum (the local peer is one
of the signers) → ALLOW, every M3/M4/M6 deny-flip, and the single-sig superset.

## §6.11 reentry transport + §7a conformance handlers

- `system/validate/{echo,dispatch-outbound}` are wired behind the **conformance** flag (the host
  `--validate` opt-in; **OFF by default** — `dispatch-outbound` is a standing dialer). `echo` returns
  its params verbatim; `dispatch-outbound` is a generic relay that forwards `value` verbatim.
- The §6.11 reentry loop is **smoke-tested green over real two-peer TCP**: the initiator (validator,
  B-role) mints a reentry cap authorizing the responder to call the initiator's `system/validate/
  echo`; the responder's `dispatch-outbound` originates the EXECUTE back over the **same inbound
  connection**; the initiator's reader dispatches it; the echo result flows back → 200. This is the
  surface the S4 `origination-core` gate's `dispatch_outbound_reentry` (3/3) needs — **not** a from-
  zero transport rewrite at S4 (the trap OCaml/COBOL hit; the reader-demux + request_id correlation
  is built now).

## Ambiguities logged

3 net-new entries (`SPEC-AMBIGUITY-LOG.md`): **A-CPP-011** (shared-entity model, A-C-009 pre-resolved
structurally), **A-CPP-012** (genuine multi-sig built at S3), **A-CPP-013** (`libtsan` absent from
the `cpp-toolchain` image → recommend adding it for a TSan concurrency pass before S4). **All C++
engineering / container findings — none a spec defect.** Corroboration-only reach peer; the
discovery well stays dry, exactly as the slate predicted.

## Build / run

```
# g++ (default)
cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build --output-on-failure
# clang++ cross-pass
cmake -S . -B build-clang -G Ninja -DCMAKE_CXX_COMPILER=clang++ && cmake --build build-clang \
  && ctest --test-dir build-clang --output-on-failure
```

Everything runs in the `entity-core-keystone/cpp-toolchain:latest` image (`--network=none` for
builds; loopback TCP is in the container's own netns, so the smoke runs offline too).

## Phase exit

Smoke green (13/13) on both compilers; peer compiles cleanly (`-Werror -pedantic`, ASan/LSan/UBSan);
type-registry 53/53; multi-sig accept-path 9/9; §6.11 reentry surface built + smoke-tested. The code
reads as C++23 (RAII, `std::expected`, `std::shared_ptr`, threads, value semantics) — not transpiled.
**Ready for S4 `validate-peer --profile core`** (NOT run this phase, per the S3 boundary).
