# entity-core-protocol-fortran — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/fortran-toolchain:latest` (gfortran 15.2)
**Status:** ✅ **COMPLETE — full pinned-corpus gate 69/69 (0 fail, 0 skip); unit suite ALL PASS.**
Reproduce: `./run-s2.sh` → `make test` (container-bound, `--network=none`).
Report: `status/CONFORMANCE-REPORT.md`.

The fixed-width SIGNED-ONLY numeric probe is validated: a substrate whose only wide
integer is a signed `integer(int64)` reproduced ECF's full unsigned integer tower
`[0, 2^64-1]` (incl. the `[2^63, 2^64-1]` octet the corpus itself never reaches, via the
mandatory head-form self-test) AND the native-IEEE float tower byte-identically to the
corpus — the uint boundary carried as an explicit 64-bit bit pattern with no side-channel.
No spec defect on the numeric seam (A-FTN-002/003 = corroboration, like Tcl/Rexx). One
real corpus-coverage finding surfaced (A-FTN-012) and one durable gfortran lesson (A-FTN-011).

## Done — files created (all under `protocol-generator/fortran/`)

| File | Role |
|---|---|
| `src/status.f90` | error model (status-code): EC_*-aligned codes + codec leaf-reject kinds |
| `src/varint.f90` | LEB128 varint primitives (N1) — pure Fortran over `ishft`/`iand` bit-carrier |
| `src/entity_core_ffi.f90` | `iso_c_binding` interface blocks matching the VERBATIM `entitycore_codec.h` (ec_* crypto/SHA/framing/base58) — bound DIRECTLY, no C wrapper |
| `src/cbor.f90` | **the numeric probe**: `ecf_value_t` tagged-union model + canonical ECF encode/decode + signed-carrier uint64 tower + native-IEEE + hand-rolled f16/shortest ladder + N2 tag scanner + N3 empty-map + `cbor_scan_len` (N4) + head-form self-test |
| `src/entity.f90` | entity framing composed from codec + FFI: content_hash / peer_id / sign / verify (core types only) |
| `test/conformance.f90` | the S2 GATE — corpus driver (decode with our own decoder, re-encode + byte-compare; Class B via FFI) |
| `test/unit_tests.f90` | N1–N4 covering tests + accept-path (map sort, float ladder, nint, ult, signed-carrier self-test) |
| `Makefile`, `run-s2.sh` | container-bound build + gate (rexx-shaped; builds `libentitycore_codec` if absent) |
| `status/CONFORMANCE-REPORT.md`, `status/PHASE-S2.md`, `status/SPEC-AMBIGUITY-LOG.md` (updated) | reports |

## Findings / decisions (S2)

- **A-FTN-002 (the signed-carrier uint64 probe) — CLOSED as corroboration.** The head-form
  self-test round-trips `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}` byte-exact; all 14 int + 14
  float vectors green. Bit-pattern emission (`ishft`/`iand`) + the `ult()` bias-trick
  compare carry the full uint tower on a signed-only substrate with no ad-hoc convention.
  The float tower is tractable (contrast Rexx): native `transfer` for f32/f64, hand-rolled
  f16 verified by round-trip-bit-compare. **No spec-precision finding — the spec is tight
  enough to force even a signed-only substrate to carry the unsigned tower exactly.**
- **A-FTN-011 (gfortran lesson — RESOLVED).** The obvious recursive value model
  (`type(ecf_value_t), allocatable :: items(:)`) DOUBLE-FREES: gfortran 15.2's generated
  recursive auto-deallocator mis-frees on the deep corpus (SIGABRT reproduced). Fix: the
  self-referential aggregate is a **POINTER** (never auto-deallocated / never dtor-followed);
  byte payloads stay allocatable. Arena-like lifetime (freed at process exit; S3's store
  owns lifetime explicitly). A durable lesson for any gfortran-family peer.
- **A-FTN-012 (corpus finding — arch escalation).** `tag_reject.1/2/3/5` do NOT contain the
  tags their `.diag` descriptions claim (they decode to a leading entity + trailing
  garbage; the intended `a1` map byte reads as `61` text-1). They exercise ONLY the
  full-consumption / trailing-data reject (matching the reference C codec `ecf.c:471`), NOT
  the §6.3 tag scanner. Only `tag_reject.4` covers N2 — so a trailing-only decoder passes
  5/5 tag vectors vacuously. Our decoder does BOTH; `t_n2_tag_reject` adds the real
  nested-tag coverage. Candidate `HANDOFF-TO-ARCH` (corpus regen; F16-class defect).
- **A-FTN-010 (deferred).** test-drive not yet vendored under `--network=none`; unit suite
  is plain-Fortran assertions (same coverage). Vendor `testdrive.F90` + re-express at S3.

## What S3 must know

- **The codec surface is ready + reusable.** `entity_core_cbor` (`cbor_encode` /
  `cbor_decode` returning `consumed` / `cbor_scan_len` for N4 original-bytes),
  `entity_core_entity` (content_hash / peerid / sign / verify), `entity_core_varint`,
  `entity_core_ffi`, `entity_core_status`. Compile order is dependency-linear
  (status → varint/ffi → cbor → entity) and encoded in the Makefile.
- **VALUE MODEL IS POINTER-BASED (A-FTN-011).** `ecf_value_t%items(:)` is a pointer, never
  freed by the codec — the decoded tree is arena-like. S3's store must own entity lifetime
  explicitly (module-level allocatable records per `[async] store_model`); do NOT try to
  deep-free a decoded tree (the gfortran dtor bug is why it's a pointer). Assignment of an
  `ecf_value_t` is a SHALLOW (pointer) copy of `items` — fine for read; a real store needs
  to retain the original wire bytes (N4) not the tree.
- **Full-consumption is a reject (A-FTN-012).** A message/frame decode MUST reject trailing
  bytes — `cbor_decode` reports `consumed`; the peer's frame path checks `consumed == len`.
  This is how 4 of the 5 tag_reject vectors are actually rejected.
- **iso_c_binding direct bind works end-to-end** — no helper binary (unlike Rexx), no
  stubs shim (unlike Tcl). The ONLY C wrapper S3 needs is the socket net-shim
  (`src/ext/net_shim.c`, `ec_net_*`), per profile `[async]`. Crypto stays direct.
- **Pins confirmed** at S2 entry (3 spec-data + corpus SHA-256, all match MANIFEST).
- **Next: S3** — the live networked peer (single-thread select loop over the C net-shim;
  §6.11 manual reentry pump; §7b store-safety structural). Error model is the same
  `intent(out) stat` status-code convention already used throughout the codec.
