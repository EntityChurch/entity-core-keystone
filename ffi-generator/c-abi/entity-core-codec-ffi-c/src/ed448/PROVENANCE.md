# Vendored Ed448 — provenance & supply-chain pins (S6 / S9 / S11)

**Why this exists.** `entity-core-codec-ffi-c` is otherwise self-contained
(libsodium for SHA-256 + Ed25519, hand-rolled SHA-384, hand-rolled Base58; the
`.so` is `ldd` = libc only). libsodium has **no Ed448**, which the v7.66/67
crypto-agility seed tables require. Per the operator decision (user
direction): **vendor a constant-time Ed448 as compiled-in source — not link an
external crypto library** — so the artifact stays self-contained by
construction. OpenSSL-as-a-library was rejected (shared link breaks
self-containment; static is a fedora packaging mess; large symbol surface).
This is the S6 "profile/operator decides the lib, not the agent silently"
record and the S11 pin record.

## What is vendored

All Ed448 source is extracted from **one** pinned upstream, plus a thin wrapper:

| Path | Origin | Role |
|---|---|---|
| `vendor/curve448/*` (18 files) | OpenSSL `crypto/ec/curve448/` | Constant-time Goldilocks field/curve/scalar arithmetic + Ed448 EdDSA (`eddsa.c`). Originally Mike Hamburg / Cryptography Research (the lineage ancestor of the Rust impl's `ed448-goldilocks`). |
| `vendor/keccak/keccak1600.c` | OpenSSL `crypto/sha/keccak1600.c` | Raw Keccak-f[1600] sponge (`SHA3_absorb`/`SHA3_squeeze`). Ed448 hashes with SHAKE256. |
| `vendor/compat/internal/numbers.h` | OpenSSL `include/internal/numbers.h` | 128-bit int types / limits (self-contained, `<limits.h>` only). |
| `vendor/compat/internal/constant_time.h` | OpenSSL `include/internal/constant_time.h` | `constant_time_*` helpers used by the field code (self-contained, needs only `ossl_inline`). |
| `vendor/compat/{openssl,crypto,internal}/*` (shims) | **keystone-authored** | Minimal stand-ins for the OpenSSL-internal headers the vendored `.c` files `#include` (`<openssl/e_os2.h>`, `<openssl/crypto.h>`, `<openssl/macros.h>`, `crypto/ecx.h`, `internal/e_os.h`). We link **no** OpenSSL library, so the heavy `opensslconf.h`/`core.h`/provider chain is deliberately omitted; the shims provide only the handful of macros/types actually used (`ossl_inline`, `__owur`, `OSSL_LIB_CTX`, `OPENSSL_cleanse` decl, `NON_EMPTY_TRANSLATION_UNIT`, the public X448 size constants). |
| `ec_shake256.{h,c}` | **keystone-authored** | SHAKE256 (FIPS 202) buffering over the keccak1600 sponge: standard SHA-3 absorb / 0x1F-pad / squeeze, rate 136. Renamed `shake256_*` (not `ec_*`) so the export.map version script localizes it. |
| `ed448_glue.{h,c}` | **keystone-authored** | Adapter from the codec's `ec_ed448_*` ABI to `ossl_ed448_*`; pure Ed448 (empty context, phflag 0). Also defines `OPENSSL_cleanse`. |

## Upstream pin (S11)

- **Source:** OpenSSL **3.3.2** (well over 30 days old at pin time, satisfies S11).
- **Tarball:** `github.com/openssl/openssl/archive/refs/tags/openssl-3.3.2.tar.gz`
  **sha256 `bedbb16955555f99b1a7b1ba90fc97879eb41025081be359ecd6a9fcbdf1c8d2`**.
- **License:** Apache-2.0 — matches the S9 default for generated/vendored output.
- Verification shas of the key extracted files (as vendored):
  - `vendor/keccak/keccak1600.c` `bc377ba753feb1ee9b564f309cc928b819f03914a3272080806f2e5344f78734`
  - `vendor/compat/internal/numbers.h` `a522330d99080c48cd3998dfcddce6b2243a80a62765fe7fb18753b3676d096d`
  - `vendor/compat/internal/constant_time.h` `5a02b13f7f0c6eaa1a891f58c3f3d09ca35adbe76d97b593205f349446c0f406`
  - `vendor/curve448/*` shas: see git; only `eddsa.c` is modified from upstream
    (upstream sha `0c549facfbcf8154624ad2f70315e79f00371d5cc42edd824a618aa1fdf3b14a`).

## The one upstream modification

`vendor/curve448/eddsa.c` is the **only** vendored file changed from upstream.
The change retargets its SHAKE256 hashing off the OpenSSL EVP/provider layer
(which would require linking libcrypto) onto the self-contained `ec_shake256`
wrapper — same Keccak sponge, same pinned source. Every change is fenced by a
`KEYSTONE FFI MODIFICATION` banner at the top of the file: the `EVP_MD_CTX`
handle becomes a `shake256_ctx`, `EVP_Digest{Update,FinalXOF}` become
`shake256_{update,final_xof}`, `oneshot_hash`/`hash_init_with_dom` are rewritten
to call the wrapper, and the (always-NULL) `OSSL_LIB_CTX *ctx` / `propq` params
are retained but ignored. The curve/field/scalar arithmetic is byte-for-byte
upstream.

## Correctness evidence (not "trust the vendor")

- **RFC 8032 §7.4 KAT** (`conformance/ed448_kat.c`): the C impl reproduces the
  canonical Ed448 pubkey + 114-byte signature byte-for-byte from the spec's
  secret key over the empty message; verify accepts the good sig and rejects a
  tampered one. Independent ground truth — not a cross-impl comparison.
- **C↔Rust ABI differential** (`conformance/abi_differential.c`, dlmopen):
  seed→pubkey, sign, verify-good, verify-tampered agree byte-for-byte across the
  real boundary over the corpus seeds 0x42/0x46 — **101/101**. Rust
  (`ed448-goldilocks`) is corpus-pin-proven, so C is transitively corpus-correct.
  Two independent codebases (OpenSSL-curve448 vs ed448-goldilocks) converging to
  the byte is the S8 convergence guarantee for the 5th impl.

## Re-vendoring (idempotent)

In `containers/c-toolchain` (network needed only for this author-time step, never
the build): fetch `openssl-3.3.2.tar.gz`, verify the tarball sha above, extract
`crypto/ec/curve448/`, `crypto/sha/keccak1600.c`,
`include/internal/{numbers,constant_time}.h`, then re-apply the `eddsa.c`
SHAKE retarget (the banner marks every hunk). The build itself pulls nothing.
