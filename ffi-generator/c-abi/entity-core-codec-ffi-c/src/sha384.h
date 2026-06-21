/*
 * sha384.h — hand-rolled SHA-384 (FIPS 180-4) for the C codec's crypto-agility
 * surface (content_hash_format 0x01). libsodium ships SHA-256 + SHA-512 but NOT
 * SHA-384, and SHA-384 is NOT a truncation of SHA-512 (different IV) — so we
 * hand-roll the SHA-512 compression with the SHA-384 IV. A hash is safe to
 * hand-roll (no secrets, fully vector-checkable); this keeps the artifact
 * self-contained (spec sec.7) without pulling a second crypto lib for one digest.
 *
 * Pinned by the v7.67 agility corpus's SHA-384 digest (verified against the
 * intended 64-byte fixture; see the C verify path). Twin of Rust `sha2::Sha384`.
 */
#ifndef EC_SHA384_H
#define EC_SHA384_H

#include <stddef.h>
#include <stdint.h>

#define EC_SHA384_DIGEST_LEN 48

/* One-shot SHA-384 over `data` → 48-byte `out`. */
void cc_sha384(const uint8_t *data, size_t len, uint8_t out[EC_SHA384_DIGEST_LEN]);

#endif /* EC_SHA384_H */
