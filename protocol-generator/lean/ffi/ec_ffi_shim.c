/* entity-core-protocol-lean — crypto FFI shim (S2).
 *
 * Bridges Lean's ByteArray ABI to the C-ABI byte-pointer functions exported by
 * libentitycore_codec (ffi-generator/c-abi). The C-ABI takes raw
 * (uint8_t*, len) buffers; Lean passes ByteArray as a boxed scalar-array
 * object, so each wrapper pulls cptr/size and (for outputs) allocates a Lean
 * sarray. Same pattern proved out by the S1/1c crypto-ffi spike.
 *
 * Primitives bridged here:
 *   - ec_sha256          (content_hash construction; corpus fixture sha pin)
 *   - ec_ed25519_sign    (signature.* vectors: deterministic seed-based sign)
 *   - ec_ed25519_keygen  (S3 peer identity: fresh keypair at startup)
 *   - ec_ed25519_verify  (S3 §5.5 chain-walk signature verification)
 *   - ec_impl_info       (provenance: which library actually linked)
 *
 * CRYPTO IS THE SPEC'S OWN TRUST BOUNDARY (S1 1a §4): these @[extern] defs do
 * not reduce in the kernel, so signature/hash properties are axiomatic in Lean.
 * V7 cites Ed25519/SHA-256 normatively but does not define them — prove the
 * protocol, trust the primitive. */

#include <lean/lean.h>
#include <stdint.h>
#include <stddef.h>

/* Provided by libentitycore_codec, linked via the lakefile's moreLinkArgs. */
extern int32_t ec_sha256(const uint8_t *data_ptr, size_t data_len,
                         uint8_t *out_ptr /* 32 */);
extern int32_t ec_ed25519_sign(const uint8_t *priv_ptr /* 32 */,
                               const uint8_t *msg_ptr, size_t msg_len,
                               uint8_t *out_sig /* 64 */);
extern int32_t ec_ed25519_keygen(uint8_t *out_priv /* 32 */, uint8_t *out_pub /* 32 */);
extern int32_t ec_ed25519_seed_to_pubkey(const uint8_t *seed_ptr /* 32 */,
                                         uint8_t *out_pub /* 32 */);
extern int32_t ec_ed25519_verify(const uint8_t *pub_ptr /* 32 */,
                                 const uint8_t *msg_ptr, size_t msg_len,
                                 const uint8_t *sig_ptr /* 64 */);
extern const char *ec_impl_info(void);

/* sha256 : @& ByteArray -> ByteArray  (32-byte digest) */
LEAN_EXPORT lean_obj_res ec_lean_sha256(b_lean_obj_arg data) {
    size_t len = lean_sarray_size(data);
    const uint8_t *ptr = lean_sarray_cptr(data);
    lean_object *out = lean_alloc_sarray(1, 32, 32); /* elem_size=1, size=cap=32 */
    ec_sha256(ptr, len, lean_sarray_cptr(out));
    return out;
}

/* ed25519Sign : @& ByteArray (seed, 32) -> @& ByteArray (msg) -> ByteArray (sig, 64)
 * The 32-byte "seed" IS the Ed25519 secret key (RFC 8032). Signing is
 * deterministic, so a fixed seed + fixed message yields a fixed 64-byte sig —
 * exactly what the corpus signature.* vectors pin. On a malformed seed length
 * the C-ABI returns nonzero; we still return a 64-byte buffer (zeros) so the
 * Lean side stays total — a wrong-length seed simply fails the byte-compare. */
LEAN_EXPORT lean_obj_res ec_lean_ed25519_sign(b_lean_obj_arg seed,
                                              b_lean_obj_arg msg) {
    const uint8_t *sptr = lean_sarray_cptr(seed);
    const uint8_t *mptr = lean_sarray_cptr(msg);
    size_t mlen = lean_sarray_size(msg);
    lean_object *out = lean_alloc_sarray(1, 64, 64);
    ec_ed25519_sign(sptr, mptr, mlen, lean_sarray_cptr(out));
    return out;
}

/* ed25519Keygen : Unit -> ByteArray (64 = priv32 ‖ pub32)
 * S3 peer identity: a fresh RFC-8032 keypair minted at startup. Returned as one
 * 64-byte buffer (priv ‖ pub); the Lean side slices it. validate-peer dials
 * whatever peer is listening, so a fresh per-boot identity is sufficient (no
 * fixed-seed → pubkey derivation needed; the C-ABI exposes keygen, not
 * seed_to_pubkey, for ed25519). */
LEAN_EXPORT lean_obj_res ec_lean_ed25519_keygen(uint32_t salt, lean_obj_arg w) {
    (void)salt; (void)w;
    lean_object *out = lean_alloc_sarray(1, 64, 64);
    uint8_t *o = lean_sarray_cptr(out);
    ec_ed25519_keygen(o /* priv -> [0,32) */, o + 32 /* pub -> [32,64) */);
    return lean_io_result_mk_ok(out);
}

/* ed25519SeedToPubkey : @& ByteArray (seed,32) -> ByteArray (pub,32)
 * Deterministically derive the RFC-8032 Ed25519 public key from a 32-byte seed
 * (the secret key). Lets a peer adopt a *persistent* identity from an on-disk
 * keypair (--name): the seed is loaded from PEM, the pubkey re-derived here, so a
 * fixed seed → a fixed peer_id across runs (and matches the Go validator's
 * FromSeed().PeerID()). A malformed seed length makes the C-ABI return nonzero;
 * we still return a 32-byte buffer (zeros) so the Lean side stays total. */
LEAN_EXPORT lean_obj_res ec_lean_ed25519_seed_to_pubkey(b_lean_obj_arg seed) {
    const uint8_t *sptr = lean_sarray_cptr(seed);
    lean_object *out = lean_alloc_sarray(1, 32, 32);
    ec_ed25519_seed_to_pubkey(sptr, lean_sarray_cptr(out));
    return out;
}

/* ed25519Verify : @& ByteArray (pub,32) -> @& ByteArray (msg) -> @& ByteArray (sig,64) -> Bool
 * The §5.5 chain-walk signature check. Returns true iff the C-ABI verifies (rc==0).
 * A wrong-length pub/sig makes the C-ABI return nonzero → false (stays total). */
LEAN_EXPORT uint8_t ec_lean_ed25519_verify(b_lean_obj_arg pub,
                                           b_lean_obj_arg msg,
                                           b_lean_obj_arg sig) {
    const uint8_t *pptr = lean_sarray_cptr(pub);
    const uint8_t *mptr = lean_sarray_cptr(msg);
    size_t mlen = lean_sarray_size(msg);
    const uint8_t *gptr = lean_sarray_cptr(sig);
    return ec_ed25519_verify(pptr, mptr, mlen, gptr) == 0 ? 1 : 0;
}

/* implInfo : Unit -> String  (provenance: which library actually linked) */
LEAN_EXPORT lean_obj_res ec_lean_impl_info(lean_obj_arg unit) {
    lean_dec(unit);
    return lean_mk_string(ec_impl_info());
}
