/* Lean S1/1c spike — CRYPTO FFI shim.
 *
 * Bridges Lean's ByteArray ABI to the C-ABI byte-pointer functions exported by
 * libentitycore_codec (ffi-generator/c-abi). The C-ABI takes raw (uint8_t*, len)
 * buffers; Lean passes ByteArray as a boxed scalar-array object, so each wrapper
 * pulls the cptr/size and (for outputs) allocates a Lean sarray. This is the
 * OCaml/Swift/Zig FFI-hybrid precedent: prove the protocol, trust the curve. */

#include <lean/lean.h>
#include <stdint.h>
#include <stddef.h>

/* Provided by libentitycore_codec, linked via the lakefile's moreLinkArgs. */
extern int32_t ec_sha256(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr);
extern int32_t ec_ed25519_keygen(uint8_t *out_priv, uint8_t *out_pub);
extern int32_t ec_ed25519_sign(const uint8_t *priv_ptr,
                               const uint8_t *msg_ptr, size_t msg_len,
                               uint8_t *out_sig);
extern int32_t ec_ed25519_verify(const uint8_t *pub_ptr,
                                 const uint8_t *msg_ptr, size_t msg_len,
                                 const uint8_t *sig_ptr);
extern const char *ec_impl_info(void);

/* sha256 : @& ByteArray -> ByteArray  (32-byte digest) */
LEAN_EXPORT lean_obj_res ec_lean_sha256(b_lean_obj_arg data) {
    size_t len = lean_sarray_size(data);
    const uint8_t *ptr = lean_sarray_cptr(data);
    lean_object *out = lean_alloc_sarray(1, 32, 32);  /* elem_size=1, size=32, cap=32 */
    ec_sha256(ptr, len, lean_sarray_cptr(out));
    return out;
}

/* implInfo : Unit -> String  (provenance: which library actually linked) */
LEAN_EXPORT lean_obj_res ec_lean_impl_info(lean_obj_arg unit) {
    lean_dec(unit);
    return lean_mk_string(ec_impl_info());
}

/* ed25519Selftest : @& ByteArray -> Bool
 * keygen -> sign(msg) -> verify; returns true iff the full round-trip succeeds.
 * Exercises the sign/verify boundary end-to-end through the C-ABI. */
LEAN_EXPORT uint8_t ec_lean_ed25519_selftest(b_lean_obj_arg msg) {
    size_t len = lean_sarray_size(msg);
    const uint8_t *mptr = lean_sarray_cptr(msg);
    uint8_t priv[32], pub[32], sig[64];
    if (ec_ed25519_keygen(priv, pub) != 0) return 0;
    if (ec_ed25519_sign(priv, mptr, len, sig) != 0) return 0;
    return ec_ed25519_verify(pub, mptr, len, sig) == 0 ? 1 : 0;
}
