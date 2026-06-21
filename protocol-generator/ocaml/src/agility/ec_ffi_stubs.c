/* OCaml ↔ entity-codec C-ABI stubs — the Ed448 half of the hybrid agility seam.
 *
 * The OCaml ecosystem has no conformant native Ed448 (mirage-crypto-ec 2.1.0
 * does not implement it — issue mirage/mirage-crypto#112, open since 2021 — and
 * there is no BouncyCastle-equivalent pure-OCaml library). So Ed25519 + SHA-256
 * stay native (Sign / Hash), and the agility higher-bar Ed448 (key_type 0x02)
 * is sourced from libentitycore_codec via the C-ABI. See A-OC-002.
 *
 * These prototypes are transcribed verbatim from the canonical contract
 *   ffi-generator/c-abi/spec/entitycore_codec.h  (C-ABI v1.1, §4.3 / §4.3a / §4.6)
 * — only the symbols this seam calls are declared, so the build needs the shared
 * library (-lentitycore_codec) but not the header on the include path. The .so is
 * the self-contained C impl (libc-only; RFC 8032 §7.4 KAT-exact Ed448, vendored
 * OpenSSL 3.3.2 curve448). The Rust impl is byte-interchangeable (same artifact,
 * provenance via ec_impl_info, not the filename — C-ABI §"interchangeable impls").
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>

/* --- verbatim from entitycore_codec.h --- */
#define EC_OK              0
#define EC_ED448_PUB_LEN   57
#define EC_ED448_SIG_LEN  114
#define EC_SHA384_LEN      48

extern int32_t ec_ed448_seed_to_pubkey(const uint8_t *seed_ptr /* 57 */,
                                        uint8_t *out_pub /* 57 */);
extern int32_t ec_ed448_sign(const uint8_t *priv_ptr /* 57 */,
                             const uint8_t *msg_ptr, size_t msg_len,
                             uint8_t *out_sig /* 114 */);
extern int32_t ec_ed448_verify(const uint8_t *pub_ptr /* 57 */,
                              const uint8_t *msg_ptr, size_t msg_len,
                              const uint8_t *sig_ptr /* 114 */);
extern int32_t ec_sha384(const uint8_t *data_ptr, size_t data_len,
                        uint8_t *out_ptr /* 48 */);
extern const char *ec_abi_version(void);
extern const char *ec_impl_info(void);

/* OCaml strings carry their own length and may embed NULs (CBOR / digests), so
 * everything goes through (ptr, caml_string_length) — never strlen. Outputs are
 * fixed-size by the ABI; we allocate the exact OCaml string and memcpy. A
 * non-EC_OK return becomes an OCaml Failure (the .ml layer maps to result). */

CAMLprim value caml_ec_ed448_seed_to_pubkey(value seed) {
  CAMLparam1(seed);
  CAMLlocal1(out);
  if (caml_string_length(seed) != 57)
    caml_failwith("ec_ed448_seed_to_pubkey: seed must be 57 bytes");
  uint8_t pub[EC_ED448_PUB_LEN];
  int32_t rc = ec_ed448_seed_to_pubkey((const uint8_t *)Bytes_val(seed), pub);
  if (rc != EC_OK) caml_failwith("ec_ed448_seed_to_pubkey: FFI error");
  out = caml_alloc_string(EC_ED448_PUB_LEN);
  memcpy(Bytes_val(out), pub, EC_ED448_PUB_LEN);
  CAMLreturn(out);
}

CAMLprim value caml_ec_ed448_sign(value priv, value msg) {
  CAMLparam2(priv, msg);
  CAMLlocal1(out);
  if (caml_string_length(priv) != 57)
    caml_failwith("ec_ed448_sign: private key (seed) must be 57 bytes");
  uint8_t sig[EC_ED448_SIG_LEN];
  int32_t rc = ec_ed448_sign((const uint8_t *)Bytes_val(priv),
                             (const uint8_t *)Bytes_val(msg),
                             caml_string_length(msg), sig);
  if (rc != EC_OK) caml_failwith("ec_ed448_sign: FFI error");
  out = caml_alloc_string(EC_ED448_SIG_LEN);
  memcpy(Bytes_val(out), sig, EC_ED448_SIG_LEN);
  CAMLreturn(out);
}

CAMLprim value caml_ec_ed448_verify(value pub, value msg, value sig) {
  CAMLparam3(pub, msg, sig);
  if (caml_string_length(pub) != 57 || caml_string_length(sig) != 114)
    CAMLreturn(Val_bool(0));
  int32_t rc = ec_ed448_verify((const uint8_t *)Bytes_val(pub),
                               (const uint8_t *)Bytes_val(msg),
                               caml_string_length(msg),
                               (const uint8_t *)Bytes_val(sig));
  CAMLreturn(Val_bool(rc == EC_OK));
}

CAMLprim value caml_ec_sha384(value data) {
  CAMLparam1(data);
  CAMLlocal1(out);
  uint8_t digest[EC_SHA384_LEN];
  int32_t rc = ec_sha384((const uint8_t *)Bytes_val(data),
                         caml_string_length(data), digest);
  if (rc != EC_OK) caml_failwith("ec_sha384: FFI error");
  out = caml_alloc_string(EC_SHA384_LEN);
  memcpy(Bytes_val(out), digest, EC_SHA384_LEN);
  CAMLreturn(out);
}

CAMLprim value caml_ec_abi_version(value unit) {
  CAMLparam1(unit);
  CAMLreturn(caml_copy_string(ec_abi_version()));
}

CAMLprim value caml_ec_impl_info(value unit) {
  CAMLparam1(unit);
  CAMLreturn(caml_copy_string(ec_impl_info()));
}
