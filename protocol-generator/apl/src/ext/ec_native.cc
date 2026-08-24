/*
 * entity-core-protocol-apl — src/ext/ec_native.cc
 *
 * GNU APL NATIVE FUNCTION (⎕FX) C++ shim binding libentitycore_codec's ec_*
 * symbols (crypto floor §9.1, SHA-256/384, base58 peer-id). This is the FFI
 * half of the FFI-HYBRID codec: the canonical CBOR VALUE codec is hand-rolled
 * pure APL (src/cbor.apl — the array-model probe); crypto / base58 cross HERE
 * because there is no native audited APL crypto and APL has no exact integer
 * past 2^63 (base58 long-division would be lossy — A-APL-010).
 *
 * Mechanism (A-APL-009, verified in the toolchain image): a native-fn .so is
 * compiled against apl's RETAINED source-tree headers (Value.hh/Cell.hh/... at
 * $APL_SRC=/opt/apl-1.9/src + the configure-generated config.h at the build
 * root) — `make install` ships only libapl.h. apl is linked -export-dynamic,
 * so this dlopen'd .so resolves apl's own symbols at ⎕FX load. Loaded from APL
 * via  'src/ext/ec_native.so' ⎕FX 'EcNative'.
 *
 * ABI to APL: a single DYADIC native function  Z ← opcode EcNative B
 *   opcode 1  EcSha256      B = data bytes            → 32 bytes
 *   opcode 2  EcSha384      B = data bytes            → 48 bytes
 *   opcode 3  seed_to_pubkey B = seed(32)             → 32 bytes
 *   opcode 4  ed25519_sign  B = (priv32)(msg)         → 64 bytes
 *   opcode 5  ed25519_verify B = (pub32)(msg)(sig64)  → rc (1 int: 0 ok / <0)
 *   opcode 6  peerid_format B = (keyType)(hashType)(digest) → base58 ASCII bytes
 *   opcode 7  peerid_parse  B = base58 ASCII bytes    → (keyType hashType) , digest
 * Byte vectors cross as APL integer cells 0..255 (the array byte model, matching
 * ⎕FIO recv/send). The result is always an APL integer vector.
 */

#include <cstring>
#include <cstdint>
#include <vector>

#include "Native_interface.hh"
#include "Value.hh"

// the verbatim C-ABI header (entitycore_codec.h, C-ABI 1.1); -I the spec dir.
#include "entitycore_codec.h"

class NativeFunction;

// mandatory native-function entry points
extern "C" void * get_function_mux(const char * function_name);
static Fun_signature get_signature() { return SIG_Z_A_F2_B; }
static bool close_fun(Cause, const NativeFunction *) { return true; }
static Token eval_AB(Value_P A, Value_P B, const NativeFunction * caller);

void *
get_function_mux(const char * function_name)
{
   if (!strcmp(function_name, "get_signature"))
      return reinterpret_cast<void *>(&get_signature);
   if (!strcmp(function_name, "eval_AB"))
      return reinterpret_cast<void *>(&eval_AB);
   if (!strcmp(function_name, "close_fun"))
      return reinterpret_cast<void *>(&close_fun);
   return 0;
}

// ── helpers: APL Value <-> bytes ─────────────────────────────────────────────

// read every ravel cell of `v` as one octet (0..255).
static std::vector<uint8_t>
to_bytes(Value_P v)
{
   std::vector<uint8_t> out;
   const ShapeItem n = v->element_count();
   out.reserve(n);
   for (ShapeItem i = 0; i < n; ++i)
      out.push_back((uint8_t)(v->get_cravel(i).get_near_int() & 0xFF));
   return out;
}

// read the k-th element of a nested B as bytes (it is a nested/pointer cell).
static std::vector<uint8_t>
nested_bytes(Value_P B, ShapeItem k)
{
   const Cell & c = B->get_cravel(k);
   if (c.is_pointer_cell())   return to_bytes(c.get_pointer_value());
   // a length-1 element (e.g. a single-byte vector reduced to a scalar int)
   std::vector<uint8_t> one;
   one.push_back((uint8_t)(c.get_near_int() & 0xFF));
   return one;
}

// build an APL integer vector result from raw bytes.
static Token
ret_bytes(const uint8_t * p, size_t n)
{
   Value_P Z(ShapeItem(n), LOC);
   for (size_t i = 0; i < n; ++i)   Z->next_ravel_Int(p[i] & 0xFF);
   Z->check_value(LOC);
   return Token(TOK_APL_VALUE1, Z);
}

// build a length-1 integer vector (a status code / small scalar-ish result).
static Token
ret_int(int64_t v)
{
   Value_P Z(ShapeItem(1), LOC);
   Z->next_ravel_Int(v);
   Z->check_value(LOC);
   return Token(TOK_APL_VALUE1, Z);
}

static uint8_t EC_DUMMY = 0;   // valid ptr for zero-length inputs

// ── dispatch ─────────────────────────────────────────────────────────────────

static Token
eval_AB(Value_P A, Value_P B, const NativeFunction * caller)
{
   const int opcode = (int)A->get_cfirst().get_near_int();

   switch (opcode)
      {
        case 1:   // SHA-256
           {
             std::vector<uint8_t> d = to_bytes(B);
             uint8_t out[EC_SHA256_LEN];
             int rc = ec_sha256(d.empty() ? &EC_DUMMY : d.data(), d.size(), out);
             if (rc != EC_OK)   return ret_int(rc);
             return ret_bytes(out, EC_SHA256_LEN);
           }
        case 2:   // SHA-384
           {
             std::vector<uint8_t> d = to_bytes(B);
             uint8_t out[EC_SHA384_LEN];
             int rc = ec_sha384(d.empty() ? &EC_DUMMY : d.data(), d.size(), out);
             if (rc != EC_OK)   return ret_int(rc);
             return ret_bytes(out, EC_SHA384_LEN);
           }
        case 3:   // Ed25519 seed -> public key
           {
             std::vector<uint8_t> s = to_bytes(B);
             uint8_t out[EC_ED25519_PUB_LEN];
             int rc = ec_ed25519_seed_to_pubkey(s.data(), out);
             if (rc != EC_OK)   return ret_int(rc);
             return ret_bytes(out, EC_ED25519_PUB_LEN);
           }
        case 4:   // Ed25519 sign: B = (priv32)(msg)
           {
             std::vector<uint8_t> priv = nested_bytes(B, 0);
             std::vector<uint8_t> msg  = nested_bytes(B, 1);
             uint8_t sig[EC_ED25519_SIG_LEN];
             int rc = ec_ed25519_sign(priv.data(),
                                      msg.empty() ? &EC_DUMMY : msg.data(),
                                      msg.size(), sig);
             if (rc != EC_OK)   return ret_int(rc);
             return ret_bytes(sig, EC_ED25519_SIG_LEN);
           }
        case 5:   // Ed25519 verify: B = (pub32)(msg)(sig64) -> rc
           {
             std::vector<uint8_t> pub = nested_bytes(B, 0);
             std::vector<uint8_t> msg = nested_bytes(B, 1);
             std::vector<uint8_t> sig = nested_bytes(B, 2);
             int rc = ec_ed25519_verify(pub.data(),
                                        msg.empty() ? &EC_DUMMY : msg.data(),
                                        msg.size(), sig.data());
             return ret_int(rc);
           }
        case 6:   // peer-id format: B = (keyType)(hashType)(digest) -> base58 ASCII
           {
             const uint64_t kt = (uint64_t)B->get_cravel(0).get_near_int();
             const uint64_t ht = (uint64_t)B->get_cravel(1).get_near_int();
             std::vector<uint8_t> dig = nested_bytes(B, 2);
             uint8_t out[128];
             size_t out_len = 0;
             int rc = ec_peerid_format(kt, ht, dig.data(), dig.size(),
                                       out, sizeof out, &out_len);
             if (rc != EC_OK)   return ret_int(rc);
             return ret_bytes(out, out_len);
           }
        case 7:   // peer-id parse: B = base58 ASCII -> (keyType hashType) , digest
           {
             std::vector<uint8_t> b58 = to_bytes(B);
             uint64_t kt = 0, ht = 0;
             uint8_t dig[128];
             size_t dig_len = 0;
             int rc = ec_peerid_parse(b58.data(), b58.size(),
                                      &kt, &ht, dig, &dig_len);
             if (rc != EC_OK)   return ret_int(rc);
             Value_P Z(ShapeItem(2 + dig_len), LOC);
             Z->next_ravel_Int((int64_t)kt);
             Z->next_ravel_Int((int64_t)ht);
             for (size_t i = 0; i < dig_len; ++i)   Z->next_ravel_Int(dig[i] & 0xFF);
             Z->check_value(LOC);
             return Token(TOK_APL_VALUE1, Z);
           }
        default:
           return ret_int(EC_INVALID_ARGUMENT);
      }
}

// prevent unused warnings for the optional entry points
bool (*ec_close_unused)(Cause, const NativeFunction *) = &close_fun;
