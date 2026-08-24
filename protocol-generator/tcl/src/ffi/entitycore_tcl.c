/* entity-core-protocol-tcl — crypto FFI shim.
 *
 * A-TCL-005: fedora:43 has no `cffi`, so the crypto binding to libentitycore_codec
 * is this self-contained Tcl C-extension, built with the Tcl stubs API (no external
 * Tcl package). It exposes the §9.1 crypto floor the pure-Tcl codec cannot do:
 *   ::entity::core::crypto::sha256  data            -> 32-byte digest
 *   ::entity::core::crypto::sha384  data            -> 48-byte digest
 *   ::entity::core::crypto::ed25519_sign  seed msg   -> 64-byte signature
 *   ::entity::core::crypto::ed25519_pubkey seed      -> 32-byte public key
 *   ::entity::core::crypto::ed25519_verify pub msg sig -> 0|1
 *   ::entity::core::crypto::impl_info               -> provenance string
 * All CBOR/base58/varint stay in pure Tcl; only these primitives cross the C-ABI.
 */
/* USE_TCL_STUBS is passed via -D on the compile line (see Makefile). */
#include <tcl.h>
#include <string.h>
#include "entitycore_codec.h"

static int need_args(Tcl_Interp *ip, int oc, int want, Tcl_Obj *const ov[], const char *msg) {
    if (oc != want) { Tcl_WrongNumArgs(ip, 1, ov, msg); return 0; }
    return 1;
}

static int Sha256Cmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    if (!need_args(ip, oc, 2, ov, "data")) return TCL_ERROR;
    Tcl_Size len; const unsigned char *data = Tcl_GetByteArrayFromObj(ov[1], &len);
    unsigned char out[32];
    if (ec_sha256(data, (size_t)len, out) != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("ec_sha256 failed", -1)); return TCL_ERROR;
    }
    Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(out, 32));
    return TCL_OK;
}

static int Sha384Cmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    if (!need_args(ip, oc, 2, ov, "data")) return TCL_ERROR;
    Tcl_Size len; const unsigned char *data = Tcl_GetByteArrayFromObj(ov[1], &len);
    unsigned char out[48];
    if (ec_sha384(data, (size_t)len, out) != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("ec_sha384 failed", -1)); return TCL_ERROR;
    }
    Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(out, 48));
    return TCL_OK;
}

static int Ed25519SignCmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    if (!need_args(ip, oc, 3, ov, "seed msg")) return TCL_ERROR;
    Tcl_Size slen, mlen;
    const unsigned char *seed = Tcl_GetByteArrayFromObj(ov[1], &slen);
    const unsigned char *msg  = Tcl_GetByteArrayFromObj(ov[2], &mlen);
    if (slen != 32) { Tcl_SetObjResult(ip, Tcl_NewStringObj("seed must be 32 bytes", -1)); return TCL_ERROR; }
    unsigned char sig[64];
    if (ec_ed25519_sign(seed, msg, (size_t)mlen, sig) != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("ec_ed25519_sign failed", -1)); return TCL_ERROR;
    }
    Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(sig, 64));
    return TCL_OK;
}

static int Ed25519PubkeyCmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    if (!need_args(ip, oc, 2, ov, "seed")) return TCL_ERROR;
    Tcl_Size slen;
    const unsigned char *seed = Tcl_GetByteArrayFromObj(ov[1], &slen);
    if (slen != 32) { Tcl_SetObjResult(ip, Tcl_NewStringObj("seed must be 32 bytes", -1)); return TCL_ERROR; }
    unsigned char pub[32];
    if (ec_ed25519_seed_to_pubkey(seed, pub) != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("ec_ed25519_seed_to_pubkey failed", -1)); return TCL_ERROR;
    }
    Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(pub, 32));
    return TCL_OK;
}

static int Ed25519VerifyCmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    if (!need_args(ip, oc, 4, ov, "pubkey msg sig")) return TCL_ERROR;
    Tcl_Size plen, mlen, glen;
    const unsigned char *pub = Tcl_GetByteArrayFromObj(ov[1], &plen);
    const unsigned char *msg = Tcl_GetByteArrayFromObj(ov[2], &mlen);
    const unsigned char *sig = Tcl_GetByteArrayFromObj(ov[3], &glen);
    if (plen != 32 || glen != 64) { Tcl_SetObjResult(ip, Tcl_NewStringObj("pubkey 32 + sig 64 required", -1)); return TCL_ERROR; }
    int32_t rc = ec_ed25519_verify(pub, msg, (size_t)mlen, sig);
    Tcl_SetObjResult(ip, Tcl_NewIntObj(rc == 0 ? 1 : 0));
    return TCL_OK;
}

static int ImplInfoCmd(ClientData cd, Tcl_Interp *ip, int oc, Tcl_Obj *const ov[]) {
    Tcl_SetObjResult(ip, Tcl_NewStringObj(ec_impl_info(), -1));
    return TCL_OK;
}

int Entitycorecrypto_Init(Tcl_Interp *ip) {
    if (Tcl_InitStubs(ip, "9.0", 0) == NULL) return TCL_ERROR;
    Tcl_CreateNamespace(ip, "::entity::core::crypto", NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::sha256",         Sha256Cmd,        NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::sha384",         Sha384Cmd,        NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::ed25519_sign",   Ed25519SignCmd,   NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::ed25519_pubkey", Ed25519PubkeyCmd, NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::ed25519_verify", Ed25519VerifyCmd, NULL, NULL);
    Tcl_CreateObjCommand(ip, "::entity::core::crypto::impl_info",      ImplInfoCmd,      NULL, NULL);
    Tcl_PkgProvide(ip, "entitycorecrypto", "0.1");
    return TCL_OK;
}
