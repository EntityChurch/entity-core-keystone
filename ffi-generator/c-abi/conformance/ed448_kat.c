/* RFC 8032 §7.4 Ed448 known-answer test for entity-core-codec-ffi-c.
 *
 * Independent ground truth (not a cross-impl comparison): drives the C impl's
 * ec_ed448_{seed_to_pubkey,sign,verify} against the canonical "-----  Blank"
 * Ed448 vector and asserts byte-exact pubkey + signature. If the vendored
 * curve448 + the SHAKE256-over-keccak1600 wrapper are correct, these match.
 *
 * Build (links the self-contained static archive):
 *   gcc -I ../entity-core-codec-ffi-c/include ed448_kat.c \
 *       ../entity-core-codec-ffi-c/build/libentitycore_codec.a -o /tmp/kat
 */
#include "entitycore_codec.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int hex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* RFC 8032 §7.4, first vector (empty message). */
static const char *SK =
  "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3"
  "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
static const char *PK =
  "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
  "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
static const char *SIG =
  "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
  "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a"
  "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db"
  "b61149f05a7363268c71d95808ff2e652600";

int main(void) {
    uint8_t sk[57], pk_want[57], sig_want[114];
    uint8_t pk_got[57], sig_got[114];
    uint8_t msg[1] = {0};  /* non-null, length 0 */
    int fails = 0;

    if (hex(SK, sk, 57) || hex(PK, pk_want, 57) || hex(SIG, sig_want, 114)) {
        printf("bad test data\n");
        return 2;
    }

    /* 1. seed -> pubkey */
    if (ec_ed448_seed_to_pubkey(sk, pk_got) != EC_OK ||
        memcmp(pk_got, pk_want, 57) != 0) {
        printf("FAIL seed_to_pubkey\n");
        fails++;
    } else {
        printf("PASS seed_to_pubkey (57B byte-exact)\n");
    }

    /* 2. sign (empty message) */
    if (ec_ed448_sign(sk, msg, 0, sig_got) != EC_OK ||
        memcmp(sig_got, sig_want, 114) != 0) {
        printf("FAIL sign\n");
        fails++;
    } else {
        printf("PASS sign (114B byte-exact vs RFC 8032)\n");
    }

    /* 3. verify (good) */
    if (ec_ed448_verify(pk_want, msg, 0, sig_want) != EC_OK) {
        printf("FAIL verify(good)\n");
        fails++;
    } else {
        printf("PASS verify(good)\n");
    }

    /* 4. verify (tampered sig must fail) */
    sig_want[0] ^= 0x01;
    if (ec_ed448_verify(pk_want, msg, 0, sig_want) == EC_OK) {
        printf("FAIL verify(tampered) accepted a bad signature\n");
        fails++;
    } else {
        printf("PASS verify(tampered) rejected\n");
    }

    printf("\n# RFC 8032 Ed448 KAT: %s\n", fails ? "FAIL" : "PASS (4/4)");
    return fails ? 1 : 0;
}
