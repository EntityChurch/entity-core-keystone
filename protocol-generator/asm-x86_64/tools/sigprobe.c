/* sigprobe.c — throwaway: determine what bytes an entity-signature signs.
 * Reads a captured authenticate REQUEST frame body (raw CBOR, no 4-byte header) from
 * argv[1], locates the client public_key, the PoP signature entity's target (the
 * signed entity's content_hash) and signature, then tests ec_ed25519_verify against
 * candidate messages: the 33-byte content_hash, the 32-byte digest.
 * Build: cc -O0 -o sigprobe sigprobe.c -L<codec> -lentitycore_codec
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int32_t ec_ed25519_verify(const uint8_t *pub, const uint8_t *msg, size_t mlen,
                                 const uint8_t *sig);

static const uint8_t *find(const uint8_t *h, size_t hn, const char *needle, size_t nn) {
    for (size_t i = 0; i + nn <= hn; i++)
        if (!memcmp(h + i, needle, nn)) return h + i + nn;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <frame-body-file>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    static uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
    fprintf(stderr, "read %zu bytes\n", n);

    /* public_key: "public_key"(0x6a 70..) then 58 20 <32> */
    const uint8_t *pk = find(buf, n, "\x6apublic_key\x58\x20", 13);
    /* target: "target"(0x66 74..) then 58 21 00 <32> */
    const uint8_t *tg = find(buf, n, "\x66target\x58\x21\x00", 10);
    /* signature: "signature"(0x69 73..) then 58 40 <64> */
    const uint8_t *sg = find(buf, n, "\x69signature\x58\x40", 12);
    if (!pk || !tg || !sg) { fprintf(stderr, "markers: pk=%p tg=%p sg=%p\n",(void*)pk,(void*)tg,(void*)sg); return 3; }

    uint8_t ch33[33]; ch33[0] = 0x00; memcpy(ch33 + 1, tg, 32);

    int a = ec_ed25519_verify(pk, ch33, 33, sg);          /* 33-byte content_hash */
    int b = ec_ed25519_verify(pk, tg, 32, sg);            /* 32-byte digest only  */
    printf("verify(33-byte content_hash) = %d %s\n", a, a==0?"<== SIGNED MESSAGE":"");
    printf("verify(32-byte digest)       = %d %s\n", b, b==0?"<== SIGNED MESSAGE":"");
    return 0;
}
