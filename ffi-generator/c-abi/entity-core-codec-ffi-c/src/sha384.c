/*
 * sha384.c — SHA-384 (FIPS 180-4), the SHA-512 compression function run with the
 * SHA-384 initial hash values and truncated to 48 bytes. Constant-time-irrelevant
 * (no secret inputs); correctness is pinned by the agility corpus digest.
 */
#include "sha384.h"
#include <string.h>

static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

/* SHA-512 round constants K[80] (FIPS 180-4 sec.4.2.3). */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/* SHA-384 IV (FIPS 180-4 sec.5.3.4). */
static const uint64_t IV384[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

static void sha512_compress(uint64_t H[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int t = 0; t < 16; t++) {
        w[t] = 0;
        for (int i = 0; i < 8; i++) w[t] = (w[t] << 8) | block[t * 8 + i];
    }
    for (int t = 16; t < 80; t++) {
        uint64_t s0 = rotr64(w[t-15], 1) ^ rotr64(w[t-15], 8) ^ (w[t-15] >> 7);
        uint64_t s1 = rotr64(w[t-2], 19) ^ rotr64(w[t-2], 61) ^ (w[t-2] >> 6);
        w[t] = w[t-16] + s0 + w[t-7] + s1;
    }
    uint64_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (int t = 0; t < 80; t++) {
        uint64_t S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K[t] + w[t];
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

void cc_sha384(const uint8_t *data, size_t len, uint8_t out[EC_SHA384_DIGEST_LEN]) {
    uint64_t H[8];
    memcpy(H, IV384, sizeof(H));

    /* Process all full 128-byte blocks. */
    size_t i = 0;
    for (; i + 128 <= len; i += 128) sha512_compress(H, data + i);

    /* Final block(s): remaining bytes + 0x80 + 16-byte (128-bit) length. */
    uint8_t buf[256];
    size_t rem = len - i;
    memcpy(buf, data + i, rem);
    buf[rem] = 0x80;
    size_t pad_to = (rem < 112) ? 128 : 256; /* room for 0x80 + 16-byte length */
    memset(buf + rem + 1, 0, pad_to - rem - 1);
    /* 128-bit big-endian bit length; we only fill the low 64 bits (len < 2^61). */
    uint64_t bits = (uint64_t)len << 3;
    for (int k = 0; k < 8; k++) buf[pad_to - 1 - k] = (uint8_t)(bits >> (8 * k));
    /* high 64 bits of the length: for len < 2^61 bytes this is the carry only. */
    uint64_t bits_hi = (uint64_t)len >> 61;
    for (int k = 0; k < 8; k++) buf[pad_to - 9 - k] = (uint8_t)(bits_hi >> (8 * k));

    sha512_compress(H, buf);
    if (pad_to == 256) sha512_compress(H, buf + 128);

    /* SHA-384 output = first 6 of 8 state words (48 bytes), big-endian. */
    for (int w = 0; w < 6; w++)
        for (int k = 0; k < 8; k++)
            out[w * 8 + k] = (uint8_t)(H[w] >> (56 - 8 * k));
}
