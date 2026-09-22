/* Do the two INTERCHANGEABLE C-ABI impls agree on their FAILURE SET?
   abi_differential drives 101 probes of VALID input and is silent about this.
   `type` is attacker-controlled wire bytes on the §6.3 put path: a submitted
   entity's `type` is a CBOR major-3 head, and nothing in CBOR enforces that a
   text string's bytes are actually UTF-8.                                    */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

typedef int (*ch_fn)(const unsigned char *, unsigned long,
                     const unsigned char *, unsigned long, unsigned char *);
struct C { const char *name; const unsigned char *ty; unsigned long tl; };

int main(int argc, char **argv) {
    void *hc = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *hr = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!hc || !hr) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    ch_fn c = (ch_fn)dlsym(hc, "ec_content_hash");
    ch_fn r = (ch_fn)dlsym(hr, "ec_content_hash");
    if (!c || !r) { fprintf(stderr, "dlsym failed\n"); return 2; }
    if ((void *)c == (void *)r) {
        fprintf(stderr, "FATAL: identical address -- comparing a lib to itself\n");
        return 2;
    }
    const unsigned char data[] = { 0x40 };   /* empty byte string */
    struct C cases[] = {
        {"ascii 'primitive/bytes'",   (const unsigned char *)"primitive/bytes", 15},
        {"empty type",                (const unsigned char *)"", 0},
        {"invalid UTF-8  ff fe",      (const unsigned char *)"\xff\xfe", 2},
        {"lone continuation  80",     (const unsigned char *)"\x80", 1},
        {"truncated 2-byte  c3",      (const unsigned char *)"\xc3", 1},
        {"overlong  c0 80",           (const unsigned char *)"\xc0\x80", 2},
        {"UTF-16 surrogate ed a0 80", (const unsigned char *)"\xed\xa0\x80", 3},
        {"embedded NUL  'a\\0b'",     (const unsigned char *)"a\x00" "b", 3},
    };
    int diverge = 0, n = (int)(sizeof cases / sizeof *cases);
    printf("%-28s %5s %5s   %s\n", "type bytes", "C", "Rust", "verdict");
    for (int i = 0; i < n; i++) {
        unsigned char oc[33], orr[33];
        memset(oc, 0xCC, 33); memset(orr, 0xDD, 33);
        int rc1 = c(cases[i].ty, cases[i].tl, data, 1, oc);
        int rc2 = r(cases[i].ty, cases[i].tl, data, 1, orr);
        const char *v;
        if (rc1 != rc2)                          { v = "RC DIVERGE";     diverge++; }
        else if (rc1 == 0 && memcmp(oc, orr, 33)) { v = "DIGEST DIVERGE"; diverge++; }
        else if (rc1 == 0)                        v = "agree (hashed)";
        else                                      v = "agree (both refuse)";
        printf("%-28s %5d %5d   %s\n", cases[i].name, rc1, rc2, v);
    }
    printf("\n%d of %d inputs diverge\n", diverge, n);
    return 0;
}
