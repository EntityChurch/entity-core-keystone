/* Minimal file reader for the COBOL codec self-test harness (test-only — the
 * peer itself does no file I/O for the protocol; it speaks TCP). Reads a whole
 * binary file (the pinned conformance-vectors fixture) into a caller buffer.
 * Returns 0 on success, -1 on open failure; writes the byte count to *out_len. */
#include <stdio.h>

int ec_read_file(const char *path, unsigned char *buf, long cap, long *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long n = (long)fread(buf, 1, (size_t)cap, f);
    fclose(f);
    if (out_len) *out_len = n;
    return 0;
}
