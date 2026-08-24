/* peers grant-dimension unit test (F-peers remediation, 2026-08-13) — the conformance
 * oracle has ZERO vectors that exercise the `peers` grant dimension (see
 * research/stewardship/HANDOFF-TO-ARCH-2026-08-13-peers-grant-dimension-oracle-gap.md), so
 * this is the only regression guard for it (AGENTS: "conformance-green can be vacuous").
 *
 * Drives derive_handler (extract_peer, §5.2 line 2196) and grant_scope_ok (the §5.2
 * check_permission grant loop, dispatch.s) directly, against hand-encoded canonical-CBOR
 * fixtures — no live peer, no socket. Links dispatch.o + cbor.o only: is_peer_id/
 * derive_handler/grant_scope_ok never call the FFI/host externs dispatch.o also references
 * (ec_content_hash, ec_ed25519_*, write_all, mcpy, strlen), so those + the data symbols
 * (g_peerid/g_pubkey/g_seed/g_opengrants) are stubbed/defined right here rather than
 * pulling in the whole host.s peer-main (which would collide with this file's own main).
 * Run via `make peers-scope-test`.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- link-satisfying stubs/data for dispatch.o's unrelated externs (never invoked by
 * is_peer_id/derive_handler/grant_scope_ok — abort() catches it if that assumption breaks) */
uint8_t g_peerid[128];
uint64_t g_peerid_len;
uint8_t g_pubkey[64];
uint8_t g_seed[64];
uint64_t g_opengrants;

void ec_content_hash(void) { abort(); }
void ec_ed25519_verify(void) { abort(); }
void ec_ed25519_sign(void) { abort(); }
void ec_peerid_format(void) { abort(); }
void ec_peerid_parse(void) { abort(); }
void write_all(void) { abort(); }
void mcpy(void) { abort(); }
void strlen_unused_marker(void) { } /* real strlen() comes from libc via <string.h> below */
/* type_table/type_table_count: typestore.o data, unrelated to the peers-scope path (also
 * pulled in transitively since dispatch.o is linked as one unit). */
uint8_t type_table[8];
uint64_t type_table_count;

/* dispatch.o/cbor.o under test */
extern int32_t is_peer_id(const uint8_t *ptr, uint64_t len);
extern void derive_handler(const uint8_t *exec_map);
extern int32_t grant_scope_ok(const uint8_t *token_data, const uint8_t *target_ptr,
                              uint64_t target_len, const uint8_t *op_ptr, uint64_t op_len);
extern uint8_t *g_handler_ptr;
extern uint64_t g_handler_len;
extern uint8_t *g_target_peer_ptr;
extern uint64_t g_target_peer_len;

static int pass = 0, fail = 0;
#define CHECK(cond, name) do { if (cond) { pass++; printf("PASS %s\n", name); } \
    else { fail++; printf("FAIL %s\n", name); } } while (0)

/* ---- minimal canonical-CBOR encoder (independent of the r15-cursor asm writer — this is
 * plain bytes, so a small standalone encoder is simpler and lower-risk than driving the
 * asm w_* primitives' register-cursor convention from C). ---- */
static uint8_t *w_head(uint8_t *p, int major, uint64_t n) {
    if (n < 24) { *p++ = (uint8_t)((major << 5) | n); return p; }
    if (n < 256) { *p++ = (uint8_t)((major << 5) | 24); *p++ = (uint8_t)n; return p; }
    fprintf(stderr, "w_head: count too large for this test's encoder\n");
    abort();
}
static uint8_t *w_text(uint8_t *p, const char *s) {
    size_t n = strlen(s);
    p = w_head(p, 3, (uint64_t)n);
    memcpy(p, s, n);
    return p + n;
}
static uint8_t *w_map_hdr(uint8_t *p, uint64_t npairs) { return w_head(p, 5, npairs); }
static uint8_t *w_arr_hdr(uint8_t *p, uint64_t n) { return w_head(p, 4, n); }

/* {"uri": <uri>} */
static size_t build_exec_uri_map(uint8_t *buf, const char *uri) {
    uint8_t *p = buf;
    p = w_map_hdr(p, 1);
    p = w_text(p, "uri");
    p = w_text(p, uri);
    return (size_t)(p - buf);
}

/* {"include": [<elem0>...]} — 0 or 1 elements is all this test needs. */
static uint8_t *w_scope_incl1(uint8_t *p, const char *elem) {
    p = w_map_hdr(p, 1);
    p = w_text(p, "include");
    p = w_arr_hdr(p, 1);
    p = w_text(p, elem);
    return p;
}

/* {"grants": [ {"operations":{include:[op]}, "handlers":{include:[handler]},
 *   [peers-block], "resources":{include:["*"]}} ] }
 * peers_elem == NULL  -> grant OMITS the "peers" field entirely (default-scope case).
 * peers_elem != NULL  -> grant carries {"peers":{"include":[peers_elem]}}. */
static size_t build_token_data(uint8_t *buf, const char *op, const char *handler,
                               const char *peers_elem) {
    uint8_t *p = buf;
    int nfields = peers_elem ? 4 : 3;
    p = w_map_hdr(p, 1);
    p = w_text(p, "grants");
    p = w_arr_hdr(p, 1);
    p = w_map_hdr(p, (uint64_t)nfields);
    p = w_text(p, "operations");
    p = w_scope_incl1(p, op);
    p = w_text(p, "handlers");
    p = w_scope_incl1(p, handler);
    if (peers_elem) {
        p = w_text(p, "peers");
        p = w_scope_incl1(p, peers_elem);
    }
    p = w_text(p, "resources");
    p = w_scope_incl1(p, "*");
    return (size_t)(p - buf);
}

/* Two distinct, well-formed (46-char, all-Base58) peer ids. */
#define LOCAL_PEER   "111111111111111111111111111111111111111111AAAA"
#define FOREIGN_PEER "222222222222222222222222222222222222222222BBBB"
/* 45 chars — one short of the §5.4 is_peer_id floor. */
#define SHORT_ID     "11111111111111111111111111111111111111111AAAA"
/* 46 chars but with a non-Base58 byte ('0' is excluded from the Bitcoin alphabet). */
#define BAD_ALPHA_ID "011111111111111111111111111111111111111111AAAA"

int main(void) {
    memcpy(g_peerid, LOCAL_PEER, strlen(LOCAL_PEER));
    g_peerid_len = strlen(LOCAL_PEER);

    printf("-- A: is_peer_id (§5.4) --\n");
    CHECK(is_peer_id((const uint8_t *)LOCAL_PEER, strlen(LOCAL_PEER)) == 1, "ipi.valid46");
    CHECK(is_peer_id((const uint8_t *)SHORT_ID, strlen(SHORT_ID)) == 0, "ipi.tooshort45");
    CHECK(is_peer_id((const uint8_t *)BAD_ALPHA_ID, strlen(BAD_ALPHA_ID)) == 0, "ipi.badalpha");

    printf("-- B: derive_handler / extract_peer (§5.2 line 2196) --\n");
    {
        uint8_t buf[256];
        char uri[256];
        snprintf(uri, sizeof(uri), "entity://%s/system/tree", FOREIGN_PEER);
        size_t n = build_exec_uri_map(buf, uri);
        (void)n;
        derive_handler(buf);
        CHECK(g_target_peer_len == strlen(FOREIGN_PEER) &&
              memcmp(g_target_peer_ptr, FOREIGN_PEER, strlen(FOREIGN_PEER)) == 0,
              "dh.foreign_peer_extracted");
        CHECK(g_handler_len == 11 && memcmp(g_handler_ptr, "system/tree", 11) == 0,
              "dh.handler_after_foreign_peer");
    }
    {
        uint8_t buf[256];
        char uri[256];
        /* local, short-form path (no valid peer-id first segment) -> extract_peer's
         * fallback: target_peer = local_peer_id. */
        snprintf(uri, sizeof(uri), "entity://%s/thing", "short-segment");
        size_t n = build_exec_uri_map(buf, uri);
        (void)n;
        derive_handler(buf);
        CHECK(g_target_peer_len == g_peerid_len &&
              memcmp(g_target_peer_ptr, g_peerid, g_peerid_len) == 0,
              "dh.local_fallback_short_segment");
    }
    {
        /* no uri field at all -> both handler and target_peer default. */
        uint8_t buf[16];
        uint8_t *p = buf;
        p = w_map_hdr(p, 0);
        (void)p;
        derive_handler(buf);
        CHECK(g_target_peer_len == g_peerid_len &&
              memcmp(g_target_peer_ptr, g_peerid, g_peerid_len) == 0,
              "dh.local_fallback_no_uri");
    }

    printf("-- C: grant_scope_ok peers dimension (§5.2 check_permission) --\n");
    {
        uint8_t tbuf[512];
        build_token_data(tbuf, "get", "system/tree", FOREIGN_PEER);

        g_target_peer_ptr = (uint8_t *)FOREIGN_PEER;
        g_target_peer_len = strlen(FOREIGN_PEER);
        g_handler_ptr = (uint8_t *)"system/tree";
        g_handler_len = 11;
        int rc = grant_scope_ok(tbuf, (const uint8_t *)"whatever", 8,
                                (const uint8_t *)"get", 3);
        CHECK(rc == 1, "gso.explicit_peers_include_match_ACCEPT");

        g_target_peer_ptr = (uint8_t *)LOCAL_PEER;
        g_target_peer_len = strlen(LOCAL_PEER);
        rc = grant_scope_ok(tbuf, (const uint8_t *)"whatever", 8,
                            (const uint8_t *)"get", 3);
        CHECK(rc == 0, "gso.explicit_peers_include_mismatch_REJECT");
    }
    {
        /* grant OMITS "peers" entirely -> defaults to {include:[local_peer_id]} (§5.2
         * line 2378/1040). This is the headline bug: pre-fix, the dimension was never
         * read at all, so a foreign target_peer was silently ALLOWed here. */
        uint8_t tbuf[512];
        build_token_data(tbuf, "get", "system/tree", NULL);

        g_target_peer_ptr = (uint8_t *)LOCAL_PEER;
        g_target_peer_len = strlen(LOCAL_PEER);
        int rc = grant_scope_ok(tbuf, (const uint8_t *)"whatever", 8,
                                (const uint8_t *)"get", 3);
        CHECK(rc == 1, "gso.default_peers_local_target_ACCEPT");

        g_target_peer_ptr = (uint8_t *)FOREIGN_PEER;
        g_target_peer_len = strlen(FOREIGN_PEER);
        rc = grant_scope_ok(tbuf, (const uint8_t *)"whatever", 8,
                            (const uint8_t *)"get", 3);
        CHECK(rc == 0, "gso.default_peers_foreign_target_REJECT");
    }

    printf("-- %d pass, %d fail --\n", pass, fail);
    return fail ? 1 : 0;
}
