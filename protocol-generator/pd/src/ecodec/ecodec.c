/*
 * ecodec — the entity-core codec/crypto seam for the Pure Data peer (#33).
 *
 * A Pd C external (m_pd.h) that is the THINNEST possible bridge to the
 * language-agnostic C-ABI codec (libentitycore_codec / ffi-generator/c-abi).
 * It owns exactly what the reactive-patch substrate genuinely cannot do —
 * bytes / maps / canonical CBOR / crypto / peer-id — and NOTHING of the
 * §6.5/§6.6 dispatch logic, which is authored on the canvas (the FLOW-DESIGN
 * wrapper-guard). Values Pd atoms can't hold (byte buffers, keys, u64 ints)
 * ride as opaque handles; readable fields come back as plain float/symbol atoms.
 *
 * SURFACE (grows as the canvas dispatch spine needs each field):
 *   S2 smoke        info / sha256test — prove the C-ABI link.
 *   §1.6 framing    buf_reset / buf_append / buf_read_len / buf_body_{len,out}
 *                   (byte store + 4-byte-BE length the float atoms can't hold).
 *   §3.1 decode     decode_frame / exec_field — minimal CBOR reader unwraps the
 *                   envelope → root_type + request_id/uri/operation as atoms.
 *   §3.3 encode     build_response / emit_response_frame — canonical-CBOR writer
 *                   builds a content-hashed EXECUTE_RESPONSE frame.
 *   §6.6 dispatch   walk_nsegs / walk_prefix / tree_get — string slicing + a
 *                   placeholder handler tree (the WALK is on the canvas).
 *   §4.1 handshake  peer_id / build_hello — Ed25519 identity + hello response.
 * NEXT (authenticate leg, §4.6): byte-field + included-map decode, signature
 * verify (ec_ed25519_verify), and the §4.4 capability-grant construction.
 * (Sequenced in an internal build handoff, 2026-07-14 — not published; the
 * authored canvas and this file are the record that matters here.)
 * The wrapper-guard holds: this owns bytes/CBOR/crypto/store; the §6.5/§6.6
 * dispatch logic is authored on the canvas.
 */

#include "m_pd.h"
#include "s_stuff.h"          /* sys_addpollfn / sys_rmpollfn / sys_closesocket */
#include "entitycore_codec.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static t_class *ecodec_class;

typedef struct _ecodec {
    t_object  x_obj;
    t_outlet *x_out;
} t_ecodec;

/* ── §1.6 frame receive buffer ────────────────────────────────────────────
 * The byte store the reactive-patch canvas genuinely cannot hold (Pd atoms are
 * 32-bit floats — no byte buffer, no exact u32 length, A-PD-003). This external
 * owns ONLY the bytes + the one length-decode Pd can't do; the §1.6 framing
 * STATE MACHINE (header→body phase, byte counting, emit) is authored on the
 * canvas (frame-assembler.pd). Single global assembler for now — per-socket
 * demux is A-PD-002 (multi-connection §6.11), grown when the oracle needs it.
 */
#define ECODEC_MAX_FRAME (16 * 1024 * 1024)   /* §4.10 default TCP frame cap */

static unsigned char *g_rbuf     = NULL;      /* CURRENT-frame scratch (one frame at a
                                               * time; the decode/authz path reads it) */
static size_t         g_rbuf_len = 0;
static size_t         g_rbuf_cap = 0;

/* ── §6.11 multi-connection transport (A-PD-002 resolution) ───────────────────
 * Stock Pd [netreceive] cannot serve a conformant multi-connection peer: its
 * `send` BROADCASTS to every open socket (x_net.c netreceive_send loops all
 * x_nconnections) and binary mode carries no per-connection source id. Sockets are
 * an explicitly-legitimate FFI seam (bytes/maps/sockets/crypto/store), so the peer
 * owns its TCP transport HERE — one listening socket + a per-connection receive
 * buffer + frame assembler + issued-nonce, admission-capped and reply-targeted to
 * the originating fd. The §6.5/§5.2/§6.6 DISPATCH logic stays on the canvas: a
 * completed frame is copied into g_rbuf and the existing decode→route→ladder cascade
 * is kicked synchronously, so per-request transient state (g_dec/g_auth/g_authz)
 * remains a safe single-owner global (one frame fully dispatched before the next).
 * Only the receive buffer and the issued nonce are per-connection — they span
 * multiple socket-read events / multiple frames on one connection. */
#define EC_MAX_CONN 128               /* §4.10(c) admission bound: self-limit well below a
                                       * 256-connection flood so the excess is refused */

typedef struct ec_conn {
    int            fd;
    unsigned char *rbuf;              /* per-connection receive accumulation */
    size_t         rlen, rcap;
    int            have_len;          /* §1.6 phase: 0 = reading 4-byte len, 1 = body */
    uint32_t       framelen;          /* decoded body length once have_len */
    unsigned char  nonce[32];         /* §4.6 nonce issued in THIS conn's hello */
    int            nonce_set;
    int            authenticated;     /* RT-6 (§4.6): a valid authenticate has already been
                                       * accepted on THIS conn — a second one is a nonce replay */
    char           hello_peer[128];   /* §4.6 step 3 / §4.7 row 8: the peer_id THIS conn greeted
                                       * as. Recorded only on the ACCEPT path of build_hello — a
                                       * refused hello must leave no state on the connection. */
    double         accept_ms;         /* accept time (for idle-flood reaping) */
    int            got_data;          /* has this conn ever sent a byte? */
} ec_conn;

static double ec_now_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Wall-clock ms since epoch. MS PRECISION IS LOAD-BEARING for mint timestamps:
 * a token is {grants, grantee, granter, created_at} — with a second-truncated
 * created_at, two mints of the same scope in the same second are CONTENT-HASH
 * IDENTICAL, so revoking one revokes the other (the oracle's revoke probe then
 * kills the session floor cap and every later category 403s). */
static uint64_t wall_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ── Run modes (cohort convention, both OFF by default) ────────────────────────
 * EC_OPEN_GRANTS=1  — the degenerate [default → *] §4.4 seed grant (the cohort's
 *                     `--debug-open-grants`): grant-gated conformance categories
 *                     need write authority the SHOULD-floor grant never gives.
 * EC_VALIDATE=1     — the §7a `system/validate/*` conformance handlers incl. the
 *                     §6.13(b) dispatch-outbound reentry seam (the cohort's
 *                     `--validate`). Env vars because a Pd patch has no argv. */
static int ec_flag(const char *name)
{
    const char *e = getenv(name);
    return e && *e && strcmp(e, "0") != 0;
}
static int open_grants_on(void) { static int v = -1; if (v < 0) v = ec_flag("EC_OPEN_GRANTS"); return v; }
static int validate_on(void)    { static int v = -1; if (v < 0) v = ec_flag("EC_VALIDATE");    return v; }

static ec_conn *g_conns[EC_MAX_CONN];
static int      g_nconn      = 0;
static int      g_listen_fd  = -1;
static int      g_listen_paused = 0;  /* stopped accepting at cap → OS backlog then refuses */
static int      g_cur_fd     = -1;    /* fd of the frame currently dispatching (reply target) */
static ec_conn *g_cur_conn   = NULL;  /* its connection (per-conn nonce access) */
static t_ecodec *g_self      = NULL;  /* the single [ecodec] instance (outlet from poll cbs) */
static t_clock  *g_reap_clock = NULL; /* periodic idle-connection reaper (§4.10(c) flood) */
#define EC_IDLE_REAP_MS 2000.0        /* reap a connection open this long with NO data */

/* Send a framed reply in full to one connection. Sockets are non-blocking, so handle
 * short writes; MSG_NOSIGNAL keeps a peer that closed early from raising SIGPIPE. A
 * client that stops draining is dropped after a bounded spin rather than stalling the
 * single-threaded scheduler (a §1.6 oversize/slow peer must not wedge the others). */
static void conn_send_all(int fd, const unsigned char *b, size_t n)
{
    size_t off = 0; long spins = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; spins = 0; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (++spins > 1000000L) break;   /* peer not draining — drop, don't wedge */
            continue;
        }
        break;                               /* EPIPE / peer gone */
    }
}

static int rbuf_append(unsigned char b)
{
    if (g_rbuf_len >= g_rbuf_cap) {
        size_t ncap = g_rbuf_cap ? g_rbuf_cap * 2 : 256;
        if (ncap > (size_t)ECODEC_MAX_FRAME + 4) ncap = (size_t)ECODEC_MAX_FRAME + 4;
        if (g_rbuf_len >= ncap) return -1;    /* at the cap already */
        unsigned char *nb = (unsigned char *)realloc(g_rbuf, ncap);
        if (!nb) return -1;
        g_rbuf = nb; g_rbuf_cap = ncap;
    }
    g_rbuf[g_rbuf_len++] = b;
    return 0;
}

/* [info( -> provenance string from the linked C-ABI impl (proves the bridge). */
static void ecodec_info(t_ecodec *x)
{
    const char *info = ec_impl_info();
    outlet_symbol(x->x_out, gensym(info ? info : "ec_impl_info=NULL"));
}

/* [sha256test( -> first byte of SHA-256("abc"); known answer 0xba (186). */
static void ecodec_sha256test(t_ecodec *x)
{
    const unsigned char msg[3] = { 'a', 'b', 'c' };
    unsigned char digest[EC_SHA256_LEN];
    int32_t rc = ec_sha256(msg, sizeof(msg), digest);
    if (rc != EC_OK) {
        pd_error(x, "ecodec: ec_sha256 failed (rc=%d)", (int)rc);
        outlet_float(x->x_out, (t_float)rc);
        return;
    }
    outlet_float(x->x_out, (t_float)digest[0]);   /* 186 == 0xba on success */
}

/* ── §1.6 frame primitives (canvas holds the state machine; we hold bytes) ── */

/* [buf_reset( — clear the receive buffer (start of a new phase/frame). */
static void ecodec_buf_reset(t_ecodec *x)
{
    (void)x;
    g_rbuf_len = 0;
}

/* [buf_append <byte>( — append one wire byte (0..255) from [netreceive -b]. */
static void ecodec_buf_append(t_ecodec *x, t_floatarg f)
{
    int b = (int)f;
    if (b < 0 || b > 255) {
        pd_error(x, "ecodec: buf_append byte out of range (%d)", b);
        return;
    }
    if (rbuf_append((unsigned char)b) != 0)
        pd_error(x, "ecodec: frame buffer overflow (>%d bytes, §4.10 cap)", ECODEC_MAX_FRAME);
}

/* [buf_read_len( — decode the 4-byte big-endian §1.6 length prefix from the
 * buffer head. Outputs [framelen <n>( when 0 <= n <= 16MiB (n fits a float
 * exactly, <= 2^24), [frameerr short( if <4 bytes buffered, or
 * [frameerr toobig( if the prefix exceeds the §4.10 cap (peer MUST close). */
static void ecodec_buf_read_len(t_ecodec *x)
{
    t_atom a;
    if (g_rbuf_len < 4) {
        SETSYMBOL(&a, gensym("short"));
        outlet_anything(x->x_out, gensym("frameerr"), 1, &a);
        return;
    }
    uint32_t n = ((uint32_t)g_rbuf[0] << 24) | ((uint32_t)g_rbuf[1] << 16)
               | ((uint32_t)g_rbuf[2] <<  8) | ((uint32_t)g_rbuf[3]);
    if (n > (uint32_t)ECODEC_MAX_FRAME) {
        SETSYMBOL(&a, gensym("toobig"));
        outlet_anything(x->x_out, gensym("frameerr"), 1, &a);
        return;
    }
    SETFLOAT(&a, (t_float)n);                 /* n <= 2^24 -> exact in t_float */
    outlet_anything(x->x_out, gensym("framelen"), 1, &a);
}

/* [buf_body_len( — output the current buffered byte count as [bodylen <n>(. */
static void ecodec_buf_body_len(t_ecodec *x)
{
    t_atom a;
    SETFLOAT(&a, (t_float)g_rbuf_len);
    outlet_anything(x->x_out, gensym("bodylen"), 1, &a);
}

/* [buf_body_out( — emit the buffered body as a Pd list of byte-floats. Wired to
 * [netreceive]'s inlet this echoes the frame back on the same socket (the S3.2
 * framing round-trip proof). Grows into decode_frame in the next step. */
static void ecodec_buf_body_out(t_ecodec *x)
{
    if (g_rbuf_len == 0) {
        outlet_list(x->x_out, &s_list, 0, NULL);
        return;
    }
    t_atom *av = (t_atom *)getbytes(sizeof(t_atom) * g_rbuf_len);
    if (!av) { pd_error(x, "ecodec: buf_body_out alloc failed"); return; }
    for (size_t i = 0; i < g_rbuf_len; i++)
        SETFLOAT(&av[i], (t_float)g_rbuf[i]);
    outlet_list(x->x_out, &s_list, (int)g_rbuf_len, av);
    freebytes(av, sizeof(t_atom) * g_rbuf_len);
}

/* ── Minimal CBOR reader (§1.3 ECF: definite lengths only; tags rejected) ────
 * Just enough to navigate a decoded envelope: map/array/text/bytes/int/float
 * head decode + whole-value skip + by-key map lookup. NOT a validator — the
 * §1.8 hash check + §3.2 full tag scan stay in libentitycore_codec's
 * ec_decode_entity, called on the guard-ladder path later. This reader unwraps
 * the envelope structure to surface the dispatch fields as canvas atoms. */
typedef struct { const unsigned char *p; size_t len; size_t pos; } cbor_rd;

/* read initial byte + argument (length/value). 0 ok, -1 malformed. */
static int cbor_head(cbor_rd *r, int *major, uint64_t *arg)
{
    if (r->pos >= r->len) return -1;
    unsigned char ib = r->p[r->pos++];
    *major = ib >> 5;
    int ai = ib & 0x1f;
    if (ai < 24) { *arg = (uint64_t)ai; return 0; }
    if (ai == 24) { if (r->pos + 1 > r->len) return -1; *arg = r->p[r->pos++]; return 0; }
    if (ai == 25) { if (r->pos + 2 > r->len) return -1;
        *arg = ((uint64_t)r->p[r->pos] << 8) | r->p[r->pos + 1]; r->pos += 2; return 0; }
    if (ai == 26) { if (r->pos + 4 > r->len) return -1;
        *arg = ((uint64_t)r->p[r->pos] << 24) | ((uint64_t)r->p[r->pos + 1] << 16)
             | ((uint64_t)r->p[r->pos + 2] << 8) | r->p[r->pos + 3]; r->pos += 4; return 0; }
    if (ai == 27) {
        if (r->pos + 8 > r->len) return -1;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | r->p[r->pos + i];
        r->pos += 8; *arg = v; return 0;
    }
    return -1;  /* ai 28..31 (incl. indefinite) — reject: §1.3 definite lengths only */
}

/* skip one complete data item. rejects major-type-6 tags (§3.2). 0 ok, -1 err. */
static int cbor_skip(cbor_rd *r)
{
    int major; uint64_t arg;
    if (cbor_head(r, &major, &arg) != 0) return -1;
    switch (major) {
        case 0: case 1: case 7: return 0;                 /* int / simple / float: head only */
        case 2: case 3:                                    /* bytes / text */
            if (r->pos + arg > r->len) return -1;
            r->pos += (size_t)arg; return 0;
        case 4:                                            /* array: arg items */
            for (uint64_t i = 0; i < arg; i++) if (cbor_skip(r) != 0) return -1;
            return 0;
        case 5:                                            /* map: arg key/value pairs */
            for (uint64_t i = 0; i < arg; i++) { if (cbor_skip(r) != 0) return -1;
                                                 if (cbor_skip(r) != 0) return -1; }
            return 0;
        default: return -1;                                /* 6 = tag: reject */
    }
}

/* Given a reader at a map head, find text-key `key`; on hit leave `out` at the
 * value and return 1; else return 0 (out consumed). */
static int cbor_map_find(const unsigned char *buf, size_t len, size_t map_pos,
                         const char *key, cbor_rd *out)
{
    cbor_rd r = { buf, len, map_pos };
    int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 5) return 0;   /* not a map */
    size_t klen = strlen(key);
    for (uint64_t i = 0; i < n; i++) {
        int kmaj; uint64_t kl;
        size_t khead = r.pos;
        if (cbor_head(&r, &kmaj, &kl) != 0 || kmaj != 3) { r.pos = khead; if (cbor_skip(&r) != 0) return 0; if (cbor_skip(&r) != 0) return 0; continue; }
        if (r.pos + kl > len) return 0;
        int match = (kl == klen && memcmp(r.p + r.pos, key, klen) == 0);
        r.pos += (size_t)kl;                          /* now at value */
        if (match) { out->p = buf; out->len = len; out->pos = r.pos; return 1; }
        if (cbor_skip(&r) != 0) return 0;             /* skip value, next pair */
    }
    return 0;
}

/* Copy a text-string value at reader `r` into out[cap] (NUL-terminated). 0 ok. */
static int cbor_get_text(cbor_rd *r, char *out, size_t cap)
{
    int major; uint64_t arg;
    cbor_rd t = *r;
    if (cbor_head(&t, &major, &arg) != 0 || major != 3) return -1;
    if (t.pos + arg > t.len) return -1;
    if (arg >= cap) return -1;                        /* too long for our fixed field */
    memcpy(out, t.p + t.pos, (size_t)arg);
    out[arg] = '\0';
    return 0;
}

/* Copy a byte-string value at reader `r` into out[cap]; *outlen = length. 0 ok. */
static int cbor_get_bytes(cbor_rd *r, unsigned char *out, size_t cap, size_t *outlen)
{
    int major; uint64_t arg;
    cbor_rd t = *r;
    if (cbor_head(&t, &major, &arg) != 0 || major != 2) return -1;   /* major 2 = bstr */
    if (t.pos + arg > t.len) return -1;
    if (arg > cap) return -1;                          /* too long for our buffer */
    memcpy(out, t.p + t.pos, (size_t)arg);
    *outlen = (size_t)arg;
    return 0;
}

/* Return ptr+len of the COMPLETE encoded item at `pos` (for re-hashing a sub-map
 * from its verbatim wire bytes — §4.6 authenticate-entity hash). 0 ok, -1 err. */
static int cbor_value_slice(const unsigned char *buf, size_t len, size_t pos,
                            const unsigned char **out_ptr, size_t *out_len)
{
    cbor_rd r = { buf, len, pos };
    size_t start = r.pos;
    if (cbor_skip(&r) != 0) return -1;
    *out_ptr = buf + start;
    *out_len = r.pos - start;
    return 0;
}

/* §3.1 RESOLUTION INTEGRITY: does the entity at `entpos` actually hash to the key
 * it is filed under? Recomputes content_hash({type, data}) from the entity's own
 * verbatim wire bytes and compares. 1 = binds, 0 = does not (or cannot be checked).
 *
 * THE KEY IS WIRE-SUPPLIED AND THE VALUE IS WIRE-SUPPLIED, so without this the map
 * is an attacker-chosen address book. §3.1 states the invariant — "keyed by
 * content hash" — and 0.8.2.23 §5.2a makes it a per-site obligation: an attacker
 * who knows a victim's identity hash files their OWN system/peer under it and is
 * attributed the victim's authority, with a genuine signature over a genuine
 * public key. Measured on the wire 2026-09-14: this peer answered 200.
 *
 * Fails CLOSED on anything it cannot verify (no type, no data, over-long type):
 * an entry that cannot be checked is not a resolution. */
static int ec_entity_hash(const char *type, const unsigned char *data, size_t dlen,
                          unsigned char out33[33]);   /* defined with the writers below */
static int included_key_binds(const unsigned char *buf, size_t len,
                              size_t entpos, const unsigned char key33[33])
{
    cbor_rd tf, df; char type[128];
    const unsigned char *dptr; size_t dlen;
    unsigned char recomputed[33];
    if (!cbor_map_find(buf, len, entpos, "type", &tf)) return 0;
    if (cbor_get_text(&tf, type, sizeof type) != 0) return 0;
    if (!cbor_map_find(buf, len, entpos, "data", &df)) return 0;
    if (cbor_value_slice(buf, len, df.pos, &dptr, &dlen) != 0) return 0;
    if (ec_entity_hash(type, dptr, dlen, recomputed) != 0) return 0;
    return memcmp(recomputed, key33, 33) == 0;
}

/* Find an entity in envelope.included by its 33-byte content_hash (bstr) key. On
 * hit, leave `out` at the entity map value and return 1; else 0. included keys are
 * byte strings (§3.1), so cbor_map_find (text keys) can't do this.
 *
 * The bind is HERE, at the single read site every caller goes through, rather than
 * as a separate envelope-wide rung. That is mechanism (b) of §1.8 — discard the
 * key, resolve by validated content_hash — so a forged address does not produce a
 * new refusal class: the lookup simply MISSES, and each caller's existing rung
 * answers the §5.2a row that lookup already owns (author absent -> 401
 * authentication_failed; capability absent -> 403 capability_denied). 0.8.2.23
 * ruled explicitly that a uniform verdict MUST NOT be required, which is what
 * makes the cheap fix the conformant one. */
static int included_find(const unsigned char *buf, size_t len,
                         const unsigned char key33[33], cbor_rd *out)
{
    cbor_rd inc;
    if (!cbor_map_find(buf, len, 0, "included", &inc)) return 0;
    cbor_rd r = { buf, len, inc.pos };
    int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 5) return 0;
    for (uint64_t i = 0; i < n; i++) {
        size_t khead = r.pos;
        int kmaj; uint64_t kl;
        if (cbor_head(&r, &kmaj, &kl) != 0) return 0;
        if (kmaj == 2 && kl == 33 && r.pos + 33 <= len && memcmp(r.p + r.pos, key33, 33) == 0) {
            if (!included_key_binds(buf, len, r.pos + 33, key33)) return 0;   /* §3.1 */
            out->p = buf; out->len = len; out->pos = r.pos + 33; return 1;   /* value */
        }
        r.pos = khead;
        if (cbor_skip(&r) != 0 || cbor_skip(&r) != 0) return 0;              /* skip key+value */
    }
    return 0;
}

/* Copy a bstr field `name` from the data map of the entity at reader `ent`
 * (entity = {type,data,content_hash}). 0 ok. */
static int entity_data_bytes(const unsigned char *buf, size_t len, const cbor_rd *ent,
                             const char *name, unsigned char *out, size_t cap, size_t *olen)
{
    cbor_rd d, f;
    if (!cbor_map_find(buf, len, ent->pos, "data", &d)) return -1;
    if (!cbor_map_find(buf, len, d.pos, name, &f)) return -1;
    return cbor_get_bytes(&f, out, cap, olen);
}

/* True iff the entity at reader `ent` has top-level type == `want`. */
static int entity_type_is(const unsigned char *buf, size_t len, const cbor_rd *ent, const char *want)
{
    cbor_rd tf; char t[80];
    if (!cbor_map_find(buf, len, ent->pos, "type", &tf)) return 0;
    if (cbor_get_text(&tf, t, sizeof t) != 0) return 0;
    return strcmp(t, want) == 0;
}

/* Read an unsigned-int field `name` from the data map of entity at `ent` into
 * *out. Returns 1 if present (and unsigned), 0 if absent, -1 on type error. */
static int entity_data_uint(const unsigned char *buf, size_t len, const cbor_rd *ent,
                            const char *name, uint64_t *out)
{
    cbor_rd d, f; int major; uint64_t arg;
    if (!cbor_map_find(buf, len, ent->pos, "data", &d)) return 0;
    if (!cbor_map_find(buf, len, d.pos, name, &f)) return 0;   /* absent → 0 */
    if (cbor_head(&f, &major, &arg) != 0 || major != 0) return -1;
    *out = arg; return 1;
}

/* ── decoded-frame scratch (single global; per-socket demux is A-PD-002) ──── */
typedef struct {
    int  valid;
    char env_type[64];
    char root_type[64];
    char request_id[128];
    char uri[512];
    char operation[64];
} ec_decoded_t;
static ec_decoded_t g_dec;

/* [decode_frame( — parse the §3.1 envelope in the frame buffer into the
 * dispatch fields. Outputs [decoded <root_type>( on success (canvas branches on
 * execute vs execute/response), or [decerr <reason>(. Fields then read via
 * [exec_field <name>(. Leans on the minimal reader; NOT hash-validated (that is
 * a later guard-ladder step via ec_decode_entity). */
static void ecodec_decode_frame(t_ecodec *x)
{
    t_atom a;
    memset(&g_dec, 0, sizeof(g_dec));
    const unsigned char *buf = g_rbuf;
    size_t len = g_rbuf_len;

    /* The WIRE envelope (§1.1/§3.1) is the bare {root, included} data map — NOT
     * an entity triple. Its own type/content_hash are elided on the wire (§3.1
     * transport optimization: the envelope's content_hash is NOT REQUIRED during
     * transport). So `root` is a TOP-LEVEL key, read directly at map_pos 0.
     * (Envelope type is implicit — always system/protocol/envelope on the wire —
     * so g_dec.env_type stays empty; it is informational only.) */
    cbor_rd root;
    if (!cbor_map_find(buf, len, 0, "root", &root)) {
        SETSYMBOL(&a, gensym("no_root")); outlet_anything(x->x_out, gensym("decerr"), 1, &a); return;
    }
    cbor_rd rtype;
    if (!cbor_map_find(buf, len, root.pos, "type", &rtype) || cbor_get_text(&rtype, g_dec.root_type, sizeof(g_dec.root_type)) != 0) {
        SETSYMBOL(&a, gensym("no_root_type")); outlet_anything(x->x_out, gensym("decerr"), 1, &a); return;
    }
    /* root.data — EXECUTE (or EXECUTE_RESPONSE) fields */
    cbor_rd rdata;
    if (cbor_map_find(buf, len, root.pos, "data", &rdata)) {
        cbor_rd f;
        if (cbor_map_find(buf, len, rdata.pos, "request_id", &f)) cbor_get_text(&f, g_dec.request_id, sizeof(g_dec.request_id));
        if (cbor_map_find(buf, len, rdata.pos, "uri", &f))        cbor_get_text(&f, g_dec.uri, sizeof(g_dec.uri));
        if (cbor_map_find(buf, len, rdata.pos, "operation", &f))  cbor_get_text(&f, g_dec.operation, sizeof(g_dec.operation));
    }
    g_dec.valid = 1;
    SETSYMBOL(&a, gensym(g_dec.root_type));
    outlet_anything(x->x_out, gensym("decoded"), 1, &a);
}

/* [exec_field <name>( — output a decoded field as [<name> <value>(. Names:
 * request_id / uri / operation / root_type / env_type. Empty/missing → "". */
static void ecodec_exec_field(t_ecodec *x, t_symbol *s)
{
    const char *name = s->s_name;
    const char *val = NULL;
    if      (!strcmp(name, "request_id")) val = g_dec.request_id;
    else if (!strcmp(name, "uri"))        val = g_dec.uri;
    else if (!strcmp(name, "operation"))  val = g_dec.operation;
    else if (!strcmp(name, "root_type"))  val = g_dec.root_type;
    else if (!strcmp(name, "env_type"))   val = g_dec.env_type;
    else { pd_error(x, "ecodec: exec_field unknown field '%s'", name); return; }
    t_atom a;
    SETSYMBOL(&a, gensym((val && val[0]) ? val : "(none)"));
    outlet_anything(x->x_out, gensym(name), 1, &a);
}

/* ── Minimal canonical-CBOR writer (§1.3 ECF) — the response build direction ──
 * Emits minimal-int heads + definite lengths; callers place map keys in the
 * canonical (length-then-lex) order themselves (no runtime sort needed for the
 * fixed known response shapes). content_hash is computed from ECF({type,data})
 * via ec_sha256 (§1.2) — no reliance on the C-ABI's data-encoding internals. */
typedef struct { unsigned char *p; size_t len, cap; } wbuf;

static int wb_ensure(wbuf *w, size_t extra)
{
    if (w->p && w->len + extra <= w->cap) return 0;
    size_t nc = w->cap ? w->cap : 64;
    while (nc < w->len + extra) nc *= 2;
    unsigned char *np = (unsigned char *)realloc(w->p, nc);
    if (!np) return -1;
    w->p = np; w->cap = nc; return 0;
}
static int wb_byte(wbuf *w, unsigned char b) { if (wb_ensure(w, 1)) return -1; w->p[w->len++] = b; return 0; }
static int wb_raw(wbuf *w, const unsigned char *d, size_t n)
{ if (wb_ensure(w, n)) return -1; memcpy(w->p + w->len, d, n); w->len += n; return 0; }
static int wb_head(wbuf *w, int major, uint64_t n)
{
    int m = major << 5;
    if (n < 24)             return wb_byte(w, (unsigned char)(m | n));
    if (n < 256)            return wb_byte(w, (unsigned char)(m | 24)) || wb_byte(w, (unsigned char)n);
    if (n < 65536)          return wb_byte(w, (unsigned char)(m | 25)) || wb_byte(w, (unsigned char)(n >> 8)) || wb_byte(w, (unsigned char)(n & 255));
    if (n < 0x100000000ULL) return wb_byte(w, (unsigned char)(m | 26)) || wb_byte(w, (unsigned char)(n >> 24)) || wb_byte(w, (unsigned char)(n >> 16)) || wb_byte(w, (unsigned char)(n >> 8)) || wb_byte(w, (unsigned char)(n & 255));
    if (wb_byte(w, (unsigned char)(m | 27))) return -1;
    for (int i = 7; i >= 0; i--) if (wb_byte(w, (unsigned char)((n >> (i * 8)) & 255))) return -1;
    return 0;
}
static int wb_text(wbuf *w, const char *s) { size_t n = strlen(s); return wb_head(w, 3, n) || wb_raw(w, (const unsigned char *)s, n); }
static int wb_bytes(wbuf *w, const unsigned char *b, size_t n) { return wb_head(w, 2, n) || wb_raw(w, b, n); }

/* 33-byte content_hash of {type, data_cbor}: 0x00 || SHA-256(ECF{data,type}). */
static int ec_entity_hash(const char *type, const unsigned char *data, size_t dlen, unsigned char out33[33])
{
    wbuf ecf = {0};
    int bad = wb_head(&ecf, 5, 2) || wb_text(&ecf, "data") || wb_raw(&ecf, data, dlen)
            || wb_text(&ecf, "type") || wb_text(&ecf, type);
    if (bad) { free(ecf.p); return -1; }
    unsigned char digest[EC_SHA256_LEN];
    int32_t rc = ec_sha256(ecf.p, ecf.len, digest);
    free(ecf.p);
    if (rc != EC_OK) return -1;
    out33[0] = 0x00; memcpy(out33 + 1, digest, 32);
    return 0;
}
/* materialize {data, type, content_hash} (canonical key order) into w. */
static int wb_entity(wbuf *w, const char *type, const unsigned char *data, size_t dlen, const unsigned char h33[33])
{
    return wb_head(w, 5, 3) || wb_text(w, "data") || wb_raw(w, data, dlen)
        || wb_text(w, "type") || wb_text(w, type)
        || wb_text(w, "content_hash") || wb_bytes(w, h33, 33);
}

/* [build_response <status> <code>( — build a §3.3 EXECUTE_RESPONSE envelope frame
 * (root = execute/response{status, result = system/protocol/error{code}}),
 * echoing the last-decoded request_id, and emit it as a length-prefixed Pd
 * byte-list (wire to [netreceive] to reply). Every embedded entity carries a
 * correct §1.2 content_hash so the receiver's §1.8 fidelity check passes. The
 * §6.5 verdict (status + code) is the canvas's decision; this assembles it. */
/* Assemble + emit an EXECUTE_RESPONSE envelope frame: root = execute/response
 * {result, status, request_id(echoed)} where result is an entity of the given
 * result_type wrapping result_data (canonical CBOR of the result's data map).
 * Every embedded entity carries a correct §1.2 content_hash. Emits the framed
 * bytes as a Pd list (wire to [netreceive] to reply). Shared by all responders. */
/* Core: build an EXECUTE_RESPONSE frame with an explicit `included` map (the
 * verbatim CBOR of the map value, INCLUDING its map head — e.g. "\xa0" for empty
 * or a 3-entry map for the §4.4 grant). The thin emit_response_frame wrapper below
 * passes the empty map (error/hello responses carry no included entities). */
static void emit_response_frame_inc(t_ecodec *x, unsigned status,
                                    const char *result_type,
                                    const unsigned char *result_data, size_t rdlen,
                                    const unsigned char *inc, size_t inc_len)
{
    const char *rid = g_dec.request_id[0] ? g_dec.request_id : "";
    wbuf resent = {0}, respd = {0}, respent = {0}, envd = {0}, frame = {0};
    unsigned char resh[33], resph[33];
    int bad = 1;

    if (ec_entity_hash(result_type, result_data, rdlen, resh)) goto done;
    if (wb_entity(&resent, result_type, result_data, rdlen, resh)) goto done;

    /* root = execute/response {result, status, request_id} (canonical order) */
    if (wb_head(&respd, 5, 3)
        || wb_text(&respd, "result")     || wb_raw(&respd, resent.p, resent.len)
        || wb_text(&respd, "status")     || wb_head(&respd, 0, status)
        || wb_text(&respd, "request_id") || wb_text(&respd, rid)) goto done;
    if (ec_entity_hash("system/protocol/execute/response", respd.p, respd.len, resph)) goto done;
    if (wb_entity(&respent, "system/protocol/execute/response", respd.p, respd.len, resph)) goto done;

    /* WIRE envelope (§1.1/§3.1): the bare {root, included} data map, framed
     * DIRECTLY — no entity-triple wrapper. The envelope's own type/content_hash
     * are elided on the wire (§3.1 transport optimization); the reference peer
     * sends exactly this shape. Framing the {root, included} map is the envelope. */
    if (wb_head(&envd, 5, 2)
        || wb_text(&envd, "root")     || wb_raw(&envd, respent.p, respent.len)
        || wb_text(&envd, "included") || wb_raw(&envd, inc, inc_len)) goto done;
    {
        uint32_t n = (uint32_t)envd.len;                 /* §1.6 length prefix */
        if (wb_byte(&frame, (n >> 24) & 255) || wb_byte(&frame, (n >> 16) & 255)
            || wb_byte(&frame, (n >> 8) & 255) || wb_byte(&frame, n & 255)
            || wb_raw(&frame, envd.p, envd.len)) goto done;
    }
    bad = 0;
done:
    free(resent.p); free(respd.p); free(respent.p); free(envd.p);
    if (bad) { pd_error(x, "ecodec: response build failed"); free(frame.p); return; }

    /* Transport-owned socket (g_cur_fd set by dispatch_frame): send the framed reply
     * to the ORIGINATING connection only — no broadcast, the whole point of A-PD-002.
     * Legacy [netreceive] test patches (g_cur_fd < 0): emit the byte list to wire back
     * through [netreceive]'s inlet as before. */
    if (g_cur_fd >= 0) {
        conn_send_all(g_cur_fd, frame.p, frame.len);
        free(frame.p);
        return;
    }
    t_atom *av = (t_atom *)getbytes(sizeof(t_atom) * frame.len);
    if (!av) { pd_error(x, "ecodec: response alloc"); free(frame.p); return; }
    for (size_t i = 0; i < frame.len; i++) SETFLOAT(&av[i], (t_float)frame.p[i]);
    outlet_list(x->x_out, &s_list, (int)frame.len, av);
    freebytes(av, sizeof(t_atom) * frame.len);
    free(frame.p);
}

/* Emit an EXECUTE_RESPONSE with an EMPTY included map (error + hello responses). */
static void emit_response_frame(t_ecodec *x, unsigned status, const char *result_type,
                                const unsigned char *result_data, size_t rdlen)
{
    static const unsigned char empty_map = 0xa0;      /* CBOR map(0) */
    emit_response_frame_inc(x, status, result_type, result_data, rdlen, &empty_map, 1);
}

/* Emit a §3.3 error EXECUTE_RESPONSE (result = system/protocol/error{code}). */
static void emit_error_response(t_ecodec *x, unsigned status, const char *code)
{
    const char *cstr = (code && code[0]) ? code : "error";
    wbuf errd = {0};
    if (wb_head(&errd, 5, 1) || wb_text(&errd, "code") || wb_text(&errd, cstr)) {
        pd_error(x, "ecodec: build_response failed"); free(errd.p); return;
    }
    emit_response_frame(x, status, "system/protocol/error", errd.p, errd.len);
    free(errd.p);
}

/* [build_response <status> <code>( — §3.3 error response (result = error{code}). */
static void ecodec_build_response(t_ecodec *x, t_floatarg statusf, t_symbol *code)
{
    emit_error_response(x, (unsigned)statusf, (code && code->s_name[0]) ? code->s_name : "error");
}

/* ── §1.5/§7.4 peer identity (Ed25519). Ephemeral per process for now — the
 * persistent --name keypair convention is deferred (A-PD-008). peer_id =
 * base58(0x01 0x00 || pubkey) via the C-ABI. ─────────────────────────────── */
static unsigned char g_priv[EC_ED25519_PRIV_LEN];
static unsigned char g_pub[EC_ED25519_PUB_LEN];
static char g_peer_id[128];
static int  g_identity_ready = 0;

/* Nonce issued in this connection's hello response (§4.6 step-1 nonce-echo).
 * SINGLE global — correct for the single-connection oracle handshake; per-
 * connection state (multi-socket) is A-PD-002/(c). Set by build_hello. */
static unsigned char g_issued_nonce[32];
static int           g_issued_nonce_set = 0;
/* RT-6 (§4.6): mirrors ec_conn.authenticated for the single-global legacy
 * ([netreceive] test patch) path, same per-connection/global split as the nonce. */
static int           g_authenticated = 0;
/* §4.7 row 8: mirrors ec_conn.hello_peer on the same legacy path. */
static char          g_hello_peer[128] = "";

/* Minimal base64 decode (standard alphabet, '=' padding). Returns bytes or -1. */
static int b64_decode(const char *in, unsigned char *out, size_t outcap)
{
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned v = 0; int bits = 0; size_t n = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r' || *p == ' ') continue;
        const char *q = strchr(A, *p);
        if (!q) return -1;
        v = (v << 6) | (unsigned)(q - A); bits += 6;
        if (bits >= 8) { bits -= 8; if (n >= outcap) return -1; out[n++] = (unsigned char)(v >> bits); }
    }
    return (int)n;
}

/* EC_NAME: load the persistent Ed25519 seed from the standard on-disk keypair
 * (~/.entity/peers/NAME/keypair — a PEM whose body is base64(32-byte seed); the
 * Go entity-peer --name / peer-manager convention, A-PD-008). The priv half of
 * the C-ABI keypair IS the seed; the pubkey derives via seed_to_pubkey. */
static int load_named_seed(void)
{
    const char *name = getenv("EC_NAME");
    if (!name || !*name) return 0;
    const char *home = getenv("HOME"); if (!home || !*home) home = "/root";
    char path[512];
    int m = snprintf(path, sizeof path, "%s/.entity/peers/%s/keypair", home, name);
    if (m < 0 || (size_t)m >= sizeof path) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char buf[4096]; size_t len = fread(buf, 1, sizeof buf - 1, f); fclose(f);
    buf[len] = '\0';
    char b64[4096]; size_t bl = 0;
    for (char *line = strtok(buf, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        if (strncmp(line, "-----", 5) == 0) continue;
        for (char *p = line; *p && bl < sizeof b64 - 1; p++)
            if (*p != ' ' && *p != '\t') b64[bl++] = *p;
    }
    b64[bl] = '\0';
    unsigned char seed[64];
    if (b64_decode(b64, seed, sizeof seed) != 32) return 0;
    memcpy(g_priv, seed, 32);
    if (ec_ed25519_seed_to_pubkey(g_priv, g_pub) != EC_OK) return 0;
    return 1;
}

static void ec_init_identity(void)
{
    if (g_identity_ready) return;
    if (!load_named_seed()
        && ec_ed25519_keygen(g_priv, g_pub) != EC_OK) { g_peer_id[0] = '\0'; return; }
    size_t out_len = 0;
    if (ec_peerid_format(1 /*Ed25519*/, 0 /*identity-multihash*/, g_pub, EC_ED25519_PUB_LEN,
                         (uint8_t *)g_peer_id, sizeof(g_peer_id) - 1, &out_len) == EC_OK
        && out_len < sizeof(g_peer_id)) {
        g_peer_id[out_len] = '\0';
        g_identity_ready = 1;
    } else {
        g_peer_id[0] = '\0';
    }
}

/* [peer_id( — output this peer's base58 peer_id as [peer_id <id>(. */
static void ecodec_peer_id(t_ecodec *x)
{
    ec_init_identity();
    t_atom a; SETSYMBOL(&a, gensym(g_peer_id[0] ? g_peer_id : "(no-identity)"));
    outlet_anything(x->x_out, gensym("peer_id"), 1, &a);
}

/* [build_hello( — §4.4 hello EXECUTE_RESPONSE: status 200, result =
 * system/protocol/connect/hello {nonce, peer_id, protocols, timestamp}. */
/* Exact string membership in a CBOR text array. */
static int array_has_str(const unsigned char *buf, size_t len, size_t arr_pos, const char *value)
{
    cbor_rd r = { buf, len, arr_pos }; int mj; uint64_t n;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        char e[128]; cbor_rd ev = { buf, len, r.pos };
        if (cbor_get_text(&ev, e, sizeof e) != 0) return 0;
        if (!strcmp(e, value)) return 1;
        if (cbor_skip(&r) != 0) return 0;
    }
    return 0;
}

/* §4.5 hello negotiation: is `value` compatible with the initiator's advertised
 * `field` set (hash_formats / key_types) in the incoming hello EXECUTE? An ABSENT
 * field defaults to the spec singleton (["ecfv1-sha256"] / ["ed25519"]) which equals
 * our advertised value, so absent → compatible. Present → membership decides. Used to
 * reject a disjoint hello (empty intersection) with the §4.7 coded status. */
static int hello_set_ok(const unsigned char *buf, size_t len, const char *field, const char *value)
{
    cbor_rd root, rdata, params, pdata, arr;
    if (!cbor_map_find(buf, len, 0, "root", &root)) return 1;
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) return 1;
    if (!cbor_map_find(buf, len, rdata.pos, "params", &params)) return 1;
    if (!cbor_map_find(buf, len, params.pos, "data", &pdata)) return 1;
    if (!cbor_map_find(buf, len, pdata.pos, field, &arr)) return 1;   /* absent → default set */
    return array_has_str(buf, len, arr.pos, value);
}

/* Element count of a hello params array field. -1 = the field is ABSENT (or the
 * frame has no hello params at all), 0 = present and empty, n>0 = present with n
 * entries. hello_set_ok above deliberately conflates absent with compatible — an
 * absent hash_formats/key_types takes the §4.5 default set — and `protocols` is the
 * one negotiated field with NO default, so it needs a predicate that can tell the
 * two apart. */
static int hello_array_len(const unsigned char *buf, size_t len, const char *field)
{
    cbor_rd root, rdata, params, pdata, arr;
    if (!cbor_map_find(buf, len, 0, "root", &root)) return -1;
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) return -1;
    if (!cbor_map_find(buf, len, rdata.pos, "params", &params)) return -1;
    if (!cbor_map_find(buf, len, params.pos, "data", &pdata)) return -1;
    if (!cbor_map_find(buf, len, pdata.pos, field, &arr)) return -1;   /* absent */
    { cbor_rd r = { buf, len, arr.pos }; int mj; uint64_t n;
      if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return -1;
      return (int)n; }
}

/* The peer_id the initiator greeted as, out of the hello params. Empty string when
 * absent — a hello need not carry one, and §4.7 row 8's second input only bites when
 * BOTH legs name a peer_id and they differ. */
static void hello_peer_id(const unsigned char *buf, size_t len, char *out, size_t cap)
{
    cbor_rd root, rdata, params, pdata, f;
    out[0] = '\0';
    if (!cbor_map_find(buf, len, 0, "root", &root)) return;
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) return;
    if (!cbor_map_find(buf, len, rdata.pos, "params", &params)) return;
    if (!cbor_map_find(buf, len, params.pos, "data", &pdata)) return;
    if (!cbor_map_find(buf, len, pdata.pos, "peer_id", &f)) return;
    if (cbor_get_text(&f, out, cap) != 0) out[0] = '\0';
}

static void ecodec_build_hello(t_ecodec *x)
{
    ec_init_identity();
    /* §4.5 negotiation at the hello step (the canonical earliest reject point, §4.5
     * v7.66 closeout): reject a disjoint hash_formats (no overlap with our SHA-256
     * home format) with 400 incompatible_hash_format, and an initiator whose key_types
     * accept-set excludes our own key_type (ed25519 — it must be able to VERIFY us)
     * with 400 unsupported_key_type (§4.7 status table). */
    if (!hello_set_ok(g_rbuf, g_rbuf_len, "hash_formats", "ecfv1-sha256")) {
        emit_error_response(x, 400, "incompatible_hash_format"); return;
    }
    if (!hello_set_ok(g_rbuf, g_rbuf_len, "key_types", "ed25519")) {
        emit_error_response(x, 400, "unsupported_key_type"); return;
    }
    /* §4.4 surface 6 / §4.7 row 3: the greeted identity's OWN key_type, read out of the
     * peer_id multihash (§1.5) rather than out of any text field — an agility probe
     * presents key_type=0xFD in the peer_id while `key_type` still reads "ed25519".
     * pd already gated this at AUTHENTICATE; the hello is the earlier surface and §4.5
     * calls it the canonical reject point.
     *
     * ORDERED BEFORE THE `protocols` LADDER BELOW, AND THAT ORDER IS THE WHOLE POINT
     * (F56): AGILITY-UNKNOWN-1 sends key_type 0xFD **and** protocols ["entity-core/v7"]
     * in ONE hello, so both gates match and whichever runs first names the failure.
     * Measured with the two the other way round: 400 incompatible_protocol, where the
     * §4.7 registry pins unsupported_key_type. */
    {
        char greeted[128];
        hello_peer_id(g_rbuf, g_rbuf_len, greeted, sizeof greeted);
        if (greeted[0]) {
            uint64_t kt = 0, ht = 0; unsigned char dig[256]; size_t dl = 0;
            int parsed = ec_peerid_parse((const uint8_t *)greeted, strlen(greeted),
                                         &kt, &ht, dig, &dl) == EC_OK;
            if (!parsed || kt != 1 /*Ed25519 — this peer's only sign/verify algorithm,
                                    * same floor the authenticate rung enforces */) {
                emit_error_response(x, 400, "unsupported_key_type"); return;
            }
        }
    }
    /* §4.5 `protocols` — the one negotiated field Required with NO default, so it
     * carries TWO distinct §4.7 refusals and they are different rows:
     *   absent or empty  → 400 invalid_request      (a peer that names no version has
     *                                                made no incompatible-VERSION claim;
     *                                                the request is malformed, row 10's
     *                                                argument one row up)
     *   non-empty disjoint → 400 incompatible_protocol   (§4.7 row 1)
     *
     * CHECKED LAST, AND THAT ORDER IS OBSERVABLE (F56): AGILITY-UNKNOWN-1 sends
     * key_type 0xfd AND protocols ["entity-core/v7"] in one hello, so whichever gate
     * runs first names the failure. §4.5 fixes no precedence between them, so the
     * order is stated here rather than left to the order these ifs happen to sit in. */
    {
        int nproto = hello_array_len(g_rbuf, g_rbuf_len, "protocols");
        if (nproto <= 0) { emit_error_response(x, 400, "invalid_request"); return; }
        if (!hello_set_ok(g_rbuf, g_rbuf_len, "protocols", "entity-core/1.0")) {
            emit_error_response(x, 400, "incompatible_protocol"); return;
        }
    }
    /* nonce: 32 bytes of CSPRNG (§4.5 hello `random(32)`, §4.6 "≥32-byte CSPRNG").
     * Sourced from a throwaway libsodium keypair's 32-byte public key (real
     * randomness). EC_ED25519_PUB_LEN == 32 = the required nonce width. */
    unsigned char np[EC_ED25519_PRIV_LEN], nonce[EC_ED25519_PUB_LEN];
    if (ec_ed25519_keygen(np, nonce) != EC_OK) memset(nonce, 0, sizeof(nonce));
    /* retain for §4.6 nonce-echo — PER CONNECTION when transport owns the socket
     * (g_cur_conn set), else the single global (legacy [netreceive] test patches). */
    if (g_cur_conn) { memcpy(g_cur_conn->nonce, nonce, 32); g_cur_conn->nonce_set = 1; }
    else { memcpy(g_issued_nonce, nonce, sizeof(g_issued_nonce)); g_issued_nonce_set = 1; }
    /* §4.7 row 8 second input: remember who we were greeted BY, so a later authenticate
     * naming a different peer_id is caught. Recorded only here, past every refusal above
     * — a rejected hello must leave no state on the connection. */
    if (g_cur_conn) hello_peer_id(g_rbuf, g_rbuf_len, g_cur_conn->hello_peer, sizeof g_cur_conn->hello_peer);
    else hello_peer_id(g_rbuf, g_rbuf_len, g_hello_peer, sizeof g_hello_peer);
    uint64_t ts = wall_ms();

    /* result data — canonical key order (length-then-lex): nonce(5) peer_id(7)
     * key_types(9) protocols(9) timestamp(9) hash_formats(12). §4.5 requires the
     * responder advertise a non-empty hash_formats (incl. our SHA-256 home format)
     * and a key_types accept-set (what we can VERIFY). */
    wbuf rd = {0};
    int bad = wb_head(&rd, 5, 6)
        || wb_text(&rd, "nonce")        || wb_bytes(&rd, nonce, sizeof(nonce))
        || wb_text(&rd, "peer_id")      || wb_text(&rd, g_peer_id)
        || wb_text(&rd, "key_types")    || wb_head(&rd, 4, 1) || wb_text(&rd, "ed25519")
        || wb_text(&rd, "protocols")    || wb_head(&rd, 4, 1) || wb_text(&rd, "entity-core/1.0")
        || wb_text(&rd, "timestamp")    || wb_head(&rd, 0, ts)
        || wb_text(&rd, "hash_formats") || wb_head(&rd, 4, 1) || wb_text(&rd, "ecfv1-sha256");
    if (bad) { pd_error(x, "ecodec: build_hello failed"); free(rd.p); return; }
    emit_response_frame(x, 200, "system/protocol/connect/hello", rd.p, rd.len);
    free(rd.p);
}

/* ── §4.6 authenticate proof-of-possession — SEAM primitives ──────────────────
 * The three MUST checks (nonce-echo, signature, identity-binding) are authored as
 * a VISIBLE canvas guard ladder (FLOW-DESIGN: not a folded verdict); the seam
 * exposes one primitive per rung, each doing only the substrate-hard part (CBOR
 * byte navigation + crypto) and reporting a 0/1 the canvas branches on. State for
 * the in-flight authenticate is stashed by [auth_decode] into g_auth; the three
 * [auth_check_*] rungs read it. Single global — the single-connection handshake
 * (per-connection demux is A-PD-002). */
typedef struct {
    int  valid;
    char peer_id[128];
    char key_type[32];
    unsigned char public_key[64]; size_t public_key_len;
    unsigned char nonce[64];      size_t nonce_len;
    unsigned char auth_hash[33];  /* recomputed content_hash of the authenticate entity */
} ec_auth_t;
static ec_auth_t g_auth;

static void auth_err(t_ecodec *x, const char *reason)
{
    t_atom a; SETSYMBOL(&a, gensym(reason));
    outlet_anything(x->x_out, gensym("auth_err"), 1, &a);
}

/* [auth_check_established( — RT-6 (§4.6) anti-replay: has THIS connection already
 * completed authenticate? A second authenticate must not be re-processed (it would
 * re-verify the same still-cached nonce and re-issue a grant) — the nonce is
 * documented single-use. Rung → [established_ok 0|1( — 0 = already authenticated,
 * canvas rejects with 401 invalid_nonce WITHOUT calling auth_decode; 1 = first
 * authenticate on this conn, canvas proceeds to the normal PoP ladder. */
static void ecodec_auth_check_established(t_ecodec *x)
{
    int already = g_cur_conn ? g_cur_conn->authenticated : g_authenticated;
    t_atom a; SETFLOAT(&a, already ? 0 : 1);
    outlet_anything(x->x_out, gensym("established_ok"), 1, &a);
}

/* [hello_state( — §4.7 rows 8 and 9: which connection state is THIS `hello` arriving
 * in? A PREDICATE, not a decision — the canvas owns the three-way verdict.
 *
 *   0 = fresh        — no hello has been accepted on this conn → build_hello
 *   1 = half-open    — hello accepted, authenticate not yet → 409 connection_sequence_error
 *   2 = established  — the handshake completed            → 409 connection_already_established
 *
 * The two refusals are DIFFERENT rows with different codes and the same status, and
 * §4.7 spells the distinction out: "connection already established" is its own row,
 * while a second hello before authenticate is the out-of-order row — "a connect
 * operation the responder implements, arriving in a state that forbids it". A peer
 * that folds them into one code fails the MUST-emit contract that table exists for.
 *
 * `nonce_set` IS the half-open bit: build_hello writes it only past every §4.5
 * refusal, so a REJECTED hello leaves the connection fresh and the caller may retry
 * with a conformant one. */
static void ecodec_hello_state(t_ecodec *x)
{
    int done = g_cur_conn ? g_cur_conn->nonce_set     : g_issued_nonce_set;
    int est  = g_cur_conn ? g_cur_conn->authenticated : g_authenticated;
    t_atom a; SETFLOAT(&a, est ? 2 : (done ? 1 : 0));
    outlet_anything(x->x_out, gensym("hello_state"), 1, &a);
}

/* [uri_is_connect( — is this EXECUTE addressed to the connect handler? A PREDICATE;
 * the canvas branches on it.
 *
 * It exists for §4.7's LAST row: "an operation name the responder does not implement,
 * in any state" is 400 invalid_request — but ONLY for a connect EXECUTE. The same
 * unknown operation on system/tree is 501 unsupported_operation (§3.3's 501 slot), and
 * on an unregistered path 404 handler_not_found. Without this predicate the canvas
 * cannot tell those three apart, and pd's op-switch sent every non-hello/authenticate
 * operation down the §5.2 authz ladder — where an unknown CONNECT op arrived carrying
 * no author and was refused 401 authentication_failed, naming a remedy (authenticate)
 * that cannot fix an operation name. */
static const char *to_peer_relative(const char *in);   /* defined with the §6.6 walk helpers */
static void ecodec_uri_is_connect(t_ecodec *x)
{
    const char *rel = to_peer_relative(g_dec.uri);
    int ok = (strcmp(rel, "system/protocol/connect") == 0);
    t_atom a; SETFLOAT(&a, ok);
    outlet_anything(x->x_out, gensym("connect_uri"), 1, &a);
}

/* [auth_check_hello_binding( — §4.6 step 3 / §4.7 row 8, SECOND input. The row names
 * two: `peer_id` not derived from `public_key` (that is [auth_check_bind(, above) and
 * a hello/authenticate peer_id MISMATCH — this one. They share a code because they are
 * one failure seen from two sides, and implementing only the first leaves a caller free
 * to greet as one peer and authenticate as another: deriving peer_id from public_key
 * proves the identity is SELF-CONSISTENT and says nothing about whether it is the
 * identity this connection has been negotiating with. Every seed-policy lookup after
 * the handshake then resolves against the wrong peer.
 *
 * Vacuous when the hello named no peer_id (the field is optional there) — the row bites
 * only when both legs name one and they differ. */
static void ecodec_auth_check_hello_binding(t_ecodec *x)
{
    const char *greeted = g_cur_conn ? g_cur_conn->hello_peer : g_hello_peer;
    int ok = !(greeted && greeted[0] && g_auth.valid && g_auth.peer_id[0]
               && strcmp(greeted, g_auth.peer_id) != 0);
    t_atom a; SETFLOAT(&a, ok ? 1 : 0);
    outlet_anything(x->x_out, gensym("hello_bind_ok"), 1, &a);
}

/* [auth_decode( — parse the authenticate EXECUTE in the frame buffer. The
 * authenticate ENTITY is root.data.params {type:"system/protocol/connect/
 * authenticate", data:{peer_id, public_key, key_type, nonce}}. Extract the four
 * fields and recompute the authenticate entity's content_hash from its verbatim
 * params.data bytes (§4.6 hardening — validate-before-trust, don't trust the
 * wire content_hash). Outputs [auth_decoded <peer_id>( or [auth_err <reason>(. */
static void ecodec_auth_decode(t_ecodec *x)
{
    memset(&g_auth, 0, sizeof(g_auth));
    const unsigned char *buf = g_rbuf;
    size_t len = g_rbuf_len;
    cbor_rd root, rdata, params, pdata, f;

    if (!cbor_map_find(buf, len, 0, "root", &root))            { auth_err(x, "no_root");       return; }
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata))    { auth_err(x, "no_root_data");  return; }
    if (!cbor_map_find(buf, len, rdata.pos, "params", &params)){ auth_err(x, "no_params");     return; }
    if (!cbor_map_find(buf, len, params.pos, "data", &pdata))  { auth_err(x, "no_params_data");return; }

    if (!cbor_map_find(buf, len, pdata.pos, "peer_id", &f)
        || cbor_get_text(&f, g_auth.peer_id, sizeof g_auth.peer_id) != 0)   { auth_err(x, "no_peer_id");    return; }
    if (!cbor_map_find(buf, len, pdata.pos, "key_type", &f)
        || cbor_get_text(&f, g_auth.key_type, sizeof g_auth.key_type) != 0) { auth_err(x, "no_key_type");   return; }
    /* §4.6/§4.7: a key_type outside the supported set MUST be rejected with 400
     * unsupported_key_type up front (defense-in-depth fallback to the §4.5 hello
     * reject, §4.5 v7.66 closeout) — before the identity-binding rung, so an unknown
     * key_type surfaces as unsupported_key_type, not identity_mismatch (AGILITY-UNKNOWN-1).
     * The discriminating key_type is encoded in the peer_id multihash (§1.5), not just
     * the text field — an agility probe presents key_type=0xFD in the peer_id while the
     * text field still reads "ed25519" — so parse the peer_id's key_type code. */
    {
        uint64_t pid_kt = 0, pid_ht = 0; unsigned char dig[256]; size_t dlen = 0;
        int parsed = ec_peerid_parse((const uint8_t *)g_auth.peer_id, strlen(g_auth.peer_id),
                                     &pid_kt, &pid_ht, dig, &dlen) == EC_OK;
        /* reject unless the identity is Ed25519 in BOTH the text field AND the peer_id
         * multihash — an unparseable/unknown-key_type peer_id is not our floor identity. */
        if (strcmp(g_auth.key_type, "ed25519") != 0 || !parsed || pid_kt != 1 /*Ed25519*/) {
            emit_error_response(x, 400, "unsupported_key_type"); return;
        }
    }
    if (!cbor_map_find(buf, len, pdata.pos, "public_key", &f)
        || cbor_get_bytes(&f, g_auth.public_key, sizeof g_auth.public_key, &g_auth.public_key_len) != 0) { auth_err(x, "no_public_key"); return; }
    if (!cbor_map_find(buf, len, pdata.pos, "nonce", &f)
        || cbor_get_bytes(&f, g_auth.nonce, sizeof g_auth.nonce, &g_auth.nonce_len) != 0) { auth_err(x, "no_nonce"); return; }

    /* authenticate_hash = content_hash({type, params.data-verbatim}) */
    const unsigned char *dptr; size_t dlen;
    if (cbor_value_slice(buf, len, pdata.pos, &dptr, &dlen) != 0) { auth_err(x, "pdata_slice"); return; }
    if (ec_entity_hash("system/protocol/connect/authenticate", dptr, dlen, g_auth.auth_hash)) { auth_err(x, "hash_fail"); return; }

    g_auth.valid = 1;
    t_atom a; SETSYMBOL(&a, gensym(g_auth.peer_id));
    outlet_anything(x->x_out, gensym("auth_decoded"), 1, &a);
}

/* [auth_check_nonce( — §4.6 step 1: authenticate.nonce == this connection's
 * issued hello nonce. Rung → 401 invalid_nonce on 0. */
static void ecodec_auth_check_nonce(t_ecodec *x)
{
    /* the issued nonce is per-connection when transport owns the socket, else the
     * single global (legacy [netreceive] test patches). */
    const unsigned char *issued = g_cur_conn ? g_cur_conn->nonce : g_issued_nonce;
    int issued_set = g_cur_conn ? g_cur_conn->nonce_set : g_issued_nonce_set;
    int ok = g_auth.valid && issued_set
             && g_auth.nonce_len == 32
             && memcmp(g_auth.nonce, issued, 32) == 0;
    t_atom a; SETFLOAT(&a, ok ? 1 : 0);
    outlet_anything(x->x_out, gensym("nonce_ok"), 1, &a);
}

/* [auth_check_sig( — §4.6 step 2: locate a system/signature in envelope.included
 * whose target == authenticate_hash, and verify its ed25519 signature against
 * authenticate.public_key over the 33-byte hash (format code + digest). Absent OR
 * invalid → 0 (canvas → 401 authentication_failed). */
static void ecodec_auth_check_sig(t_ecodec *x)
{
    int ok = 0;
    if (g_auth.valid) {
        const unsigned char *sigent = NULL; size_t siglen = 0;
        if (ec_envelope_find_signature_for(g_rbuf, g_rbuf_len, g_auth.auth_hash, 33, &sigent, &siglen) == EC_OK
            && sigent) {
            cbor_rd sdata, sf; unsigned char sig[64]; size_t nsig = 0;
            if (cbor_map_find(sigent, siglen, 0, "data", &sdata)
                && cbor_map_find(sigent, siglen, sdata.pos, "signature", &sf)
                && cbor_get_bytes(&sf, sig, sizeof sig, &nsig) == 0 && nsig == 64
                && g_auth.public_key_len == EC_ED25519_PUB_LEN) {
                if (ec_ed25519_verify(g_auth.public_key, g_auth.auth_hash, 33, sig) == EC_OK) ok = 1;
            }
        }
    }
    t_atom a; SETFLOAT(&a, ok ? 1 : 0);
    outlet_anything(x->x_out, gensym("sig_ok"), 1, &a);
}

/* [auth_check_bind( — §4.6 step 3: authenticate.peer_id is the peer-id derived
 * from authenticate.public_key (§7.4 Base58(key_type ‖ hash_type ‖ hash(pubkey))).
 * Mismatch → 0 (canvas → 401 identity_mismatch). ed25519 only for now. */
static void ecodec_auth_check_bind(t_ecodec *x)
{
    int ok = 0;
    if (g_auth.valid && g_auth.public_key_len == EC_ED25519_PUB_LEN
        && strcmp(g_auth.key_type, "ed25519") == 0) {
        char derived[128]; size_t olen = 0;
        if (ec_peerid_format(1 /*Ed25519*/, 0 /*identity-multihash*/,
                             g_auth.public_key, g_auth.public_key_len,
                             (uint8_t *)derived, sizeof derived - 1, &olen) == EC_OK
            && olen < sizeof derived) {
            derived[olen] = '\0';
            if (strcmp(derived, g_auth.peer_id) == 0) ok = 1;
        }
    }
    t_atom a; SETFLOAT(&a, ok ? 1 : 0);
    outlet_anything(x->x_out, gensym("bind_ok"), 1, &a);
}

/* §4.4 SHOULD-floor grants: [ tree:get over type + handler paths, capability:request ].
 * grant-entry canonical key order: handlers, resources, operations; scope = {include}.
 * Under EC_OPEN_GRANTS the single degenerate [default → *] entry is issued instead
 * (the cohort's --debug-open-grants seed — grant-gated categories need write authority). */
static int build_floor_grants(wbuf *g)
{
    int bad = 0;
    if (open_grants_on()) {
        /* resources carries BOTH the granter-local bare star AND the absolute
         * all-peers "/star/star" form (§5.5a: bare star is granter-local, NEVER
         * universal — without the absolute form the seed cannot cover a foreign
         * namespace and the universal_address_space probes have no write authority). */
        bad = bad || wb_head(g, 4, 1);                                /* [entry] */
        bad = bad || wb_head(g, 5, 3);
        bad = bad || wb_text(g, "handlers")   || wb_head(g, 5, 1) || wb_text(g, "include")
                  || wb_head(g, 4, 1) || wb_text(g, "*");
        bad = bad || wb_text(g, "resources")  || wb_head(g, 5, 1) || wb_text(g, "include")
                  || wb_head(g, 4, 2) || wb_text(g, "*") || wb_text(g, "/*/*");
        bad = bad || wb_text(g, "operations") || wb_head(g, 5, 1) || wb_text(g, "include")
                  || wb_head(g, 4, 1) || wb_text(g, "*");
        return bad ? -1 : 0;
    }
    bad = bad || wb_head(g, 4, 2);                                    /* [entry1, entry2] */
    /* entry 1 — read type defs + handler discovery through the tree handler */
    bad = bad || wb_head(g, 5, 3);
    bad = bad || wb_text(g, "handlers")   || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 1) || wb_text(g, "system/tree");
    bad = bad || wb_text(g, "resources")  || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 2) || wb_text(g, "system/type/*") || wb_text(g, "system/handler/*");
    bad = bad || wb_text(g, "operations") || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 1) || wb_text(g, "get");
    /* entry 2 — request capabilities through the capability handler (empty resources) */
    bad = bad || wb_head(g, 5, 3);
    bad = bad || wb_text(g, "handlers")   || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 1) || wb_text(g, "system/capability");
    bad = bad || wb_text(g, "resources")  || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 0);                                    /* include: [] */
    bad = bad || wb_text(g, "operations") || wb_head(g, 5, 1) || wb_text(g, "include")
              || wb_head(g, 4, 1) || wb_text(g, "request");
    return bad ? -1 : 0;
}

/* [build_grant( — §4.4 initial capability grant EXECUTE_RESPONSE (status 200,
 * result = system/capability/grant {token: <hash>}). Mints the SHOULD-floor token
 * (granter = this peer, grantee = the authenticated peer), signs it with the peer
 * key, and bundles token + granter peer + signature in envelope.included (keyed by
 * content_hash, canonically sorted). Requires a prior [auth_decode] (reads g_auth). */
static void ecodec_build_grant(t_ecodec *x)
{
    ec_init_identity();
    if (!g_auth.valid) { pd_error(x, "ecodec: build_grant without a decoded authenticate"); return; }

    wbuf gpd = {0}, grants = {0}, tokd = {0}, sigd = {0}, resd = {0};
    wbuf tok_ent = {0}, gp_ent = {0}, sig_ent = {0}, inc = {0};
    unsigned char granter_h[33], grantee_h[33], token_h[33], sig_h[33], sig[64];
    int bad = 1;

    /* granter peer {key_type, public_key} = this peer -> granter_h */
    if (wb_head(&gpd, 5, 2) || wb_text(&gpd, "key_type") || wb_text(&gpd, "ed25519")
        || wb_text(&gpd, "public_key") || wb_bytes(&gpd, g_pub, EC_ED25519_PUB_LEN)) goto done;
    if (ec_entity_hash("system/peer", gpd.p, gpd.len, granter_h)) goto done;

    /* grantee peer {key_type, public_key} = authenticated peer -> grantee_h. The
     * grantee entity resolves locally at A, so §4.4 includes only granter+token+sig. */
    {
        wbuf ged = {0};
        int b2 = wb_head(&ged, 5, 2) || wb_text(&ged, "key_type") || wb_text(&ged, g_auth.key_type)
              || wb_text(&ged, "public_key") || wb_bytes(&ged, g_auth.public_key, g_auth.public_key_len)
              || ec_entity_hash("system/peer", ged.p, ged.len, grantee_h);
        free(ged.p);
        if (b2) goto done;
    }

    /* token {grants, grantee, granter, created_at} -> token_h */
    if (build_floor_grants(&grants)) goto done;
    uint64_t now = wall_ms();
    if (wb_head(&tokd, 5, 4)
        || wb_text(&tokd, "grants")     || wb_raw(&tokd, grants.p, grants.len)
        || wb_text(&tokd, "grantee")    || wb_bytes(&tokd, grantee_h, 33)
        || wb_text(&tokd, "granter")    || wb_bytes(&tokd, granter_h, 33)
        || wb_text(&tokd, "created_at") || wb_head(&tokd, 0, now)) goto done;
    if (ec_entity_hash("system/capability/token", tokd.p, tokd.len, token_h)) goto done;

    /* sign token_h; signature {signer, target, algorithm, signature} -> sig_h */
    if (ec_ed25519_sign(g_priv, token_h, 33, sig) != EC_OK) goto done;
    if (wb_head(&sigd, 5, 4)
        || wb_text(&sigd, "signer")    || wb_bytes(&sigd, granter_h, 33)
        || wb_text(&sigd, "target")    || wb_bytes(&sigd, token_h, 33)
        || wb_text(&sigd, "algorithm") || wb_text(&sigd, "ed25519")
        || wb_text(&sigd, "signature") || wb_bytes(&sigd, sig, 64)) goto done;
    if (ec_entity_hash("system/signature", sigd.p, sigd.len, sig_h)) goto done;

    /* materialize the three included entities */
    if (wb_entity(&tok_ent, "system/capability/token", tokd.p, tokd.len, token_h)) goto done;
    if (wb_entity(&gp_ent,  "system/peer",             gpd.p,  gpd.len,  granter_h)) goto done;
    if (wb_entity(&sig_ent, "system/signature",        sigd.p, sigd.len, sig_h)) goto done;

    /* included {hash -> entity} x3, keys canonically sorted (all 33B -> byte-lex) */
    {
        const unsigned char *hs[3] = { token_h, granter_h, sig_h };
        const wbuf *es[3] = { &tok_ent, &gp_ent, &sig_ent };
        for (int i = 0; i < 3; i++) for (int j = i + 1; j < 3; j++)
            if (memcmp(hs[i], hs[j], 33) > 0) {
                const unsigned char *th = hs[i]; hs[i] = hs[j]; hs[j] = th;
                const wbuf *te = es[i]; es[i] = es[j]; es[j] = te;
            }
        if (wb_head(&inc, 5, 3)) goto done;
        for (int i = 0; i < 3; i++)
            if (wb_bytes(&inc, hs[i], 33) || wb_raw(&inc, es[i]->p, es[i]->len)) goto done;
    }

    /* grant result {token: token_h} */
    if (wb_head(&resd, 5, 1) || wb_text(&resd, "token") || wb_bytes(&resd, token_h, 33)) goto done;
    bad = 0;
done:
    if (!bad) {
        /* RT-6 (§4.6): mark this connection established BEFORE emitting the grant, so a
         * pipelined replay arriving right after can never race past auth_check_established. */
        if (g_cur_conn) g_cur_conn->authenticated = 1; else g_authenticated = 1;
        emit_response_frame_inc(x, 200, "system/capability/grant", resd.p, resd.len, inc.p, inc.len);
    } else
        pd_error(x, "ecodec: build_grant failed");
    free(gpd.p); free(grants.p); free(tokd.p); free(sigd.p); free(resd.p);
    free(tok_ent.p); free(gp_ent.p); free(sig_ent.p); free(inc.p);
}

/* ── §5.2 verify_request — authenticated-EXECUTE authorization SEAM (steps 1-4) ─
 * Post-establishment, every EXECUTE off the connect path is authenticated + carries
 * author + capability. verify_request runs BEFORE handler resolution: (1) content-
 * hash integrity, (2) request signature (author-signed), (3) capability integrity
 * (grantee == author + single-link chain signature), (4) revocation. Authored as a
 * VISIBLE canvas guard ladder; the seam does the crypto/CBOR per rung, reporting a
 * 0/1. supports_revocation = false (no persistent-cap extension) — step 4 is a
 * conformant skip (§5.1). check_permission (step 5, scope matching) is separate,
 * after §6.6 handler resolution — next increment. */
typedef struct {
    int  valid;
    unsigned char author_h[33];   /* execute.data.author  — caller peer hash */
    unsigned char cap_h[33];      /* execute.data.capability — token hash */
    unsigned char exec_h[33];     /* recomputed content_hash(execute) */
    char operation[64];
} ec_authz_t;
static ec_authz_t g_authz;

static void authz_err(t_ecodec *x, const char *reason)
{
    t_atom a; SETSYMBOL(&a, gensym(reason));
    outlet_anything(x->x_out, gensym("authz_err"), 1, &a);
}
static void authz_bit(t_ecodec *x, const char *sel, int ok)
{
    t_atom a; SETFLOAT(&a, ok ? 1 : 0);
    outlet_anything(x->x_out, gensym(sel), 1, &a);
}

/* [authz_decode( — parse an authenticated EXECUTE: extract author, capability,
 * operation from root.data, and recompute content_hash(execute) from the verbatim
 * root.data bytes (§5.2 step 1 input). Outputs [authz_decoded( or [authz_err(. */
static void ecodec_authz_decode(t_ecodec *x)
{
    memset(&g_authz, 0, sizeof(g_authz));
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd root, rdata, f; size_t n;

    if (!cbor_map_find(buf, len, 0, "root", &root))         { authz_err(x, "no_root");       return; }
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) { authz_err(x, "no_root_data");  return; }
    if (!cbor_map_find(buf, len, rdata.pos, "author", &f)
        || cbor_get_bytes(&f, g_authz.author_h, 33, &n) != 0 || n != 33)     { authz_err(x, "no_author");     return; }
    if (!cbor_map_find(buf, len, rdata.pos, "capability", &f)
        || cbor_get_bytes(&f, g_authz.cap_h, 33, &n) != 0 || n != 33)        { authz_err(x, "no_capability"); return; }
    if (!cbor_map_find(buf, len, rdata.pos, "operation", &f)
        || cbor_get_text(&f, g_authz.operation, sizeof g_authz.operation) != 0) { authz_err(x, "no_operation"); return; }

    /* content_hash(execute) = content_hash({type:"system/protocol/execute", data:root.data}) */
    const unsigned char *dptr; size_t dlen;
    if (cbor_value_slice(buf, len, rdata.pos, &dptr, &dlen) != 0) { authz_err(x, "rdata_slice"); return; }
    if (ec_entity_hash("system/protocol/execute", dptr, dlen, g_authz.exec_h)) { authz_err(x, "hash_fail"); return; }

    g_authz.valid = 1;
    t_atom a; SETSYMBOL(&a, gensym(g_authz.operation));
    outlet_anything(x->x_out, gensym("authz_decoded"), 1, &a);
}

/* [authz_check_integrity( — §5.2 step 1 (content-hash integrity ONLY): recomputed
 * content_hash(execute) == wire root.content_hash. A tampered content hash is a
 * structural envelope corruption → AUTHZ_DENY (§5.2 comment) → canvas 403
 * capability_denied. Split from reqsig so the 403 (integrity) and 401 (signature)
 * boundaries map to distinct codes — the §5.2a enumeration puts step-1 at authz
 * (403) and step-2 at auth (401); a folded bit would mask the boundary. */
static void ecodec_authz_check_integrity(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        cbor_rd root, chf; unsigned char wire_ch[33]; size_t n = 0;
        if (cbor_map_find(buf, len, 0, "root", &root)
            && cbor_map_find(buf, len, root.pos, "content_hash", &chf)
            && cbor_get_bytes(&chf, wire_ch, 33, &n) == 0 && n == 33
            && memcmp(wire_ch, g_authz.exec_h, 33) == 0)
            ok = 1;
    }
    authz_bit(x, "integrity_ok", ok);
}

/* [authz_check_reqsig( — §5.2 step 2 (request signature) ONLY: a signature targets
 * the exec hash with signer == author; verify it against the author peer's public
 * key (author peer MUST be present in included). Any failure → 0 → canvas 401
 * authentication_failed (auth-class per §5.2a — the envelope has no verified
 * signer). Assumes step 1 (integrity) already passed. */
static void ecodec_authz_check_reqsig(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        const unsigned char *sigent = NULL; size_t siglen = 0;
        if (ec_envelope_find_signature_for(buf, len, g_authz.exec_h, 33, &sigent, &siglen) == EC_OK && sigent) {
            cbor_rd sd, sf; unsigned char signer[33], sig[64]; size_t ns = 0, nsig = 0;
            cbor_rd authent; unsigned char apk[64]; size_t napk = 0;
            if (cbor_map_find(sigent, siglen, 0, "data", &sd)
                && cbor_map_find(sigent, siglen, sd.pos, "signer", &sf) && cbor_get_bytes(&sf, signer, 33, &ns) == 0 && ns == 33
                && memcmp(signer, g_authz.author_h, 33) == 0                              /* signer == author */
                && cbor_map_find(sigent, siglen, sd.pos, "signature", &sf) && cbor_get_bytes(&sf, sig, 64, &nsig) == 0 && nsig == 64
                && included_find(buf, len, g_authz.author_h, &authent)                    /* author peer present */
                && entity_data_bytes(buf, len, &authent, "public_key", apk, sizeof apk, &napk) == 0 && napk == EC_ED25519_PUB_LEN
                && ec_ed25519_verify(apk, g_authz.exec_h, 33, sig) == EC_OK)
                ok = 1;
        }
    }
    authz_bit(x, "reqsig_ok", ok);
}

/* [authz_check_cap_present( — §5.2 step 3: the presented capability hash resolves
 * to a system/capability/token entity in included. 0 → canvas 403 capability_denied
 * ("Capability absent" / "not in included", §5.2a). Precedes the grantee rungs so
 * a missing cap is 403, not the 401 grantee carve-out. */
static void ecodec_authz_check_cap_present(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        cbor_rd cap;
        if (included_find(buf, len, g_authz.cap_h, &cap)
            && entity_type_is(buf, len, &cap, "system/capability/token"))
            ok = 1;
    }
    authz_bit(x, "cap_ok", ok);
}

/* [authz_check_grantee( — §5.2 step 3a: the presented capability's grantee == the
 * request author (the caller holds this cap). 1 → proceed; 0 → the canvas consults
 * grantee_resolvable to split the verdict: unresolvable grantee → 401
 * unresolvable_grantee (PR-3 carve-out), resolvable-but-mismatched → 403. */
static void ecodec_authz_check_grantee(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        cbor_rd cap; unsigned char grantee[33]; size_t n = 0;
        if (included_find(buf, len, g_authz.cap_h, &cap)
            && entity_data_bytes(buf, len, &cap, "grantee", grantee, 33, &n) == 0 && n == 33
            && memcmp(grantee, g_authz.author_h, 33) == 0)
            ok = 1;
    }
    authz_bit(x, "grantee_ok", ok);
}

/* ── §5.5 verify_capability_chain (multi-link walk) ────────────────────────────
 * Walk the presented cap toward its root via the `parent` hash, enforcing at every
 * link: content-hash integrity (recompute == key → §5.2 F6 substitution), signature
 * (signer == granter, verified against the granter peer's pubkey), per-link temporal
 * validity (§5.5 not_before/expires_at), chain linkage (parent.grantee == child.
 * granter), and the parent's delegation caveats on the child (§5.7 no_delegation /
 * max_delegation_ttl / max_delegation_depth). The root (no parent) MUST be granted by
 * the local peer (§5.5 — a root cap this peer did not issue is forged). */

/* local peer identity hash: content_hash(system/peer {key_type, public_key}). */
static int local_peer_hash(unsigned char out33[33])
{
    ec_init_identity();
    wbuf pd = {0};
    int bad = wb_head(&pd, 5, 2) || wb_text(&pd, "key_type") || wb_text(&pd, "ed25519")
           || wb_text(&pd, "public_key") || wb_bytes(&pd, g_pub, EC_ED25519_PUB_LEN)
           || ec_entity_hash("system/peer", pd.p, pd.len, out33);
    free(pd.p);
    return bad ? -1 : 0;
}

/* recompute content_hash of entity `ent` ({type,data}) and compare to expect33. 0 = match. */
static int cap_content_hash_ok(const unsigned char *buf, size_t len, const cbor_rd *ent, const unsigned char expect33[33])
{
    cbor_rd tf, df; char type[64];
    if (!cbor_map_find(buf, len, ent->pos, "type", &tf)) return -1;
    { cbor_rd r = { buf, len, tf.pos }; if (cbor_get_text(&r, type, sizeof type) != 0) return -1; }
    if (!cbor_map_find(buf, len, ent->pos, "data", &df)) return -1;
    const unsigned char *dptr; size_t dlen;
    if (cbor_value_slice(buf, len, df.pos, &dptr, &dlen) != 0) return -1;
    unsigned char h[33];
    if (ec_entity_hash(type, dptr, dlen, h)) return -1;
    return memcmp(h, expect33, 33) == 0 ? 0 : -1;
}

/* verify a signature targeting cap_h with signer == granter, against granter's pubkey. */
static int cap_sig_ok(const unsigned char *buf, size_t len, const unsigned char cap_h[33], const unsigned char granter[33])
{
    const unsigned char *sigent = NULL; size_t siglen = 0;
    if (ec_envelope_find_signature_for(buf, len, cap_h, 33, &sigent, &siglen) != EC_OK || !sigent) return 0;
    cbor_rd sd, sf; unsigned char signer[33], sig[64]; size_t ns = 0, nsig = 0;
    cbor_rd grent; unsigned char gpk[64]; size_t ngpk = 0;
    return cbor_map_find(sigent, siglen, 0, "data", &sd)
        && cbor_map_find(sigent, siglen, sd.pos, "signer", &sf) && cbor_get_bytes(&sf, signer, 33, &ns) == 0 && ns == 33
        && memcmp(signer, granter, 33) == 0
        && cbor_map_find(sigent, siglen, sd.pos, "signature", &sf) && cbor_get_bytes(&sf, sig, 64, &nsig) == 0 && nsig == 64
        && included_find(buf, len, granter, &grent)
        && entity_data_bytes(buf, len, &grent, "public_key", gpk, sizeof gpk, &ngpk) == 0 && ngpk == EC_ED25519_PUB_LEN
        && ec_ed25519_verify(gpk, cap_h, 33, sig) == EC_OK;
}

/* ── §3.6/§5.5 multi-signature granter (root-only K-of-N caps, M3/M4/M6) ───────
 * `granter` is polymorphic: a 33-byte system/hash (single-sig) or an inline
 * multi-granter {signers, threshold}. The verifier finds K valid signatures
 * from the signer set instead of one from a single granter. */
static int map_uint(const unsigned char *buf, size_t len, size_t map_pos, const char *key, uint64_t *out);

/* Find + verify a system/signature in `included` with data.signer == signer and
 * data.target == cap_h, against the signer's included identity pubkey. Unlike
 * cap_sig_ok (one signature per target), K-of-N needs find-BY-SIGNER: several
 * signatures target the same cap hash. */
static int multisig_signer_ok(const unsigned char *buf, size_t len,
                              const unsigned char cap_h[33], const unsigned char signer[33])
{
    cbor_rd incf;
    if (!cbor_map_find(buf, len, 0, "included", &incf)) return 0;
    cbor_rd r = { buf, len, incf.pos }; int mj; uint64_t n;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 5) return 0;
    for (uint64_t i = 0; i < n; i++) {
        if (cbor_skip(&r) != 0) return 0;                  /* past the 33B key */
        cbor_rd ent = { buf, len, r.pos };
        if (entity_type_is(buf, len, &ent, "system/signature")) {
            cbor_rd d, f;
            unsigned char s33[33], t33[33], sig[64];
            size_t ns = 0, nt = 0, nsg = 0;
            int match = cbor_map_find(buf, len, ent.pos, "data", &d) != 0;
            if (match && cbor_map_find(buf, len, d.pos, "signer", &f)) {
                cbor_rd x = { buf, len, f.pos };
                match = cbor_get_bytes(&x, s33, 33, &ns) == 0 && ns == 33
                     && memcmp(s33, signer, 33) == 0;
            } else match = 0;
            if (match && cbor_map_find(buf, len, d.pos, "target", &f)) {
                cbor_rd x = { buf, len, f.pos };
                match = cbor_get_bytes(&x, t33, 33, &nt) == 0 && nt == 33
                     && memcmp(t33, cap_h, 33) == 0;
            } else match = 0;
            if (match && cbor_map_find(buf, len, d.pos, "signature", &f)) {
                cbor_rd x = { buf, len, f.pos };
                match = cbor_get_bytes(&x, sig, 64, &nsg) == 0 && nsg == 64;
            } else match = 0;
            if (match) {
                cbor_rd ident; unsigned char pk[64]; size_t npk = 0;
                if (included_find(buf, len, signer, &ident)
                    && entity_data_bytes(buf, len, &ident, "public_key", pk, sizeof pk, &npk) == 0
                    && npk == EC_ED25519_PUB_LEN
                    && ec_ed25519_verify(pk, cap_h, 33, sig) == EC_OK)
                    return 1;
            }
        }
        if (cbor_skip(&r) != 0) return 0;                  /* past the value */
    }
    return 0;
}

/* Locate the multi-granter's {signers, threshold} within the cap's granter
 * value (either the inline data map or a typed-entity wrapper's data map).
 * Returns 1 with *signers_pos at the signers array and *threshold set. */
static int multigranter_shape(const unsigned char *buf, size_t len, size_t cap_ent_pos,
                              size_t *signers_pos, uint64_t *threshold)
{
    cbor_rd d, gf, sf;
    if (!cbor_map_find(buf, len, cap_ent_pos, "data", &d)) return 0;
    if (!cbor_map_find(buf, len, d.pos, "granter", &gf)) return 0;
    size_t base = gf.pos;
    { cbor_rd h = { buf, len, gf.pos }; int mj; uint64_t nn;
      if (cbor_head(&h, &mj, &nn) != 0 || mj != 5) return 0; }   /* not a map → not multi */
    if (!cbor_map_find(buf, len, base, "signers", &sf)) {
        cbor_rd inner;
        if (!cbor_map_find(buf, len, base, "data", &inner)) return 0;
        base = inner.pos;
        if (!cbor_map_find(buf, len, base, "signers", &sf)) return 0;
    }
    if (map_uint(buf, len, base, "threshold", threshold) != 1) return 0;
    *signers_pos = sf.pos;
    return 1;
}

/* M3 + M4 + M6 for a multi-sig ROOT cap at `cap` (content hash cap_h): parent
 * MUST be null/absent; N≥2, no duplicate signers, K ∈ [2,N]; ≥K valid
 * signatures from the signer set; the LOCAL peer in the signer set AND signed
 * (the root-trust invariant generalized). Returns 1 ALLOW / 0 DENY. */
static int multisig_root_ok(const unsigned char *buf, size_t len, const cbor_rd *cap,
                            const unsigned char cap_h[33])
{
    unsigned char parent[33]; size_t np = 0;
    if (entity_data_bytes(buf, len, cap, "parent", parent, 33, &np) == 0 && np == 33)
        return 0;                                          /* M3: multi-sig is root-only */
    size_t sp; uint64_t threshold = 0;
    if (!multigranter_shape(buf, len, cap->pos, &sp, &threshold)) return 0;

    unsigned char signers[16][33];
    cbor_rd r = { buf, len, sp }; int mj; uint64_t n;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return 0;
    if (n < 2 || n > 16) return 0;                         /* M3: N≥2 (16 = impl bound) */
    for (uint64_t i = 0; i < n; i++) {
        cbor_rd x = { buf, len, r.pos }; size_t nb = 0;
        if (cbor_get_bytes(&x, signers[i], 33, &nb) != 0 || nb != 33) return 0;
        for (uint64_t j = 0; j < i; j++)
            if (memcmp(signers[i], signers[j], 33) == 0) return 0;   /* M3: no dups */
        if (cbor_skip(&r) != 0) return 0;
    }
    if (threshold < 2 || threshold > n) return 0;          /* M3: K ∈ [2,N] */

    unsigned char lp[33];
    if (local_peer_hash(lp)) return 0;
    int valid = 0, local_signed = 0;
    for (uint64_t i = 0; i < n; i++) {
        if (!multisig_signer_ok(buf, len, cap_h, signers[i])) continue;
        valid++;
        if (memcmp(signers[i], lp, 33) == 0) local_signed = 1;
    }
    return valid >= (int)threshold && local_signed;        /* M4 + M6 */
}

/* §5.5a granter-frame locality, multi-granter aware: single-sig → granter ==
 * local hash; multi-sig → the local peer is in the signer set (M6 has already
 * required its signature by the time perm runs, so the authority is locally
 * rooted and its bare resource patterns canonicalize in OUR frame). */
static int cap_granter_local(const unsigned char *buf, size_t len, const cbor_rd *cap)
{
    unsigned char cg[33], lp[33]; size_t ng = 0;
    if (local_peer_hash(lp)) return 0;
    if (entity_data_bytes(buf, len, cap, "granter", cg, 33, &ng) == 0 && ng == 33)
        return memcmp(cg, lp, 33) == 0;
    size_t sp; uint64_t th = 0;
    if (!multigranter_shape(buf, len, cap->pos, &sp, &th)) return 0;
    cbor_rd r = { buf, len, sp }; int mj; uint64_t n;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        unsigned char s[33]; size_t nb = 0; cbor_rd x = { buf, len, r.pos };
        if (cbor_get_bytes(&x, s, 33, &nb) == 0 && nb == 33 && memcmp(s, lp, 33) == 0) return 1;
        if (cbor_skip(&r) != 0) return 0;
    }
    return 0;
}

/* read a uint from an arbitrary map: 1 present, 0 absent, -1 type error. */
static int map_uint(const unsigned char *buf, size_t len, size_t map_pos, const char *key, uint64_t *out)
{
    cbor_rd f; if (!cbor_map_find(buf, len, map_pos, key, &f)) return 0;
    cbor_rd r = { buf, len, f.pos }; int mj; uint64_t v;
    if (cbor_head(&r, &mj, &v) != 0 || mj != 0) return -1;
    *out = v; return 1;
}
/* true iff map[key] is CBOR true (0xf5). */
static int map_bool_true(const unsigned char *buf, size_t len, size_t map_pos, const char *key)
{
    cbor_rd f; if (!cbor_map_find(buf, len, map_pos, key, &f)) return 0;
    return f.pos < len && buf[f.pos] == 0xf5;
}

/* ── §5.5a point 2: per-link chain attenuation in each side's granter frame ──────
 * When verify_capability_chain walks parent → child, the child's grants MUST be a
 * subset of the parent's — and the resource subset-check on each link MUST
 * canonicalize each side against THAT link's own granter peer_id (§5.5a). Conflating
 * the per-link frames lets a foreign-granted bare `*` (which canonicalizes to
 * `/{granter}/*`, the granter's OWN namespace) silently canonicalize to the verifier's
 * `/{verifier}/*` and falsely pass attenuation. Gates: authz_attenuation_foreign_
 * granter_{1,deep,wildcard_leaf}. Resource dimension only (what the vectors exercise). */

/* Resolve a granter content_hash to its base58 peer_id via its included system/peer
 * {key_type, public_key} entity. Ed25519 (§9.1 floor) only — the vectors are Ed25519;
 * a non-Ed25519 granter returns -1 (chain fails closed rather than mis-canonicalize). */
static int granter_pid_str(const unsigned char *buf, size_t len, const unsigned char granter[33], char *out, size_t outcap)
{
    cbor_rd grent; unsigned char pk[64]; size_t npk = 0;
    if (!included_find(buf, len, granter, &grent)) return -1;
    if (entity_data_bytes(buf, len, &grent, "public_key", pk, sizeof pk, &npk) != 0 || npk != EC_ED25519_PUB_LEN) return -1;
    size_t olen = 0;
    if (ec_peerid_format(1 /*Ed25519*/, 0, pk, npk, (uint8_t *)out, outcap - 1, &olen) != EC_OK || olen >= outcap) return -1;
    out[olen] = '\0';
    return 0;
}

/* Canonicalize a cap resource pattern to absolute form in its granter's frame:
 * peer-relative "system/x" / "*" → "/{granter_pid}/system/x" | "/{granter_pid}/*";
 * an already-absolute "/{peer}/..." passes through (§5.5a). */
static void resource_canon(const char *pat, const char *pid, char *out, size_t cap)
{
    if (pat[0] == '/') { snprintf(out, cap, "%s", pat); return; }
    snprintf(out, cap, "/%s/%s", pid, pat);
}

/* Does absolute pattern Pabs cover absolute pattern Cabs? Peer segment: parent `*`
 * covers any, else must be byte-equal. Path segment: parent `*` covers any; parent
 * "prefix/*" covers any path starting "prefix/"; else exact. (Subset arithmetic over
 * the §5.4 pattern forms; wildcard-vs-wildcard handled — wildcard_leaf gate.) */
static int abs_covers(const char *Pabs, const char *Cabs)
{
    const char *pp = Pabs + 1, *ps = strchr(pp, '/');
    const char *cp = Cabs + 1, *cs = strchr(cp, '/');
    if (!ps || !cs) return 0;
    size_t pplen = (size_t)(ps - pp), cplen = (size_t)(cs - cp);
    const char *ppath = ps + 1, *cpath = cs + 1;
    int peer_ok = (pplen == 1 && pp[0] == '*') || (pplen == cplen && strncmp(pp, cp, pplen) == 0);
    if (!peer_ok) return 0;
    if (!strcmp(ppath, "*")) return 1;
    size_t pl = strlen(ppath);
    if (pl >= 2 && ppath[pl - 1] == '*' && ppath[pl - 2] == '/') return strncmp(cpath, ppath, pl - 1) == 0;
    return strcmp(cpath, ppath) == 0;
}

/* True iff some resource pattern in the grant array at `grants_pos` (parent frame
 * `ppid`) covers `Cabs`. */
static int parent_grants_cover(const unsigned char *buf, size_t len, size_t grants_pos, const char *ppid, const char *Cabs)
{
    cbor_rd gr = { buf, len, grants_pos }; int gmj; uint64_t gn;
    if (cbor_head(&gr, &gmj, &gn) != 0 || gmj != 4) return 0;
    for (uint64_t gi = 0; gi < gn; gi++) {
        size_t ge = gr.pos; cbor_rd sc, inc;
        if (cbor_map_find(buf, len, ge, "resources", &sc) && cbor_map_find(buf, len, sc.pos, "include", &inc)) {
            cbor_rd rr = { buf, len, inc.pos }; int rmj; uint64_t rn;
            if (cbor_head(&rr, &rmj, &rn) == 0 && rmj == 4) {
                for (uint64_t ri = 0; ri < rn; ri++) {
                    char rp[512], Pabs[640]; cbor_rd re = { buf, len, rr.pos };
                    if (cbor_get_text(&re, rp, sizeof rp) != 0) return 0;
                    resource_canon(rp, ppid, Pabs, sizeof Pabs);
                    if (abs_covers(Pabs, Cabs)) return 1;
                    if (cbor_skip(&rr) != 0) return 0;
                }
            }
        }
        if (cbor_skip(&gr) != 0) return 0;
    }
    return 0;
}

/* §5.5a point 2: every resource the CHILD cap grants (canonicalized in the child's
 * granter frame `cpid`) MUST be covered by some resource the PARENT grants (parent
 * frame `ppid`). 0 → child widens beyond parent → chain rejected. */
static int resources_attenuated(const unsigned char *buf, size_t len,
                                size_t child_ent, const char *cpid,
                                size_t parent_ent, const char *ppid)
{
    cbor_rd cd, cg, pd, pg;
    if (!cbor_map_find(buf, len, child_ent, "data", &cd) || !cbor_map_find(buf, len, cd.pos, "grants", &cg)) return 1;
    if (!cbor_map_find(buf, len, parent_ent, "data", &pd) || !cbor_map_find(buf, len, pd.pos, "grants", &pg)) return 0;
    cbor_rd cgr = { buf, len, cg.pos }; int cmj; uint64_t cn;
    if (cbor_head(&cgr, &cmj, &cn) != 0 || cmj != 4) return 0;
    for (uint64_t ci = 0; ci < cn; ci++) {
        size_t ge = cgr.pos; cbor_rd sc, inc;
        if (cbor_map_find(buf, len, ge, "resources", &sc) && cbor_map_find(buf, len, sc.pos, "include", &inc)) {
            cbor_rd rr = { buf, len, inc.pos }; int rmj; uint64_t rn;
            if (cbor_head(&rr, &rmj, &rn) != 0 || rmj != 4) return 0;
            for (uint64_t ri = 0; ri < rn; ri++) {
                char rp[512], Cabs[640]; cbor_rd re = { buf, len, rr.pos };
                if (cbor_get_text(&re, rp, sizeof rp) != 0) return 0;
                resource_canon(rp, cpid, Cabs, sizeof Cabs);
                if (!parent_grants_cover(buf, len, pg.pos, ppid, Cabs)) return 0;
                if (cbor_skip(&rr) != 0) return 0;
            }
        }
        if (cbor_skip(&cgr) != 0) return 0;
    }
    return 1;
}

/* Set when a chain walk aborts because it exceeds §5.5 max depth (64) — a STRUCTURAL
 * excess that surfaces as 400 chain_depth_exceeded (§4.10(b)), distinct from an authz
 * DENY (403). Read by authz_check_capchain immediately after the walk. */
static int g_chain_depth_exceeded = 0;

static int cap_revoked(const unsigned char h33[33]);   /* fwd (dynamic store, below) */

static int ec_verify_cap_chain(const unsigned char *buf, size_t len, const unsigned char *leaf_h)
{
    g_chain_depth_exceeded = 0;
    unsigned char cur[33]; memcpy(cur, leaf_h, 33);
    unsigned char lpeer[33]; if (local_peer_hash(lpeer)) return 0;
    /* millisecond-precision wall clock — the oracle sets per-link expiry with ms
     * granularity, so a second-truncated clock misses a link that expired mid-second. */
    struct timespec ts_now; clock_gettime(CLOCK_REALTIME, &ts_now);
    uint64_t now = (uint64_t)ts_now.tv_sec * 1000ULL + (uint64_t)ts_now.tv_nsec / 1000000ULL;
    int depth = 0;
    for (int step = 0; step < 64; step++) {                 /* §5.5 max chain depth 64 */
        cbor_rd cap;
        if (!included_find(buf, len, cur, &cap)) return 0;                 /* unresolvable link */
        if (cap_revoked(cur)) return 0;                     /* §5.2 step 4: revocation marker */
        if (cap_content_hash_ok(buf, len, &cap, cur) != 0) return 0;       /* F6 substitution */
        /* per-link temporal (§5.5) — before the signature branch so both the
         * single-sig and multi-sig paths share it */
        uint64_t exp = 0, nbf = 0;
        int he = entity_data_uint(buf, len, &cap, "expires_at", &exp);
        int hn = entity_data_uint(buf, len, &cap, "not_before", &nbf);
        if (he < 0 || hn < 0) return 0;                                    /* malformed temporal */
        if (he == 1 && exp < now) return 0;                                /* per-link expired */
        if (hn == 1 && now < nbf) return 0;                                /* per-link not-yet-valid */
        unsigned char granter[33]; size_t n = 0;
        if (entity_data_bytes(buf, len, &cap, "granter", granter, 33, &n) != 0 || n != 33) {
            /* not a 33-byte hash → the polymorphic multi-granter branch (M3/M4/M6):
             * a valid K-of-N multi-sig cap is a ROOT (parent MUST be null), so the
             * walk terminates here either way. */
            return multisig_root_ok(buf, len, &cap, cur);
        }
        if (!cap_sig_ok(buf, len, cur, granter)) return 0;
        /* parent link? entity_data_bytes returns non-zero for an ABSENT parent (a
         * root cap) as well as a malformed one — both fall through to the root
         * check; only an explicit valid 33-byte parent hash continues the walk. */
        unsigned char parent[33]; size_t np = 0;
        int hp = entity_data_bytes(buf, len, &cap, "parent", parent, 33, &np);
        if (hp == 0 && np == 33) {
            cbor_rd pent;
            if (!included_find(buf, len, parent, &pent)) return 0;
            unsigned char pgrantee[33]; size_t ng = 0;
            if (entity_data_bytes(buf, len, &pent, "grantee", pgrantee, 33, &ng) != 0 || ng != 33) return 0;
            if (memcmp(pgrantee, granter, 33) != 0) return 0;             /* linkage */
            /* §5.5a point 2: child (cur) grants MUST be ⊆ parent grants, each side
             * canonicalized in ITS OWN granter's frame. `granter` is cur's granter;
             * pgranter is the parent's. A foreign-granted bare `*` stays granter-local
             * (`/{granter}/*`) and cannot silently widen to the verifier's namespace. */
            {
                unsigned char pgranter[33]; size_t npg = 0;
                if (entity_data_bytes(buf, len, &pent, "granter", pgranter, 33, &npg) != 0 || npg != 33) return 0;
                char cpid[128], ppid[128];
                if (granter_pid_str(buf, len, granter, cpid, sizeof cpid) != 0) return 0;
                if (granter_pid_str(buf, len, pgranter, ppid, sizeof ppid) != 0) return 0;
                if (!resources_attenuated(buf, len, cap.pos, cpid, pent.pos, ppid)) return 0;
            }
            /* parent delegation caveats constrain the child (cur) — §5.7 */
            cbor_rd pdata, dc;
            if (cbor_map_find(buf, len, pent.pos, "data", &pdata)
                && cbor_map_find(buf, len, pdata.pos, "delegation_caveats", &dc)) {
                if (map_bool_true(buf, len, dc.pos, "no_delegation")) return 0;
                uint64_t mttl;
                if (map_uint(buf, len, dc.pos, "max_delegation_ttl", &mttl) == 1) {
                    uint64_t cre = 0; int hc = entity_data_uint(buf, len, &cap, "created_at", &cre);
                    if (he != 1) return 0;                                /* ttl-capped but child never expires */
                    uint64_t cttl = (hc == 1 && exp >= cre) ? (exp - cre) : exp;
                    if (cttl > mttl) return 0;
                }
                uint64_t mdep;
                if (map_uint(buf, len, dc.pos, "max_delegation_depth", &mdep) == 1 && (uint64_t)(depth + 1) > mdep) return 0;
            }
            depth++;
            memcpy(cur, parent, 33);
            continue;
        }
        /* root (no parent): a root cap this peer did not grant is forged (§5.5) */
        return memcmp(granter, lpeer, 33) == 0;
    }
    g_chain_depth_exceeded = 1;                                          /* §5.5 max depth 64 */
    return 0;                                                             /* chain too deep */
}

/* [authz_check_capchain( — §5.2 step 3b / §5.5 verify_capability_chain: the full
 * multi-link walk (content-hash + per-link signature + per-link temporal + linkage
 * + delegation caveats + attenuation + forged-root). 0 → canvas 403 capability_denied,
 * EXCEPT a chain that exceeds §5.5 max depth (64): that STRUCTURAL excess surfaces as
 * 400 chain_depth_exceeded (§4.10(b)), disambiguated from an authz denial — emitted
 * here directly (a structural transport bound, like the §1.6 frame cap) so the frame
 * is answered without threading a third capchain outcome through the canvas. */
static void ecodec_authz_check_capchain(t_ecodec *x)
{
    int ok = g_authz.valid && ec_verify_cap_chain(g_rbuf, g_rbuf_len, g_authz.cap_h);
    if (!ok && g_chain_depth_exceeded) { emit_error_response(x, 400, "chain_depth_exceeded"); return; }
    authz_bit(x, "capchain_ok", ok);
}

/* [authz_check_grantee_resolvable( — §5.5 grantee resolution (PR-3): the cap's
 * grantee hash MUST resolve to a present system/peer entity (included/store). The
 * canvas consults this ONLY when grantee != author (grantee_ok == 0), to split
 * that DENY: unresolvable → 0 → 401 unresolvable_grantee (the single authz→401
 * carve-out, §3.6/§5.5); resolvable-but-mismatched → 1 → 403 capability_denied. */
static void ecodec_authz_check_grantee_resolvable(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        cbor_rd cap; unsigned char grantee[33]; size_t n = 0;
        if (included_find(buf, len, g_authz.cap_h, &cap)
            && entity_data_bytes(buf, len, &cap, "grantee", grantee, 33, &n) == 0 && n == 33) {
            cbor_rd gent;
            if (included_find(buf, len, grantee, &gent) && entity_type_is(buf, len, &gent, "system/peer"))
                ok = 1;
        }
    }
    authz_bit(x, "grantee_res_ok", ok);
}

/* [authz_check_validity( — §5.6 / §5.2 temporal validity (checked within
 * verify_capability_chain, §5.5): reject when now < not_before or expires_at < now.
 * Absent bounds → unbounded (valid). 0 → canvas 403 capability_denied (no separate
 * capability_expired code — §5.2 authorization-path code discipline). `now` is the
 * peer wall clock in ms (the same source build_grant stamps issued_at with). */
static void ecodec_authz_check_validity(t_ecodec *x)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    if (g_authz.valid) {
        cbor_rd cap;
        if (included_find(buf, len, g_authz.cap_h, &cap)) {
            uint64_t now = wall_ms(), exp = 0, nbf = 0, cre = 0;
            int have_exp = entity_data_uint(buf, len, &cap, "expires_at", &exp);
            int have_nbf = entity_data_uint(buf, len, &cap, "not_before", &nbf);
            /* §6.2 CAP-6a covers THREE fields, not two. This checked expires_at and
             * not_before and left created_at unguarded -- and the oracle probes all
             * three, so the peer honored a cap whose created_at was negative. The
             * accessor already distinguishes absent (0) from present-but-not-uint64
             * (-1); the omission was in which fields it was asked about. */
            int have_cre = entity_data_uint(buf, len, &cap, "created_at", &cre);
            ok = 1;
            if (have_exp == 1 && exp < now) ok = 0;            /* expired */
            if (have_nbf == 1 && now < nbf) ok = 0;            /* not yet valid */
            /* CAP-6a: present but unrepresentable is MALFORMED, not absent. This test
             * must stand alongside (not behind) the range tests above -- those use the
             * ==1 arm, so on their own an unrepresentable field is indistinguishable
             * from an absent one and the cap is honored (fail-open). */
            if (have_exp < 0 || have_nbf < 0 || have_cre < 0) ok = 0;
        }
    }
    authz_bit(x, "validity_ok", ok);
}

/* ── §5.2 step 5 check_permission — scope matching (§5.4) ──────────────────────
 * Pure path logic (no crypto). Grant patterns and request values are peer-relative;
 * canonicalization (§5.4) prepends the same /{local_peer}/ to both, so comparing
 * the relative forms is equivalent for local-peer grants (the floor grants omit
 * `peers`, defaulting to local; requests target the local peer → the peers
 * dimension is a no-op here and is skipped with that assumption). */

/* §5.4's NEVER_MATCH, expressed as a PREDICATE rather than as a sentinel string.
 *
 * This peer never materializes a canonical ABSOLUTE form for local grants — its
 * matchers work in peer-relative terms — so there is no string for the sentinel to
 * ride on. What the sentinel EXISTS FOR is two observable properties, and both are
 * implementable directly on the pattern:
 *   (a) a form canonicalize() cannot resolve never matches, in EITHER operand
 *       (0.8.2.20);
 *   (b) such a form in an EXCLUDE denies rather than carving out nothing (0.8.2.21).
 * Without (b) a grant exclude of "../x" matched nothing, so the grant was silently
 * wider than its author wrote (measured on the wire 2026-09-14). */
static int pat_unmatchable(const char *p)
{
    return strncmp(p, "./", 2) == 0 || strncmp(p, "../", 3) == 0 || strncmp(p, "*/", 2) == 0;
}

/* True if any text element of the array at `arr_pos` is an unmatchable form. */
static int array_any_unmatchable(const unsigned char *buf, size_t len, size_t arr_pos)
{
    cbor_rd r = { buf, len, arr_pos }; int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        char e[512]; cbor_rd ev = { buf, len, r.pos };
        if (cbor_get_text(&ev, e, sizeof e) != 0) return 0;
        if (pat_unmatchable(e)) return 1;
        if (cbor_skip(&r) != 0) return 0;
    }
    return 0;
}

/* §5.4 matches_pattern on peer-relative forms: bare star any; "prefix/" + star
 * prefix match; else exact. (The peer-wildcard form is unused by local grants.) */
static int matches_pattern_rel(const char *path, const char *pat)
{
    /* (a), FIRST — and a matcher rule rather than a property of the string: the arm
     * below returns 1 for a bare "*" pattern, so safety must not rest on a value
     * merely looking unmatchable. */
    if (pat_unmatchable(pat) || pat_unmatchable(path)) return 0;
    if (strcmp(pat, "*") == 0) return 1;
    size_t pl = strlen(pat);
    if (pl >= 2 && pat[pl - 1] == '*' && pat[pl - 2] == '/')
        return strncmp(path, pat, pl - 1) == 0;      /* path starts with "prefix/" */
    return strcmp(path, pat) == 0;
}

/* True if any text element of the array at `arr_pos` matches `value`. */
static int array_any_match(const unsigned char *buf, size_t len, size_t arr_pos, const char *value)
{
    cbor_rd r = { buf, len, arr_pos }; int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        char e[256]; cbor_rd ev = { buf, len, r.pos };
        if (cbor_get_text(&ev, e, sizeof e) != 0) return 0;
        if (matches_pattern_rel(value, e)) return 1;
        if (cbor_skip(&r) != 0) return 0;
    }
    return 0;
}

/* §5.2 matches_scope on a {include, exclude?} scope map at `scope_pos`. */
static int matches_scope_rel(const unsigned char *buf, size_t len, size_t scope_pos, const char *value)
{
    cbor_rd inc, exc;
    /* (b) — an unmatchable EXCLUDE denies. Outside the scope-type dispatch,
     * transcribing §5.2's loop literally. */
    if (cbor_map_find(buf, len, scope_pos, "exclude", &exc)
        && array_any_unmatchable(buf, len, exc.pos)) return 0;
    if (!cbor_map_find(buf, len, scope_pos, "include", &inc)) return 0;
    if (!array_any_match(buf, len, inc.pos, value)) return 0;
    if (cbor_map_find(buf, len, scope_pos, "exclude", &exc) && array_any_match(buf, len, exc.pos, value)) return 0;
    return 1;
}

/* §5.5a granter-frame resource-pattern match (dispatch surface 1). `reqrel` is the
 * request target in peer-relative (LOCAL) form; `pat` is a cap resource pattern.
 *   - peer-relative pattern (no leading slash): GRANTER-LOCAL. A bare star means
 *     "{granter}/star", the granter's OWN namespace, NOT a universal wildcard — so it
 *     matches the (local) request ONLY when the granter is the local peer. A cap
 *     minted peer-local by a FOREIGN granter and presented cross-peer therefore does
 *     NOT authorize our namespace -> 403 (V2a captok_form_dispatch_minted_pl_presented_xpeer).
 *   - absolute pattern (leading slash): names the peer position explicitly —
 *     "/{peer}/..." (specific) or "/{star}/..." (all peers). Cross-peer authority MUST
 *     use this form; it matches when the peer position is star or the local peer_id.
 * (§5.5a: "bare star MUST NOT be interpreted as universal".) */
static int matches_resource_pat(const char *reqrel, const char *pat, int granter_local, const char *local_pid)
{
    if (pat_unmatchable(pat)) return 0;                 /* (a) */
    if (pat[0] == '/') {
        const char *p = pat + 1;
        const char *slash = strchr(p, '/');
        size_t seglen = slash ? (size_t)(slash - p) : strlen(p);
        const char *rest = slash ? slash + 1 : "";
        int peer_ok = (seglen == 1 && p[0] == '*')
                   || (strlen(local_pid) == seglen && strncmp(p, local_pid, seglen) == 0);
        if (!peer_ok) return 0;
        return matches_pattern_rel(reqrel, rest[0] ? rest : "*");
    }
    return granter_local ? matches_pattern_rel(reqrel, pat) : 0;
}

/* §5.2 matches_scope over a {include, exclude?} map for the RESOURCE dimension,
 * applying §5.5a granter-frame canonicalization to each pattern. */
static int matches_resource_scope(const unsigned char *buf, size_t len, size_t scope_pos,
                                  const char *reqrel, int granter_local, const char *local_pid)
{
    cbor_rd inc, exc;
    /* (b) — an unmatchable GRANT exclude denies. FIRST, before any include test:
     * the exclude loop below is correct in isolation and is simply never reached on
     * an unmatchable form, because matches_resource_pat answers 0. */
    if (cbor_map_find(buf, len, scope_pos, "exclude", &exc)
        && array_any_unmatchable(buf, len, exc.pos)) return 0;
    if (!cbor_map_find(buf, len, scope_pos, "include", &inc)) return 0;
    cbor_rd r = { buf, len, inc.pos }; int mj; uint64_t n; int hit = 0;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        char e[512]; cbor_rd ev = { buf, len, r.pos };
        if (cbor_get_text(&ev, e, sizeof e) != 0) return 0;
        if (matches_resource_pat(reqrel, e, granter_local, local_pid)) hit = 1;
        if (cbor_skip(&r) != 0) return 0;
    }
    if (!hit) return 0;
    if (cbor_map_find(buf, len, scope_pos, "exclude", &exc)) {
        cbor_rd xr = { buf, len, exc.pos }; int xmj; uint64_t xn;
        if (cbor_head(&xr, &xmj, &xn) == 0 && xmj == 4) {
            for (uint64_t i = 0; i < xn; i++) {
                char e[512]; cbor_rd ev = { buf, len, xr.pos };
                if (cbor_get_text(&ev, e, sizeof e) != 0) return 0;
                if (matches_resource_pat(reqrel, e, granter_local, local_pid)) return 0;
                if (cbor_skip(&xr) != 0) return 0;
            }
        }
    }
    return 1;
}

/* §5.2 peers dimension: `grant.peers or {include: [local_peer_id]}`, checked
 * against `target_peer`. `peers` is `system/capability/id-scope` (same shape as
 * `operations`) — id-scope matching is literal-with-bare-star/prefix-star, no
 * absolute-path canonicalization (peer IDs carry no "/"), so matches_scope_rel
 * (already used for `operations`) applies unchanged; see rust reference
 * `matches_id_pattern` (`protocol-generator/rust/src/peer/capability.rs`). */
static int matches_peers_scope(const unsigned char *buf, size_t len, size_t ge,
                               const char *target_peer, const char *local_pid)
{
    cbor_rd sc;
    if (!cbor_map_find(buf, len, ge, "peers", &sc)) return strcmp(target_peer, local_pid) == 0;
    return matches_scope_rel(buf, len, sc.pos, target_peer);
}

/* §5.2 check_permission: some grant in the cap entity (at cap_ent_pos) covers
 * (operation, handler, target_peer, resource_or_null) across
 * operations/handlers/peers/resources. The resource dimension canonicalizes each
 * pattern in the cap GRANTER's frame (§5.5a): `granter_local` says whether the
 * cap's granter is the local peer; `local_pid` is this peer's base58 peer_id (for
 * absolute `/{peer}/...` pattern matching AND the peers-scope default/self-check).
 * `target_peer` is `extract_peer(execute.data.uri, local_pid)` (§5.2 L2067) —
 * the peer segment of the request's OWN dispatch URI, not the resource target. */
static int cap_permits(const unsigned char *buf, size_t len, size_t cap_ent_pos,
                       const char *operation, const char *handler, const char *resource,
                       int granter_local, const char *local_pid, const char *target_peer)
{
    cbor_rd d, grants;
    if (!cbor_map_find(buf, len, cap_ent_pos, "data", &d)) return 0;
    if (!cbor_map_find(buf, len, d.pos, "grants", &grants)) return 0;
    cbor_rd r = { buf, len, grants.pos }; int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 4) return 0;
    for (uint64_t i = 0; i < n; i++) {
        size_t ge = r.pos; cbor_rd sc; int okg = 1;
        if (!cbor_map_find(buf, len, ge, "operations", &sc) || !matches_scope_rel(buf, len, sc.pos, operation)) okg = 0;
        if (okg && (!cbor_map_find(buf, len, ge, "handlers", &sc) || !matches_scope_rel(buf, len, sc.pos, handler))) okg = 0;
        if (okg && !matches_peers_scope(buf, len, ge, target_peer, local_pid)) okg = 0;
        if (okg && resource) {
            if (!cbor_map_find(buf, len, ge, "resources", &sc)
                || !matches_resource_scope(buf, len, sc.pos, resource, granter_local, local_pid)) okg = 0;
        }
        if (okg) return 1;
        if (cbor_skip(&r) != 0) return 0;   /* advance to next grant-entry */
    }
    return 0;
}

/* Strip a wire path to its peer-relative form: entity://{peer}/rest or /{peer}/rest
 * -> rest; an already-relative path passes through. Returns a pointer into `in`. */
static const char *to_peer_relative(const char *in)
{
    const char *p = in;
    if (strncmp(p, "entity://", 9) == 0) { p += 9; const char *s = strchr(p, '/'); return s ? s + 1 : p; }
    if (p[0] == '/') { const char *s = strchr(p + 1, '/'); return s ? s + 1 : p + 1; }
    return p;   /* already peer-relative */
}

/* §1.4 universal-address-space store key: LOCAL-peer forms (bare-relative,
 * entity://{local}/rest, /{local}/rest) canonicalize to the bare peer-relative
 * key; a FOREIGN peer prefix is PRESERVED as an absolute "/{peer}/rest" key so a
 * foreign namespace never aliases the local one (to_peer_relative strips ANY
 * peer prefix — correct for dispatch URIs, wrong for storage). Returns `buf`. */
/* A plausible peer-id path segment: base58 alphabet, peer-id-scale length. A
 * leading '/' whose first segment is NOT a peer id is a malformed caller path
 * (caller paths are peer-relative; only "/{peer_id}/..." is absolute). */
static int is_peer_id_seg(const char *s, size_t n)
{
    if (n < 32 || n > 120) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'N')
              || (c >= 'P' && c <= 'Z') || (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z')))
            return 0;
    }
    return 1;
}

static const char *canonical_key(const char *in, char *buf, size_t cap)
{
    ec_init_identity();
    const char *peer = NULL; size_t plen = 0; const char *rest = in;
    if (strncmp(in, "entity://", 9) == 0) {
        peer = in + 9;
        const char *s = strchr(peer, '/');
        plen = s ? (size_t)(s - peer) : strlen(peer);
        rest = s ? s + 1 : "";
    } else if (in[0] == '/') {
        peer = in + 1;
        const char *s = strchr(peer, '/');
        plen = s ? (size_t)(s - peer) : strlen(peer);
        rest = s ? s + 1 : "";
    }
    if (!peer || (strlen(g_peer_id) == plen && strncmp(peer, g_peer_id, plen) == 0)) {
        snprintf(buf, cap, "%s", rest);                    /* local → bare-relative */
    } else {
        if (!is_peer_id_seg(peer, plen)) return NULL;      /* "/notapeer/..." → invalid */
        snprintf(buf, cap, "/%.*s/%s", (int)plen, peer, rest);  /* foreign → absolute */
    }
    return buf;
}

/* §5.2 extract_peer(uri, local_peer_id) (L2196-2201): the first URI path segment
 * if it looks like a peer id, else the local peer. Strips an "entity://" scheme
 * or a single leading '/' first (both to_peer_relative and canonical_key strip
 * the same two wire forms); a bare peer-relative URI's first segment is a
 * handler-tree segment, not a peer id, and falls through to local_pid — matches
 * rust's `extract_peer` (`protocol-generator/rust/src/peer/capability.rs`). */
static const char *extract_peer(const char *uri, const char *local_pid, char *out, size_t cap)
{
    const char *p = uri;
    if (strncmp(p, "entity://", 9) == 0) p += 9;
    else if (p[0] == '/') p += 1;
    const char *slash = strchr(p, '/');
    size_t seglen = slash ? (size_t)(slash - p) : strlen(p);
    if (seglen > 0 && is_peer_id_seg(p, seglen)) {
        size_t n = seglen < cap - 1 ? seglen : cap - 1;
        memcpy(out, p, n); out[n] = '\0';
        return out;
    }
    snprintf(out, cap, "%s", local_pid);
    return out;
}

/* [uri_targets_local( — §1.4 / §6.5 step 3: the ADDRESS gate. Does the EXECUTE's
 * data.uri address THIS peer? extract_peer above returns the local peer id for a
 * bare/peer-relative uri and for any first segment that is not peer-id-shaped, so
 * those all answer 1; only a real FOREIGN peer id answers 0.
 *
 * This is a PREDICATE, not a decision — it emits [uri_local_ok 0|1( and the canvas
 * owns the verdict (FLOW-DESIGN's wrapper-guard: the §5.2/§6.5 sequence is authored
 * on the canvas, the seam only does the string work). Same shape as [op_supported(
 * directly below.
 *
 * Why it exists: every other rung on the ladder canonicalizes the uri and works with
 * what is left, which drops a foreign peer id and resolves OUR handler at the
 * remaining path — the exact route §6.5 step 3 forbids, because the presented grant's
 * `peers` scope then authorizes a foreign namespace. Measured before this gate: status
 * 200, the live foreign-namespace privilege escalation. The refusal is on the ADDRESS,
 * so the canvas answers 400 invalid_request — not a 404 (which would claim this peer
 * has no such handler, false of a peer that has it and is refusing the address) and
 * not a 403 (which would make it an authz verdict when no capability question was
 * asked). It sits between the §5.2 validity rung and the §6.6 walk, so it runs after
 * authentication and before this peer resolves anything. */
static void ecodec_uri_targets_local(t_ecodec *x)
{
    ec_init_identity();
    char peer[128];
    const char *tp = extract_peer(g_dec.uri, g_peer_id, peer, sizeof peer);
    int ok = (tp && !strcmp(tp, g_peer_id));
    t_atom a; SETFLOAT(&a, ok);
    outlet_anything(x->x_out, gensym("uri_local_ok"), 1, &a);
}

/* The resolved handler pattern (peer-relative), stashed by [op_supported( so the
 * subsequent [authz_check_perm( bang can read it without re-plumbing the pattern
 * through the op-existence gate on the canvas (avoids the A-PD-007 route→$1 trap). */
static char g_resolved_handler[256];

/* The capability handler's FIXED operation vocabulary (§6.2). Unlike a data handler
 * (system/tree), whose out-of-scope operation is caught by check_permission (→ 403),
 * the capability handler's vocabulary is closed: an operation outside it "does not
 * exist on this handler" and MUST return 501 unsupported_operation REGARDLESS of the
 * caller's authority (§3.3 / §6.2 "Capability handler operation status codes",
 * L2957-2960). That authority-independence is why the op-existence gate for THIS
 * handler runs BEFORE the §5.2 perm rung — a get on system/capability is 501, not the
 * 403 an out-of-scope tree op earns. Membership is from the spec, not the oracle. */
static int capability_op_implemented(const char *op)
{
    if (!op || !op[0]) return 0;
    return !strcmp(op, "request") || !strcmp(op, "delegate")
        || !strcmp(op, "revoke")  || !strcmp(op, "configure");
}

/* [op_supported <handler_pattern>( — §6.5 dispatch step BETWEEN handler resolution
 * (§6.6 → 404 handler_not_found) and check_permission (§5.2 → 403). Scoped to the
 * capability handler's closed vocabulary (see capability_op_implemented): an op it
 * does not implement → 501 unsupported_operation, authority-irrelevant, so this gate
 * precedes the perm rung. For every other handler the gate is a pass-through (op_ok
 * = 1) — an unsupported/out-of-scope op there is a §5.2 check_permission DENY (403),
 * not a 501. Stashes the resolved pattern for the perm rung; emits [op_ok 0|1(. */
static void ecodec_op_supported(t_ecodec *x, t_symbol *handler)
{
    const char *hpat = (handler && handler->s_name[0]) ? handler->s_name : "";
    strncpy(g_resolved_handler, hpat, sizeof(g_resolved_handler) - 1);
    g_resolved_handler[sizeof(g_resolved_handler) - 1] = '\0';
    const char *op = g_authz.valid ? g_authz.operation : "";
    int ok = 1;
    if (!strcmp(hpat, "system/capability")) ok = capability_op_implemented(op);
    t_atom a; SETFLOAT(&a, ok);
    outlet_anything(x->x_out, gensym("op_ok"), 1, &a);
}

/* [authz_check_perm <handler_pattern>( — §5.2 step 5, called AFTER §6.6 handler
 * resolution (the canvas supplies the resolved handler pattern). Evaluates the
 * cap's grants against (operation, handler, first resource target). 0 → 403
 * capability_denied. When invoked with no arg (a bare bang, post op-gate) it reads
 * the pattern stashed by [op_supported(. */
static void ecodec_authz_check_perm(t_ecodec *x, t_symbol *handler)
{
    int ok = 0;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    const char *hpat = (handler && handler->s_name[0]) ? handler->s_name : g_resolved_handler;
    if (g_authz.valid) {
        cbor_rd cap;
        if (included_find(buf, len, g_authz.cap_h, &cap)) {
            const char *resource = NULL; char raw[512], key[512];
            cbor_rd root, rdata, resfld, targets;
            if (cbor_map_find(buf, len, 0, "root", &root)
                && cbor_map_find(buf, len, root.pos, "data", &rdata)
                && cbor_map_find(buf, len, rdata.pos, "resource", &resfld)
                && cbor_map_find(buf, len, resfld.pos, "targets", &targets)) {
                cbor_rd tr = { buf, len, targets.pos }; int major; uint64_t n;
                if (cbor_head(&tr, &major, &n) == 0 && major == 4 && n >= 1) {
                    cbor_rd e = { buf, len, tr.pos };
                    /* canonical form (§1.4): a FOREIGN peer prefix must stay
                     * absolute in the perm check, never alias local namespace */
                    if (cbor_get_text(&e, raw, sizeof raw) == 0)
                        resource = canonical_key(raw, key, sizeof key);
                }
            }
            /* §5.5a granter frame: the presented (leaf) cap's resource patterns
             * canonicalize against ITS granter's peer_id, not ours. A peer-relative
             * pattern (bare `*`) on a FOREIGN-granted cap is granter-local and does
             * NOT reach our namespace → DENY (V2a). Same-peer caps are unaffected
             * (granter == local, byte-identical frames). Multi-granter aware. */
            int granter_local = cap_granter_local(buf, len, &cap);
            ec_init_identity();
            /* §5.2 target_peer = extract_peer(execute.data.uri, local_peer_id) —
             * the peer segment of THIS request's own dispatch URI (g_dec.uri),
             * not the resource target parsed above. */
            char tpeer[128];
            extract_peer(g_dec.uri, g_peer_id, tpeer, sizeof tpeer);
            ok = cap_permits(buf, len, cap.pos, g_authz.operation, hpat, resource,
                             granter_local, g_peer_id, tpeer);
        }
    }
    authz_bit(x, "perm_ok", ok);
}

/* ── §6.6 path-dispatch primitives ────────────────────────────────────────
 * String slicing (segment count / prefix join) is the substrate-hard part → in
 * the seam; the WALK ITSELF (backward longest-prefix loop, the type=="system/
 * handler" filter, the early return) is authored on the canvas (the FLOW-DESIGN
 * wrapper-guard). tree_get is a bootstrapped placeholder handler set — the real
 * entity tree/content store (keyed by full path incl. peer_id, populated from
 * identity at the §4.1 handshake) replaces it later; for now it demonstrates the
 * walk discriminating known handler prefixes from unknown paths (A-PD-006). */

/* The §6.6 tree-walk runs on the CANONICALIZED, peer-relative URI: the wire URI is
 * entity://{peer}/system/tree (§1.4), and handler patterns / grant `handlers` are
 * peer-relative (system/tree). to_peer_relative strips entity://{peer}/ (or /{peer}/)
 * so prefixes match g_handler_paths and check_permission's handler dimension; a
 * bare peer-relative URI passes through unchanged (S3 treewalktest still holds). */
static int uri_nsegs(void)
{
    int n = 0, inseg = 0;
    for (const char *p = to_peer_relative(g_dec.uri); *p; p++) {
        if (*p == '/') inseg = 0;
        else if (!inseg) { n++; inseg = 1; }
    }
    return n;
}

/* join the first `i` segments of the peer-relative URI into out[cap] (NUL-term). */
static void uri_prefix(int i, char *out, size_t cap)
{
    size_t ol = 0; int seg = 0, inseg = 0;
    for (const char *q = to_peer_relative(g_dec.uri); *q; q++) {
        if (*q == '/') { inseg = 0; continue; }
        if (!inseg) { seg++; inseg = 1; if (seg > i) break; if (seg > 1 && ol + 1 < cap) out[ol++] = '/'; }
        if (seg <= i && ol + 1 < cap) out[ol++] = *q;
    }
    out[(ol < cap) ? ol : (cap ? cap - 1 : 0)] = '\0';
}

static void ecodec_walk_nsegs(t_ecodec *x)
{
    t_atom a; SETFLOAT(&a, (t_float)uri_nsegs());
    outlet_anything(x->x_out, gensym("nsegs"), 1, &a);
}

static void ecodec_walk_prefix(t_ecodec *x, t_floatarg fi)
{
    char pfx[512]; uri_prefix((int)fi, pfx, sizeof(pfx));
    t_atom a; SETSYMBOL(&a, gensym(pfx));
    outlet_anything(x->x_out, gensym("prefix"), 1, &a);
}

static const char *store_entity_type(const char *path);   /* fwd (store, below) */

/* [tree_get <path>( — output [treetype <type>( — the walk's per-prefix probe.
 * The type comes from the STORE (manifest `system/handler` entities at pattern
 * paths, §6.2/§6.6) so runtime-REGISTERED handlers resolve identically to the
 * bootstrap five (§6.13(a) dispatch uniformity); "none" when unbound. */
static void ecodec_tree_get(t_ecodec *x, t_symbol *s)
{
    const char *type = store_entity_type(s->s_name);
    t_atom a; SETSYMBOL(&a, gensym(type ? type : "none"));
    outlet_anything(x->x_out, gensym("treetype"), 1, &a);
}

/* ── minimal entity store + native type renderer + §6.3 system/tree:get ────────
 * The store holds the 14-type bootstrap floor (ENTITY-NATIVE-TYPE-SYSTEM §4.4 /
 * §11.2 — the MUST-populate-at-startup set): the 8 primitives, `system/hash`, the
 * two meta-types (`system/type`, `system/type/field-spec`), the three string-
 * address types (`system/tree/path`, `system/type/name`, `system/identity/peer-id`)
 * and the structural root `entity` (§3.1.1). Each is a `{type:"system/type", data:
 * {...}}` entity bound at `system/type/{name}` (§11.1). RENDERED NATIVELY (the
 * durable keystone lesson) — a data table of type definitions + one canonical
 * encoder, NOT hand-emitted bytes — so the oracle's per-type `_match` probe is the
 * byte-exact drift target (§12.3: our canonical CBOR must hash-match Go's). Adding a
 * type is a table row, not new code. The rest of the 53+ core/protocol/supporting
 * types (§8/§9/§10) are further mechanical rows (A-PD-006). */

/* A field-spec value node (§4.2). Exactly one of type_ref/array_of/map_of/union_of
 * is the primary; key_type/optional/byte_size are modifiers. (type_param/default/
 * type_args are unused as VALUES anywhere in the core floor — they appear only as
 * field NAMES of system/type/field-spec, whose values are plain specs — so they are
 * intentionally omitted here; add on demand.) */
typedef struct fspec {
    const char        *type_ref;   /* primary: reference a type by name */
    const struct fspec *array_of;  /* primary: array element spec */
    const struct fspec *map_of;    /* primary: map value spec */
    const struct fspec *const *union_of; /* primary: NULL-terminated variant specs */
    const char        *key_type;   /* modifier: map key type (with map_of), NULL = default string */
    int                optional;   /* modifier */
    int                byte_size;  /* modifier: fixed width in a layout, -1 = absent */
} fspec;
#define FS(...)  (&(const fspec){ .byte_size = -1, __VA_ARGS__ })

typedef struct { const char *name; const fspec *spec; } field_t;
typedef struct {
    const char        *tree_path;  /* binding: system/type/{name} (§11.1) */
    const char        *name;       /* the type name (data.name) */
    const char        *extends;    /* data.extends, or NULL */
    const field_t     *fields;     /* data.fields entries, or NULL */
    int                nfields;
    const char *const *layout;     /* data.layout (NULL-terminated), or NULL */
    int                empty_fields;/* 1 = emit `fields` as an empty map (e.g. deletion-marker) */
} typedef_t;

/* Emit one field-spec as a canonical CBOR map. Present keys are emitted in the fixed
 * length-then-lex order of the whole possible key set (map_of(6) < array_of(8) <
 * key_type(8) < optional(8) < type_ref(8) < union_of(8) < byte_size(9)), so any
 * present subset stays canonical (§1.3). */
static int emit_fspec(wbuf *w, const fspec *f)
{
    int nu = 0; if (f->union_of) while (f->union_of[nu]) nu++;
    int n = (f->map_of ? 1 : 0) + (f->array_of ? 1 : 0) + (f->key_type ? 1 : 0)
          + (f->optional ? 1 : 0) + (f->type_ref ? 1 : 0) + (f->union_of ? 1 : 0)
          + (f->byte_size >= 0 ? 1 : 0);
    if (wb_head(w, 5, n)) return -1;
    if (f->map_of   && (wb_text(w, "map_of")   || emit_fspec(w, f->map_of)))    return -1;
    if (f->array_of && (wb_text(w, "array_of") || emit_fspec(w, f->array_of)))  return -1;
    if (f->key_type && (wb_text(w, "key_type") || wb_text(w, f->key_type)))     return -1;
    if (f->optional && (wb_text(w, "optional") || wb_byte(w, 0xf5)))            return -1;  /* true */
    if (f->type_ref && (wb_text(w, "type_ref") || wb_text(w, f->type_ref)))     return -1;
    if (f->union_of) {
        if (wb_text(w, "union_of") || wb_head(w, 4, (uint64_t)nu)) return -1;
        for (int i = 0; i < nu; i++) if (emit_fspec(w, f->union_of[i])) return -1;
    }
    if (f->byte_size >= 0 && (wb_text(w, "byte_size") || wb_head(w, 0, (uint64_t)f->byte_size))) return -1;
    return 0;
}

static int field_name_cmp(const void *a, const void *b)
{
    const field_t *fa = *(const field_t *const *)a, *fb = *(const field_t *const *)b;
    size_t la = strlen(fa->name), lb = strlen(fb->name);
    if (la != lb) return la < lb ? -1 : 1;
    return strcmp(fa->name, fb->name);
}

/* Emit the `fields` map: field names sorted length-then-lex, each value a field-spec. */
static int emit_fields(wbuf *w, const field_t *f, int n)
{
    const field_t *ord[32];
    if (n > 32) return -1;
    for (int i = 0; i < n; i++) ord[i] = &f[i];
    qsort(ord, n, sizeof ord[0], field_name_cmp);
    if (wb_head(w, 5, n)) return -1;
    for (int i = 0; i < n; i++)
        if (wb_text(w, ord[i]->name) || emit_fspec(w, ord[i]->spec)) return -1;
    return 0;
}

/* Emit a `layout` array (array of field-name text strings, declaration order). */
static int emit_strarr(wbuf *w, const char *const *a)
{
    int n = 0; while (a[n]) n++;
    if (wb_head(w, 4, n)) return -1;
    for (int i = 0; i < n; i++) if (wb_text(w, a[i])) return -1;
    return 0;
}

/* Emit a type entity's `data` map: {name, fields?, layout?, extends?} in canonical
 * key order (name(4) < fields(6) < layout(6) < extends(7)). */
static int emit_typedef_data(wbuf *w, const typedef_t *t)
{
    int has_fields = (t->fields != NULL) || t->empty_fields;
    int n = 1 + (has_fields ? 1 : 0) + (t->layout ? 1 : 0) + (t->extends ? 1 : 0);
    if (wb_head(w, 5, n)) return -1;
    if (wb_text(w, "name")    || wb_text(w, t->name))                          return -1;
    if (has_fields && (wb_text(w, "fields")  || emit_fields(w, t->fields, t->nfields))) return -1;
    if (t->layout  && (wb_text(w, "layout")  || emit_strarr(w, t->layout)))    return -1;
    if (t->extends && (wb_text(w, "extends") || wb_text(w, t->extends)))       return -1;
    return 0;
}

/* Reusable field-spec shapes referenced across the meta-types' `fields`. */
#define REF(t)        FS(.type_ref = (t))
#define OPTREF(t)     FS(.type_ref = (t), .optional = 1)
#define OPTMAP(t)     FS(.map_of = REF(t), .optional = 1)
#define OPTARR(t)     FS(.array_of = REF(t), .optional = 1)

/* system/type (§4.1) — the self-defining meta-type. */
static const field_t g_f_type[] = {
    { "name",        REF("system/type/name") },
    { "extends",     OPTREF("system/type/name") },
    { "fields",      OPTMAP("system/type/field-spec") },
    { "layout",      OPTARR("primitive/string") },
    { "type_params", OPTARR("primitive/string") },
    { "type_args",   OPTMAP("system/type/name") },
};
/* system/type/field-spec (§4.2) — the shape of a single field. */
static const field_t g_f_fspec[] = {
    { "type_ref",   OPTREF("system/type/name") },
    { "optional",   OPTREF("primitive/bool") },
    { "array_of",   OPTREF("system/type/field-spec") },
    { "map_of",     OPTREF("system/type/field-spec") },
    { "union_of",   OPTARR("system/type/field-spec") },
    { "type_param", OPTREF("primitive/string") },
    { "type_args",  OPTMAP("system/type/name") },
    { "default",    OPTREF("primitive/any") },
    { "key_type",   OPTREF("system/type/name") },
    { "byte_size",  OPTREF("primitive/uint") },
};
/* system/hash (§4.5) — flat byte string: format_code || digest. */
static const field_t g_f_hash[] = {
    { "format_code", FS(.type_ref = "primitive/uint", .byte_size = 1) },
    { "digest",      REF("primitive/bytes") },
};
static const char *const g_l_hash[] = { "format_code", "digest", NULL };
/* entity (§3.1.1) — the abstract structural root {type, data}. */
static const field_t g_f_entity[] = {
    { "type", REF("primitive/string") },
    { "data", REF("primitive/any") },
};

/* Non-optional map/array field-spec shapes. */
#define MAP(t)  FS(.map_of = REF(t))
#define ARR(t)  FS(.array_of = REF(t))

/* ── Core entity types (§8) ─────────────────────────────────────────────── */
static const field_t g_f_core_entity[] = {
    { "type", REF("primitive/string") }, { "data", REF("primitive/any") },
    { "content_hash", REF("system/hash") },
};
static const field_t g_f_core_envelope[] = {
    { "root", REF("core/entity") },
    { "included", FS(.map_of = REF("core/entity"), .key_type = "system/hash", .optional = 1) },
};

/* ── Protocol types (§9 / Appendix B) ───────────────────────────────────── */
static const field_t g_f_hello[] = {
    { "peer_id", REF("system/peer-id") }, { "nonce", REF("primitive/bytes") },
    { "protocols", ARR("primitive/string") }, { "timestamp", REF("primitive/uint") },
    { "hash_formats", OPTARR("primitive/string") }, { "key_types", OPTARR("primitive/string") },
    { "compression", OPTARR("primitive/string") }, { "encryption", OPTARR("primitive/string") },
};
static const field_t g_f_authenticate[] = {
    { "peer_id", REF("system/peer-id") }, { "public_key", REF("primitive/bytes") },
    { "key_type", REF("primitive/string") }, { "nonce", REF("primitive/bytes") },
};
static const field_t g_f_restarget[] = {
    { "targets", ARR("system/tree/path") }, { "exclude", OPTARR("system/tree/path") },
};
static const field_t g_f_execute[] = {
    { "request_id", REF("primitive/string") }, { "uri", REF("system/tree/path") },
    { "operation", REF("primitive/string") },
    { "resource", OPTREF("system/protocol/resource-target") }, { "params", REF("core/entity") },
    { "bounds", OPTREF("system/bounds") }, { "deliver_to", OPTREF("system/delivery-spec") },
    { "author", OPTREF("system/hash") }, { "capability", OPTREF("system/hash") },
};
static const field_t g_f_exec_response[] = {
    { "request_id", REF("primitive/string") }, { "status", REF("primitive/uint") },
    { "result", REF("core/entity") }, { "budget_consumed", OPTREF("primitive/uint") },
};
static const field_t g_f_error[] = {
    { "code", REF("primitive/string") }, { "message", OPTREF("primitive/string") },
};

/* ── Capability types (§9.7–9.13 / §3.6) ────────────────────────────────── */
static const field_t g_f_cap_grant[]    = { { "token", REF("system/hash") } };
static const field_t g_f_path_scope[]   = {
    { "include", ARR("system/tree/path") }, { "exclude", OPTARR("system/tree/path") },
};
static const field_t g_f_id_scope[]     = {
    { "include", ARR("primitive/string") }, { "exclude", OPTARR("primitive/string") },
};
static const field_t g_f_grant_entry[]  = {
    { "handlers", REF("system/capability/path-scope") },
    { "resources", REF("system/capability/path-scope") },
    { "operations", REF("system/capability/id-scope") },
    { "peers", OPTREF("system/capability/id-scope") }, { "constraints", OPTREF("primitive/any") },
};
static const field_t g_f_caveats[]      = {
    { "no_delegation", OPTREF("primitive/bool") },
    { "max_delegation_depth", OPTREF("primitive/uint") },
    { "max_delegation_ttl", OPTREF("primitive/uint") },
};
static const field_t g_f_multi_granter[] = {
    { "signers", ARR("system/hash") }, { "threshold", REF("primitive/uint") },
};
/* token.granter is polymorphic (§3.6): single system/hash OR a multi-granter. */
static const fspec *const g_u_granter[] = {
    REF("system/hash"), REF("system/capability/multi-granter"), NULL,
};
static const field_t g_f_cap_token[]    = {
    { "grants", ARR("system/capability/grant-entry") },
    { "granter", FS(.union_of = g_u_granter) }, { "grantee", REF("system/hash") },
    { "parent", OPTREF("system/hash") }, { "created_at", REF("primitive/uint") },
    { "expires_at", OPTREF("primitive/uint") }, { "not_before", OPTREF("primitive/uint") },
    { "delegation_caveats", OPTREF("system/capability/delegation-caveats") },
    { "resource_limits", OPTREF("system/resource-limits") },
};
static const field_t g_f_cap_request[]  = {
    { "grants", ARR("system/capability/grant-entry") }, { "ttl_ms", OPTREF("primitive/uint") },
};
static const field_t g_f_revoke_req[]   = {
    { "token", REF("system/hash") }, { "reason", OPTREF("primitive/string") },
};
static const field_t g_f_revocation[]   = {
    { "token", REF("system/hash") }, { "reason", OPTREF("primitive/string") },
    { "revoked_at", REF("primitive/uint") },
};
static const field_t g_f_delegate_req[] = {
    { "parent", REF("system/hash") }, { "grants", ARR("system/capability/grant-entry") },
    { "ttl_ms", OPTREF("primitive/uint") },
};
static const field_t g_f_policy_entry[] = {
    { "peer_pattern", REF("primitive/string") },
    { "grants", ARR("system/capability/grant-entry") },
    { "ttl_ms", OPTREF("primitive/uint") }, { "notes", OPTREF("primitive/string") },
};

/* ── Supporting types (§10 / §3.7) ──────────────────────────────────────── */
static const field_t g_f_peer[] = {
    { "peer_id", REF("system/peer-id") }, { "public_key", REF("primitive/bytes") },
    { "key_type", REF("primitive/string") },
};
static const field_t g_f_signature[] = {
    { "target", REF("system/hash") }, { "signer", REF("system/hash") },
    { "algorithm", REF("primitive/string") }, { "signature", REF("primitive/bytes") },
};
/* system/handler (§3.7 dispatch target) — interface ref + private scope config. */
static const field_t g_f_handler[] = {
    { "interface", REF("system/tree/path") },
    { "max_scope", OPTARR("system/capability/grant-entry") },
    { "internal_scope", OPTARR("system/capability/grant-entry") },
    { "expression_path", OPTREF("system/tree/path") },
};
static const field_t g_f_handler_manifest[] = {
    { "pattern", REF("system/tree/path") }, { "name", REF("primitive/string") },
    { "operations", MAP("system/handler/operation-spec") },
    { "max_scope", OPTARR("system/capability/grant-entry") },
    { "internal_scope", OPTARR("system/capability/grant-entry") },
    { "expression_path", OPTREF("system/tree/path") },
};
static const field_t g_f_op_spec[] = {
    { "input_type", OPTREF("system/type/name") }, { "output_type", OPTREF("system/type/name") },
};
static const field_t g_f_handler_iface[] = {
    { "pattern", REF("system/tree/path") }, { "name", REF("primitive/string") },
    { "operations", MAP("system/handler/operation-spec") },
};
static const field_t g_f_register_req[] = {
    { "manifest", REF("system/handler/manifest") },
    { "types", OPTMAP("system/type") },
    { "requested_scope", OPTARR("system/capability/grant-entry") },
};
static const field_t g_f_register_res[] = {
    { "pattern", REF("system/tree/path") }, { "grant", REF("system/capability/token") },
};
static const field_t g_f_bounds[] = {
    { "ttl", OPTREF("primitive/uint") }, { "budget", OPTREF("primitive/uint") },
    { "chain_id", OPTREF("primitive/string") }, { "visited", OPTARR("system/tree/path") },
};
static const field_t g_f_delivery[] = {
    { "uri", REF("system/tree/path") }, { "operation", OPTREF("primitive/string") },
};
static const field_t g_f_res_limits[] = {
    { "max_budget", OPTREF("primitive/uint") }, { "max_ttl", OPTREF("primitive/uint") },
    { "max_visited_length", OPTREF("primitive/uint") },
};

/* ── Tree types (§10.9) ─────────────────────────────────────────────────── */
static const field_t g_f_listing_entry[] = {
    { "hash", OPTREF("system/hash") }, { "has_children", REF("primitive/bool") },
};
static const field_t g_f_listing[] = {
    { "path", REF("system/tree/path") }, { "entries", MAP("system/tree/listing-entry") },
    { "count", REF("primitive/uint") }, { "offset", REF("primitive/uint") },
    { "next_page", OPTREF("system/hash") },
};
static const field_t g_f_get_req[] = {
    { "tree_id", OPTREF("primitive/string") }, { "mode", OPTREF("primitive/string") },
    { "limit", OPTREF("primitive/uint") }, { "offset", OPTREF("primitive/uint") },
};
static const field_t g_f_put_req[] = {
    { "entity", OPTREF("primitive/any") }, { "tree_id", OPTREF("primitive/string") },
};

/* ── Types-handler types (§9.4 / App B) ─────────────────────────────────── */
static const field_t g_f_validate_req[] = {
    { "entity", REF("core/entity") }, { "type_name", REF("system/type/name") },
};
static const field_t g_f_validate_res[] = {
    { "valid", REF("primitive/bool") }, { "errors", OPTARR("primitive/string") },
};

#define NF(a)   (int)(sizeof(a) / sizeof((a)[0]))
#define PRIM(x) { "system/type/primitive/" x, "primitive/" x, NULL, NULL, 0, NULL, 0 }
#define TF(nm, tbl) { "system/type/" nm, nm, NULL, tbl, NF(tbl), NULL, 0 }
#define TE(nm, ext) { "system/type/" nm, nm, ext, NULL, 0, NULL, 0 }
static const typedef_t g_store[] = {
    /* 8 primitives (§3.2) — name-only, no fields/extends. */
    PRIM("any"), PRIM("bool"), PRIM("bytes"), PRIM("float"),
    PRIM("int"), PRIM("null"), PRIM("string"), PRIM("uint"),
    /* system/hash (§4.5) — carries a layout, so spelled out. */
    { "system/type/system/hash", "system/hash", "primitive/bytes", g_f_hash, NF(g_f_hash), g_l_hash, 0 },
    /* the two meta-types (§4.1/§4.2) */
    TF("system/type", g_f_type), TF("system/type/field-spec", g_f_fspec),
    /* the string-address types (§4.6/§4.7/§4.8) — extends primitive/string */
    TE("system/tree/path", "primitive/string"),
    TE("system/type/name", "primitive/string"),
    /* Peer-identity primitive under BOTH spec names — the spec is internally
     * inconsistent (A-PD-012): §4.4/§4.8 bootstrap it as `system/identity/peer-id`
     * (referenced at spec L639/L1082), while §10.1 `system/peer` + appendix
     * reference `system/peer-id` (L1453/L2399); the reference oracle's ratified-core
     * set carries only `system/peer-id`. Bind both so every spec `type_ref` resolves;
     * finding escalated to arch. */
    TE("system/identity/peer-id", "primitive/string"),
    TE("system/peer-id", "primitive/string"),
    /* the structural root (§3.1.1) */
    TF("entity", g_f_entity),

    /* ── the rest of the core type floor (§8/§9/§10) ── */
    /* core entity types (§8) */
    TF("core/entity", g_f_core_entity), TF("core/envelope", g_f_core_envelope),
    /* system/envelope is structurally system/protocol/envelope — extends core/envelope (§3.1). */
    TE("system/envelope", "core/envelope"),
    /* protocol types (§9) */
    TE("system/protocol/envelope", "core/envelope"),
    TF("system/protocol/connect/hello", g_f_hello),
    TF("system/protocol/connect/authenticate", g_f_authenticate),
    TF("system/protocol/resource-target", g_f_restarget),
    TF("system/protocol/execute", g_f_execute),
    TF("system/protocol/execute/response", g_f_exec_response),
    TF("system/protocol/error", g_f_error),
    /* capability types (§9.7–9.13 / §3.6) */
    TF("system/capability/grant", g_f_cap_grant),
    TF("system/capability/path-scope", g_f_path_scope),
    TF("system/capability/id-scope", g_f_id_scope),
    TF("system/capability/grant-entry", g_f_grant_entry),
    TF("system/capability/delegation-caveats", g_f_caveats),
    TF("system/capability/multi-granter", g_f_multi_granter),
    TF("system/capability/token", g_f_cap_token),
    TF("system/capability/request", g_f_cap_request),
    TF("system/capability/revoke-request", g_f_revoke_req),
    TF("system/capability/revocation", g_f_revocation),
    TF("system/capability/delegate-request", g_f_delegate_req),
    TF("system/capability/policy-entry", g_f_policy_entry),
    /* supporting types (§10 / §3.7) */
    TF("system/peer", g_f_peer),
    TF("system/signature", g_f_signature),
    TF("system/handler", g_f_handler),
    /* manifest extends interface (adds max_scope/internal_scope/expression_path). */
    { "system/type/system/handler/manifest", "system/handler/manifest", "system/handler/interface",
      g_f_handler_manifest, NF(g_f_handler_manifest), NULL, 0 },
    TF("system/handler/operation-spec", g_f_op_spec),
    TF("system/handler/interface", g_f_handler_iface),
    TF("system/handler/register-request", g_f_register_req),
    TF("system/handler/register-result", g_f_register_res),
    TF("system/bounds", g_f_bounds),
    TF("system/delivery-spec", g_f_delivery),
    TF("system/resource-limits", g_f_res_limits),
    /* tree types (§10.9) */
    TF("system/tree/listing-entry", g_f_listing_entry),
    TF("system/tree/listing", g_f_listing),
    TF("system/tree/get-request", g_f_get_req),
    TF("system/tree/put-request", g_f_put_req),
    /* types-handler types (§9.4) */
    TF("system/type/validate-request", g_f_validate_req),
    TF("system/type/validate-result", g_f_validate_res),
    /* deletion marker (§4.9) — a zero-field type: data = {name, fields:{}} */
    { "system/type/system/deletion-marker", "system/deletion-marker", NULL, NULL, 0, NULL, 1 },
};
static const int g_store_n = (int)(sizeof g_store / sizeof g_store[0]);

/* ── System handler interface entities (§3.7 / §6.2) ────────────────────────
 * Each core handler publishes a `system/handler/interface` entity at
 * `system/handler/{pattern}` (§6.2): the public contract {pattern, name,
 * operations}. `operations` maps op-name → {input_type?, output_type?}. Served
 * via tree:get; greens the `handlers` category's present/interface-type/
 * pattern/operations/io-type checks. */
typedef struct { const char *op, *in, *out; } op_t;   /* in/out NULL = absent */
typedef struct { const char *tree_path, *pattern, *name; const op_t *ops; int nops; } hiface_t;

static const op_t g_ops_tree[]    = {
    { "get", "system/tree/get-request", "core/entity" },
    { "put", "system/tree/put-request", "core/entity" },
};
static const op_t g_ops_type[]    = {
    { "validate", "system/type/validate-request", "system/type/validate-result" },
};
static const op_t g_ops_cap[]     = {
    { "request",   "system/capability/request",         "system/capability/grant" },
    { "revoke",    "system/capability/revoke-request",  NULL },
    { "configure", "system/capability/policy-entry",    NULL },
    { "delegate",  "system/capability/delegate-request","system/capability/grant" },
};
static const op_t g_ops_handler[] = {
    { "register",   "system/handler/register-request", "system/handler/register-result" },
    { "unregister", "system/handler/unregister-request", NULL },
};
static const op_t g_ops_connect[] = {
    { "hello",        "system/protocol/connect/hello",        NULL },
    { "authenticate", "system/protocol/connect/authenticate", NULL },
};
static const hiface_t g_handlers[] = {
    { "system/handler/system/tree",             "system/tree",             "tree",       g_ops_tree,    NF(g_ops_tree) },
    { "system/handler/system/type",             "system/type",             "type",       g_ops_type,    NF(g_ops_type) },
    { "system/handler/system/capability",       "system/capability",       "capability", g_ops_cap,     NF(g_ops_cap) },
    { "system/handler/system/handler",          "system/handler",          "handler",    g_ops_handler, NF(g_ops_handler) },
    { "system/handler/system/protocol/connect", "system/protocol/connect", "connect",    g_ops_connect, NF(g_ops_connect) },
};
static const int g_handlers_n = (int)(sizeof g_handlers / sizeof g_handlers[0]);

/* §7a conformance handlers (GUIDE-CONFORMANCE / cohort `--validate`, OFF by
 * default): system/validate/echo (result = request params) and
 * system/validate/dispatch-outbound (the §6.13(b)/§6.11 reentry relay). Visible
 * as resolvable handlers + interface entities only when EC_VALIDATE=1. */
static const op_t g_ops_vecho[] = { { "echo",     NULL, NULL } };
static const op_t g_ops_vdisp[] = { { "dispatch", NULL, NULL } };
static const hiface_t g_vhandlers[] = {
    { "system/handler/system/validate/echo",              "system/validate/echo",              "validate-echo",     g_ops_vecho, NF(g_ops_vecho) },
    { "system/handler/system/validate/dispatch-outbound", "system/validate/dispatch-outbound", "validate-dispatch", g_ops_vdisp, NF(g_ops_vdisp) },
};
static const int g_vhandlers_n = (int)(sizeof g_vhandlers / sizeof g_vhandlers[0]);

/* ── Dynamic entity store (tree:put / handler-register / revocations / policy) ──
 * The writable half of §1.7: a bind list keyed by canonical_key (bare-relative =
 * local namespace, "/{peer}/rest" = foreign). A dynamic bind SHADOWS the static
 * bootstrap tables; a tombstone (type == NULL) shadows a static binding with
 * "unbound". Entities are stored as verbatim canonical-CBOR data + type + the
 * §1.2 content_hash computed by OUR codec at bind time. */
typedef struct dent {
    char          *key;
    char          *type;            /* NULL = tombstone (path unbound) */
    unsigned char *data;            /* canonical CBOR of the entity's data value */
    size_t         dlen;
    unsigned char  hash[33];
    struct dent   *next;
} dent;
static dent *g_dstore = NULL;

static dent *dstore_find(const char *key)
{
    for (dent *d = g_dstore; d; d = d->next)
        if (!strcmp(d->key, key)) return d;
    return NULL;
}

/* Bind (or rebind) `key` to an entity {type, data}. Computes the content hash.
 * Passing type == NULL writes a tombstone (unbind that also shadows statics). */
static int dstore_bind(const char *key, const char *type, const unsigned char *data, size_t dlen)
{
    dent *d = dstore_find(key);
    if (!d) {
        d = (dent *)calloc(1, sizeof *d);
        if (!d) return -1;
        d->key = strdup(key);
        if (!d->key) { free(d); return -1; }
        d->next = g_dstore; g_dstore = d;
    }
    free(d->type); free(d->data);
    d->type = NULL; d->data = NULL; d->dlen = 0;
    if (!type) return 0;                                   /* tombstone */
    d->type = strdup(type);
    d->data = (unsigned char *)malloc(dlen ? dlen : 1);
    if (!d->type || !d->data) { free(d->type); free(d->data); d->type = NULL; d->data = NULL; return -1; }
    memcpy(d->data, data, dlen);
    d->dlen = dlen;
    if (ec_entity_hash(type, d->data, d->dlen, d->hash)) { free(d->type); free(d->data); d->type = NULL; d->data = NULL; d->dlen = 0; return -1; }
    return 0;
}

/* Is the token at `h33` marked revoked (§5.2 step 4)? Markers are written by
 * system/capability:revoke at system/capability/revocations/{hex}. */
static int cap_revoked(const unsigned char h33[33])
{
    char key[128] = "system/capability/revocations/";
    char *p = key + strlen(key);
    for (int i = 0; i < 33; i++) { sprintf(p, "%02x", h33[i]); p += 2; }
    dent *d = dstore_find(key);
    return d && d->type != NULL;
}

/* Emit an operation-spec map {input_type?, output_type?} (canonical: input_type(10) < output_type(11)). */
static int emit_op_spec(wbuf *w, const op_t *o)
{
    int n = (o->in ? 1 : 0) + (o->out ? 1 : 0);
    if (wb_head(w, 5, n)) return -1;
    if (o->in  && (wb_text(w, "input_type")  || wb_text(w, o->in)))  return -1;
    if (o->out && (wb_text(w, "output_type") || wb_text(w, o->out))) return -1;
    return 0;
}
static int op_name_cmp(const void *a, const void *b)
{
    const op_t *oa = *(const op_t *const *)a, *ob = *(const op_t *const *)b;
    size_t la = strlen(oa->op), lb = strlen(ob->op);
    if (la != lb) return la < lb ? -1 : 1;
    return strcmp(oa->op, ob->op);
}
/* Emit a handler interface's data map {name, pattern, operations} (canonical: name(4) < pattern(7) < operations(10)). */
static int emit_hiface_data(wbuf *w, const hiface_t *h)
{
    if (wb_head(w, 5, 3)
        || wb_text(w, "name")    || wb_text(w, h->name)
        || wb_text(w, "pattern") || wb_text(w, h->pattern)
        || wb_text(w, "operations") || wb_head(w, 5, (uint64_t)h->nops)) return -1;
    const op_t *ord[16]; if (h->nops > 16) return -1;
    for (int i = 0; i < h->nops; i++) ord[i] = &h->ops[i];
    qsort(ord, h->nops, sizeof ord[0], op_name_cmp);
    for (int i = 0; i < h->nops; i++)
        if (wb_text(w, ord[i]->op) || emit_op_spec(w, ord[i])) return -1;
    return 0;
}

/* Look up the type definition bound at `path`, or NULL. */
static const typedef_t *store_lookup(const char *path)
{
    for (int i = 0; i < g_store_n; i++)
        if (!strcmp(path, g_store[i].tree_path)) return &g_store[i];
    return NULL;
}
static const hiface_t *hiface_lookup(const char *path)
{
    for (int i = 0; i < g_handlers_n; i++)
        if (!strcmp(path, g_handlers[i].tree_path)) return &g_handlers[i];
    if (validate_on())
        for (int i = 0; i < g_vhandlers_n; i++)
            if (!strcmp(path, g_vhandlers[i].tree_path)) return &g_vhandlers[i];
    return NULL;
}

/* The handler MANIFEST (dispatch target, §6.2/§6.6): a `system/handler` entity
 * bound at the bare PATTERN path (e.g. `system/tree`), whose `interface` field
 * links the discovery index at `system/handler/{pattern}`. Returns the hiface
 * row whose pattern == path, or NULL. */
static const hiface_t *hmanifest_lookup(const char *path)
{
    for (int i = 0; i < g_handlers_n; i++)
        if (!strcmp(path, g_handlers[i].pattern)) return &g_handlers[i];
    if (validate_on())
        for (int i = 0; i < g_vhandlers_n; i++)
            if (!strcmp(path, g_vhandlers[i].pattern)) return &g_vhandlers[i];
    return NULL;
}

/* Emit a handler manifest's data map {interface: "system/handler/{pattern}"}. */
static int emit_hmanifest_data(wbuf *w, const hiface_t *h)
{
    char iface[300];
    int m = snprintf(iface, sizeof iface, "system/handler/%s", h->pattern);
    if (m < 0 || (size_t)m >= sizeof iface) return -1;
    return wb_head(w, 5, 1) || wb_text(w, "interface") || wb_text(w, iface);
}

/* Combined STATIC path view (typedefs + interface index + manifest pattern
 * paths) for listing + has_children; dynamic keys are walked separately. */
static int all_paths_n(void)
{
    int n = g_store_n + 2 * g_handlers_n;
    if (validate_on()) n += 2 * g_vhandlers_n;
    return n;
}
static const char *all_path_at(int i)
{
    if (i < g_store_n) return g_store[i].tree_path;
    i -= g_store_n;
    if (i < g_handlers_n) return g_handlers[i].tree_path;
    i -= g_handlers_n;
    if (i < g_handlers_n) return g_handlers[i].pattern;
    i -= g_handlers_n;
    if (i < g_vhandlers_n) return g_vhandlers[i].tree_path;
    i -= g_vhandlers_n;
    return g_vhandlers[i].pattern;
}

/* Build the `data` map for the entity bound at store `path` (dynamic bind
 * SHADOWS the static bootstrap; a tombstone shadows it with "unbound"). A
 * g_store entry is a `system/type`; an interface-index entry is a
 * `system/handler/interface`; a pattern path is the `system/handler` manifest.
 * Returns the entity type via *type_out. */
static int store_entity_data(const char *path, wbuf *w, const char **type_out)
{
    const dent *d = dstore_find(path);
    if (d) {
        if (!d->type) return -1;                   /* tombstone: unbound */
        *type_out = d->type;
        return wb_raw(w, d->data, d->dlen);
    }
    const typedef_t *t = store_lookup(path);
    if (t) { *type_out = "system/type"; return emit_typedef_data(w, t); }
    const hiface_t *h = hiface_lookup(path);
    if (h) { *type_out = "system/handler/interface"; return emit_hiface_data(w, h); }
    const hiface_t *hm = hmanifest_lookup(path);
    if (hm) { *type_out = "system/handler"; return emit_hmanifest_data(w, hm); }
    return -1;
}

/* True iff `path` is an exact store binding (dynamic-first, tombstone-aware). */
static int store_has(const char *path)
{
    const dent *d = dstore_find(path);
    if (d) return d->type != NULL;
    return store_lookup(path) || hiface_lookup(path) || hmanifest_lookup(path) ? 1 : 0;
}

/* The entity TYPE bound at `path`, or NULL — the §6.6 walk's dispatch filter
 * (`entity.type == "system/handler"` finds handlers, dynamic ones included). */
static const char *store_entity_type(const char *path)
{
    const dent *d = dstore_find(path);
    if (d) return d->type;
    if (store_lookup(path))     return "system/type";
    if (hiface_lookup(path))    return "system/handler/interface";
    if (hmanifest_lookup(path)) return "system/handler";
    return NULL;
}

/* Read the first resource target (execute.data.resource.targets[0]) as a
 * CANONICAL store key into out[cap] (§1.4: local → bare-relative, foreign →
 * "/{peer}/rest" preserved). Returns 1 present, 0 absent, -1 MALFORMED (an
 * embedded NUL byte — the wire text length exceeds the C-string length — or a
 * leading '/' whose first segment is not a peer id). */
static int exec_resource_path(char *out, size_t cap)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd root, rdata, resfld, targets;
    if (!cbor_map_find(buf, len, 0, "root", &root)) return 0;
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) return 0;
    if (!cbor_map_find(buf, len, rdata.pos, "resource", &resfld)) return 0;
    if (!cbor_map_find(buf, len, resfld.pos, "targets", &targets)) return 0;
    cbor_rd tr = { buf, len, targets.pos }; int major; uint64_t n;
    if (cbor_head(&tr, &major, &n) != 0 || major != 4 || n < 1) return 0;
    char raw[512]; cbor_rd e = { buf, len, tr.pos };
    if (cbor_get_text(&e, raw, sizeof raw) != 0) return 0;
    {   /* embedded NUL: the wire text length exceeds the C-string length */
        cbor_rd tv = { buf, len, tr.pos }; int mj; uint64_t tn;
        if (cbor_head(&tv, &mj, &tn) == 0 && mj == 3 && (size_t)tn != strlen(raw)) return -1;
    }
    if (!canonical_key(raw, out, cap)) return -1;
    return 1;
}

/* §6.3 check_path_permission (defense-in-depth / listing filter): does the
 * caller's presented cap permit (operation, system/tree, path)? Reads the
 * request context (g_authz + g_rbuf) exactly as [authz_check_perm( does. When
 * there is no authz context (S3 offline harnesses), permission is not filtered. */
static int authz_path_permitted(const char *operation, const char *path)
{
    if (!g_authz.valid) return 1;
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd cap;
    if (!included_find(buf, len, g_authz.cap_h, &cap)) return 0;
    int granter_local = cap_granter_local(buf, len, &cap);
    ec_init_identity();
    /* Same request as [authz_check_perm(: target_peer comes from THIS request's
     * own dispatch URI (g_dec.uri), not from `path` (the tree path being tested). */
    char tpeer[128];
    extract_peer(g_dec.uri, g_peer_id, tpeer, sizeof tpeer);
    return cap_permits(buf, len, cap.pos, operation, "system/tree", path,
                       granter_local, g_peer_id, tpeer);
}

/* length-then-lex comparator (§1.3 canonical CBOR key order). */
static int lenlex_cmp(const void *a, const void *b)
{
    const char *sa = *(const char *const *)a, *sb = *(const char *const *)b;
    size_t la = strlen(sa), lb = strlen(sb);
    if (la != lb) return la < lb ? -1 : 1;
    return strcmp(sa, sb);
}

/* True iff some bound path (static or live dynamic) sits strictly under `full`. */
static int path_has_children(const char *full)
{
    size_t fl = strlen(full);
    for (int j = 0; j < all_paths_n(); j++)
        if (!strncmp(all_path_at(j), full, fl) && all_path_at(j)[fl] == '/') return 1;
    for (const dent *d = g_dstore; d; d = d->next)
        if (d->type && !strncmp(d->key, full, fl) && d->key[fl] == '/') return 1;
    return 0;
}

/* Collect one child segment into kids[] with dedup. */
#define LIST_MAX_KIDS 256
static void listing_add_kid(char kids[][128], int *nk, const char *rest, size_t seglen)
{
    if (seglen == 0 || seglen >= 128) return;
    for (int j = 0; j < *nk; j++)
        if (strlen(kids[j]) == seglen && !strncmp(kids[j], rest, seglen)) return;
    if (*nk < LIST_MAX_KIDS) { memcpy(kids[*nk], rest, seglen); kids[*nk][seglen] = '\0'; (*nk)++; }
}

/* Build a system/tree/listing for `prefix` (which ends in '/' or is empty): one
 * level of child names under the prefix — static bootstrap + dynamic binds —
 * each entry {hash?, has_children}. §6.3 filters applied: a tombstone hides a
 * binding, a `system/deletion-marker` leaf is omitted, and every entry is
 * checked against the caller's capability (check_path_permission) with denied
 * entries omitted and `count` reflecting the FILTERED set. */
static int build_listing_data(const char *prefix, wbuf *w)
{
    size_t pl = strlen(prefix);
    static char kids[LIST_MAX_KIDS][128]; int nk = 0;
    for (int i = 0; i < all_paths_n(); i++) {
        const char *p = all_path_at(i);
        if (strncmp(p, prefix, pl) != 0) continue;         /* under the prefix */
        const char *rest = p + pl;
        const char *slash = strchr(rest, '/');
        listing_add_kid(kids, &nk, rest, slash ? (size_t)(slash - rest) : strlen(rest));
    }
    for (const dent *d = g_dstore; d; d = d->next) {
        if (!d->type) continue;                            /* tombstone */
        if (strncmp(d->key, prefix, pl) != 0) continue;
        const char *rest = d->key + pl;
        const char *slash = strchr(rest, '/');
        listing_add_kid(kids, &nk, rest, slash ? (size_t)(slash - rest) : strlen(rest));
    }

    /* filter: capability scope + deletion-marker leaves + tombstoned exacts */
    int keep[LIST_MAX_KIDS]; int nkeep = 0;
    for (int i = 0; i < nk; i++) {
        char full[512];
        int m = snprintf(full, sizeof full, "%s%s", prefix, kids[i]);
        if (m < 0 || (size_t)m >= sizeof full) continue;
        int is_entity = store_has(full);
        int has_children = path_has_children(full);
        if (!is_entity && !has_children) continue;         /* fully tombstoned */
        if (is_entity && !has_children) {
            const char *et = store_entity_type(full);
            if (et && !strcmp(et, "system/deletion-marker")) continue;
        }
        if (!authz_path_permitted("get", full)) continue;  /* §6.3 listing filter */
        keep[nkeep++] = i;
    }
    const char *order[LIST_MAX_KIDS];
    for (int i = 0; i < nkeep; i++) order[i] = kids[keep[i]];
    qsort(order, nkeep, sizeof order[0], lenlex_cmp);

    /* data = {path, count, offset, entries} (length-then-lex: 4,5,6,7) */
    if (wb_head(w, 5, 4)
        || wb_text(w, "path")   || wb_text(w, prefix)
        || wb_text(w, "count")  || wb_head(w, 0, (uint64_t)nkeep)
        || wb_text(w, "offset") || wb_head(w, 0, 0)
        || wb_text(w, "entries")|| wb_head(w, 5, (uint64_t)nkeep)) return -1;
    for (int i = 0; i < nkeep; i++) {
        char full[512];
        int m = snprintf(full, sizeof full, "%s%s", prefix, order[i]);
        if (m < 0 || (size_t)m >= sizeof full) return -1;
        int is_entity = store_has(full);
        int has_children = path_has_children(full);
        if (wb_text(w, order[i])) return -1;
        /* entry = {hash?, has_children} (length-then-lex: hash(4) < has_children(12)) */
        if (wb_head(w, 5, is_entity ? 2 : 1)) return -1;
        if (is_entity) {
            wbuf ed = {0}; const char *etype; unsigned char h33[33];
            if (store_entity_data(full, &ed, &etype) || ec_entity_hash(etype, ed.p, ed.len, h33)) { free(ed.p); return -1; }
            free(ed.p);
            if (wb_text(w, "hash") || wb_bytes(w, h33, 33)) return -1;
        }
        if (wb_text(w, "has_children") || wb_byte(w, has_children ? 0xf5 : 0xf4)) return -1;  /* CBOR true/false */
    }
    return 0;
}

/* [dispatch_op( — emit the RESOLVED handler pattern + the verified operation as
 * [dispatch_op <pattern> <operation>( so the canvas dispatch SPINE can select
 * the handler body FIRST (pattern → named unit) and switch on the op WITHIN it
 * (the FLOW-DESIGN spine: a flat op-switch conflates handlers — a `get` on
 * system/validate/echo must NOT reach the tree body). */
static void ecodec_dispatch_op(t_ecodec *x)
{
    const char *op = g_authz.valid && g_authz.operation[0] ? g_authz.operation : "none";
    const char *pat = g_resolved_handler[0] ? g_resolved_handler : "none";
    t_atom a[2];
    SETSYMBOL(&a[0], gensym(pat));
    SETSYMBOL(&a[1], gensym(op));
    outlet_anything(x->x_out, gensym("dispatch_op"), 2, a);
}

/* Locate the request's params entity (root.data.params) and its inner data map.
 * Returns 1 with *pent at the entity map and *pdata at its data value, else 0. */
static int exec_params_entity(cbor_rd *pent, cbor_rd *pdata)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd root, rdata;
    if (!cbor_map_find(buf, len, 0, "root", &root)) return 0;
    if (!cbor_map_find(buf, len, root.pos, "data", &rdata)) return 0;
    if (!cbor_map_find(buf, len, rdata.pos, "params", pent)) return 0;
    if (!cbor_map_find(buf, len, pent->pos, "data", pdata)) return 0;
    return 1;
}

/* Reject a malformed §2.6 path: literal empty segment ("//") and the relative
 * navigation segments "." / ".." (path traversal is not addressable — every
 * tree path is absolute-from-namespace-root). Applied to the CANONICAL key, so
 * a foreign "/{peer}/rest" key checks its rest segments the same way. */
static int path_shape_ok(const char *path)
{
    const char *p = path;
    if (p[0] == '/') {                                     /* foreign absolute key */
        const char *s = strchr(p + 1, '/');
        if (!s) return 0;
        p = s + 1;
    }
    if (strstr(p, "//")) return 0;
    const char *seg = p;
    for (;;) {
        const char *e = strchr(seg, '/');
        size_t sl = e ? (size_t)(e - seg) : strlen(seg);
        if ((sl == 1 && seg[0] == '.') || (sl == 2 && seg[0] == '.' && seg[1] == '.')) return 0;
        if (!e) break;
        seg = e + 1;
    }
    return 1;
}

/* [tree_get_serve( — §6.3 system/tree:get handler body (dispatched on the canvas
 * ALLOW path after perm_ok). Reads execute.resource; a trailing '/' (or empty) is
 * a listing request → 200 system/tree/listing; an exact path → 200 with the bound
 * entity (result = the entity) — or its content hash only under params
 * {mode:"hash"} — or 404 not_found if unbound. */
static void ecodec_tree_get_serve(t_ecodec *x)
{
    char path[512];
    int pr = exec_resource_path(path, sizeof path);
    if (pr == 0) { emit_error_response(x, 400, "bad_request"); return; }
    if (pr < 0 || !path_shape_ok(path)) { emit_error_response(x, 400, "invalid_path"); return; }
    size_t pl = strlen(path);
    if (pl == 0 || path[pl - 1] == '/') {
        wbuf ld = {0};
        if (build_listing_data(path, &ld)) { free(ld.p); emit_error_response(x, 500, "internal_error"); return; }
        emit_response_frame(x, 200, "system/tree/listing", ld.p, ld.len);
        free(ld.p);
        return;
    }
    if (store_has(path)) {
        wbuf ed = {0}; const char *etype;
        if (store_entity_data(path, &ed, &etype)) { free(ed.p); emit_error_response(x, 500, "internal_error"); return; }
        cbor_rd pent, pdata, modef; char mode[16] = "";
        if (exec_params_entity(&pent, &pdata)
            && cbor_map_find(g_rbuf, g_rbuf_len, pdata.pos, "mode", &modef)) {
            cbor_rd mv = { g_rbuf, g_rbuf_len, modef.pos };
            cbor_get_text(&mv, mode, sizeof mode);
        }
        if (!strcmp(mode, "hash")) {                        /* hash-only read */
            unsigned char h33[33]; wbuf hd = {0};
            int bad = ec_entity_hash(etype, ed.p, ed.len, h33)
                   || wb_head(&hd, 5, 1) || wb_text(&hd, "hash") || wb_bytes(&hd, h33, 33);
            free(ed.p);
            if (bad) { free(hd.p); emit_error_response(x, 500, "internal_error"); return; }
            emit_response_frame(x, 200, "system/hash", hd.p, hd.len);
            free(hd.p);
            return;
        }
        emit_response_frame(x, 200, etype, ed.p, ed.len);
        free(ed.p);
        return;
    }
    emit_error_response(x, 404, "not_found");
}

/* [tree_put_serve( — §6.3 system/tree:put handler body. params = system/tree/
 * put-request {entity?, expected_hash?}: entity present → verify/compute its
 * §1.2 content hash, bind at the canonical path (CAS against expected_hash when
 * given; the 33-byte zero hash asserts "expect absent" → 409 hash_mismatch on
 * violation) → 200 system/hash {hash}; entity absent → unbind the path (the
 * binding is removed; content GC is impl-defined) → 200 empty primitive/any. */
static void ecodec_tree_put_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    char path[512];
    int pr = exec_resource_path(path, sizeof path);
    if (pr == 0) { emit_error_response(x, 400, "ambiguous_resource"); return; }
    if (pr < 0 || !path_shape_ok(path) || !path[0] || path[strlen(path) - 1] == '/') {
        emit_error_response(x, 400, "invalid_path"); return;
    }
    if (!authz_path_permitted("put", path)) {              /* §6.3 check_path_permission */
        emit_error_response(x, 403, "capability_denied"); return;
    }

    cbor_rd pent, pdata;
    int have_params = exec_params_entity(&pent, &pdata);

    /* CAS precondition (expected_hash), evaluated against the CURRENT binding */
    if (have_params) {
        cbor_rd exf;
        if (cbor_map_find(buf, len, pdata.pos, "expected_hash", &exf)) {
            unsigned char exp[33]; size_t xl = 0;
            cbor_rd xv = { buf, len, exf.pos };
            if (cbor_get_bytes(&xv, exp, sizeof exp, &xl) != 0 || xl != 33) {
                emit_error_response(x, 400, "unexpected_params"); return;
            }
            int zero = 1; for (int i = 0; i < 33; i++) if (exp[i]) { zero = 0; break; }
            int have_current = store_has(path);
            int cas_ok;
            if (zero) cas_ok = !have_current;
            else if (!have_current) cas_ok = 0;
            else {
                wbuf ed = {0}; const char *etype; unsigned char cur[33];
                if (store_entity_data(path, &ed, &etype) || ec_entity_hash(etype, ed.p, ed.len, cur)) {
                    free(ed.p); emit_error_response(x, 500, "internal_error"); return;
                }
                free(ed.p);
                cas_ok = memcmp(cur, exp, 33) == 0;
            }
            if (!cas_ok) { emit_error_response(x, 409, "hash_mismatch"); return; }
        }
    }

    /* entity present → bind; absent → unbind (tombstone shadows the bootstrap) */
    cbor_rd entf;
    if (!have_params || !cbor_map_find(buf, len, pdata.pos, "entity", &entf)) {
        if (dstore_bind(path, NULL, NULL, 0)) { emit_error_response(x, 500, "internal_error"); return; }
        static const unsigned char empty_map = 0xa0;
        emit_response_frame(x, 200, "primitive/any", &empty_map, 1);
        return;
    }
    /* §6.3 put ADMISSION (normative, 0.8.2.11). `put` is a RECEIPT path: the
     * submitter authors the entity, the peer validates what it received (§1.8
     * item 1) and MUST NOT author a submitted entity's content_hash on the
     * submitter's behalf. Two ORDERED steps, and the order is a data dependency
     * rather than a choice -- step 2's inputs are exactly what step 1 establishes,
     * so a submission that is both malformed and mis-hashed is step 1's and
     * answers invalid_request.
     *   1. STRUCTURE -- a map with a non-empty text `type`, a PRESENT `data` (any
     *      CBOR value; null is legal), and a `content_hash` that is a well-formed
     *      system/hash whose total byte length matches its format code (§1.2).
     *      Any failure -> invalid_request; a well-formed hash naming a format code
     *      this peer cannot VERIFY is the separate §1.2 row ->
     *      unsupported_content_hash_format.
     *   2. HASH -- carried vs content_hash({type, data}) -> hash_mismatch.
     * Structural admission is not semantic validation: `data` is never checked
     * against the type named by `type`. */
    {   cbor_rd em = { buf, len, entf.pos }; int emaj; uint64_t earg;
        if (cbor_head(&em, &emaj, &earg) != 0 || emaj != 5) {
            emit_error_response(x, 400, "invalid_request"); return;
        } }
    cbor_rd etypef, edataf; char etype[128];
    if (!cbor_map_find(buf, len, entf.pos, "type", &etypef)) {
        emit_error_response(x, 400, "invalid_request"); return;
    }
    { cbor_rd tv = { buf, len, etypef.pos };
      if (cbor_get_text(&tv, etype, sizeof etype) != 0 || etype[0] == 0) {
          emit_error_response(x, 400, "invalid_request"); return; } }
    /* Presence, not truthiness: a CBOR null is a legal `data` payload and
     * cbor_map_find reports it found, which is the test §6.3 wants. */
    if (!cbor_map_find(buf, len, entf.pos, "data", &edataf)) {
        emit_error_response(x, 400, "invalid_request"); return;
    }
    const unsigned char *edp; size_t edl;
    if (cbor_value_slice(buf, len, edataf.pos, &edp, &edl) != 0) {
        emit_error_response(x, 400, "invalid_request"); return;
    }
    {   cbor_rd chf; unsigned char carried[128]; size_t chl = 0;
        /* 128 and NOT 33: `carried` only ever holds the 0x00 form (one varint byte plus
         * a 32-byte digest = 33), but sizing the READ buffer to that answers
         * invalid_request for a well-formed hash that merely names a LONGER digest —
         * SHA-384's 0x01 form is 49 bytes — and §1.2 gives that its own row. The 33-byte
         * bound is re-established below by `chl != i + 32` on the only format code this
         * peer verifies. */
        if (!cbor_map_find(buf, len, entf.pos, "content_hash", &chf)) {
            emit_error_response(x, 400, "invalid_request"); return;
        }
        { cbor_rd cv = { buf, len, chf.pos };
          if (cbor_get_bytes(&cv, carried, sizeof carried, &chl) != 0 || chl == 0) {
              emit_error_response(x, 400, "invalid_request"); return; } }
        /* leading multicodec LEB128 format-code varint (§7.3) */
        uint64_t fmt = 0; unsigned shift = 0; size_t i = 0; int done = 0;
        while (i < chl) { unsigned char b = carried[i++];
            fmt |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) { done = 1; break; }
            shift += 7; if (shift >= 64) break; }
        if (!done) { emit_error_response(x, 400, "invalid_request"); return; }
        /* §1.2 / §4.7 row 5 -- well-formed, but this peer cannot interpret it.
         * NOT invalid_request: the shape is fine, the algorithm is what we lack.
         * ec_entity_hash computes the SHA-256 floor only. */
        if (fmt != 0) { emit_error_response(x, 400, "unsupported_content_hash_format"); return; }
        if (chl != i + 32) { emit_error_response(x, 400, "invalid_request"); return; }
        unsigned char computed[33];
        if (ec_entity_hash(etype, edp, edl, computed)) {
            emit_error_response(x, 500, "internal_error"); return;
        }
        if (memcmp(computed, carried, 33) != 0) {
            emit_error_response(x, 400, "hash_mismatch"); return;
        }
    }
    if (dstore_bind(path, etype, edp, edl)) { emit_error_response(x, 500, "internal_error"); return; }

    /* result = system/hash {hash: content_hash(entity)} */
    {
        const dent *d = dstore_find(path);
        wbuf hd = {0};
        int bad = !d || wb_head(&hd, 5, 1) || wb_text(&hd, "hash") || wb_bytes(&hd, d->hash, 33);
        if (bad) { free(hd.p); emit_error_response(x, 500, "internal_error"); return; }
        emit_response_frame(x, 200, "system/hash", hd.p, hd.len);
        free(hd.p);
    }
}

/* §6.2 subset validation: every (operation, handler, resource) triple the request
 * asks for MUST be permitted by the caller's presented cap (no scope widening).
 * Returns 1 if the requested grants are within the caller's authority, 0 if any
 * triple exceeds it. Reuses cap_permits over the caller's cap grants. Self-check:
 * this is the LOCAL system/capability:request|delegate mint path (§6.2), not a
 * dispatch against a foreign URI, so target_peer is trivially local (g_peer_id) —
 * unlike the dispatch-time call sites, there is no execute.data.uri here to
 * extract_peer from. (The requested grant's OWN `peers` dimension, if any, is a
 * separate subset question this pointwise op×handler×resource walk does not
 * cover — see rust's `grant_subset`, which additionally subset-checks
 * `child.peers` against `parent.peers`; out of scope for this fix, which is
 * about the CURRENT request's target-peer check, not mint-time peers-scope
 * narrowing of a NEW grant.) */
static int req_grants_within_cap(const unsigned char *buf, size_t len, size_t grants_pos, size_t caller_cap_pos)
{
    cbor_rd r = { buf, len, grants_pos }; int mj; uint64_t n;
    if (cbor_head(&r, &mj, &n) != 0 || mj != 4) return 0;
    for (uint64_t gi = 0; gi < n; gi++) {
        size_t ge = r.pos;
        cbor_rd sc, oinc, hinc, rinc;
        if (!cbor_map_find(buf, len, ge, "operations", &sc) || !cbor_map_find(buf, len, sc.pos, "include", &oinc)) return 0;
        if (!cbor_map_find(buf, len, ge, "handlers", &sc)   || !cbor_map_find(buf, len, sc.pos, "include", &hinc)) return 0;
        int has_res = cbor_map_find(buf, len, ge, "resources", &sc) && cbor_map_find(buf, len, sc.pos, "include", &rinc);
        cbor_rd orr = { buf, len, oinc.pos }; int omj; uint64_t on;
        if (cbor_head(&orr, &omj, &on) != 0 || omj != 4) return 0;
        for (uint64_t oi = 0; oi < on; oi++) {
            char op[128]; cbor_rd oe = { buf, len, orr.pos };
            if (cbor_get_text(&oe, op, sizeof op) != 0) return 0;
            cbor_rd hrr = { buf, len, hinc.pos }; int hmj; uint64_t hn;
            if (cbor_head(&hrr, &hmj, &hn) != 0 || hmj != 4) return 0;
            for (uint64_t hi = 0; hi < hn; hi++) {
                char h[256]; cbor_rd he = { buf, len, hrr.pos };
                if (cbor_get_text(&he, h, sizeof h) != 0) return 0;
                if (has_res) {
                    cbor_rd rrr = { buf, len, rinc.pos }; int rmj; uint64_t rn;
                    if (cbor_head(&rrr, &rmj, &rn) != 0 || rmj != 4) return 0;
                    if (rn == 0 && !cap_permits(buf, len, caller_cap_pos, op, h, NULL, 1, g_peer_id, g_peer_id)) return 0;
                    for (uint64_t ri = 0; ri < rn; ri++) {
                        char res[512]; cbor_rd re = { buf, len, rrr.pos };
                        if (cbor_get_text(&re, res, sizeof res) != 0) return 0;
                        if (!cap_permits(buf, len, caller_cap_pos, op, h, res, 1, g_peer_id, g_peer_id)) return 0;
                        if (cbor_skip(&rrr) != 0) return 0;
                    }
                } else if (!cap_permits(buf, len, caller_cap_pos, op, h, NULL, 1, g_peer_id, g_peer_id)) return 0;
                if (cbor_skip(&hrr) != 0) return 0;
            }
            if (cbor_skip(&orr) != 0) return 0;
        }
        if (cbor_skip(&r) != 0) return 0;
    }
    return 1;
}

/* [cap_request_serve( — §6.2 system/capability:request handler body (dispatched on
 * the canvas ALLOW path after perm_ok for op=request). Mints a self-attenuated grant:
 * reads the requested grant-entries from execute.params.data.grants and re-issues them
 * as a token signed by the local peer, granted to the authenticated caller (grantee =
 * request author). The echoed grants are ⊆ the requested set (equal), satisfying the
 * attenuation contract; peer-policy narrowing is a future refinement. Returns 200 +
 * system/capability/grant {token} with granter+token+signature in `included`. */
static void ecodec_cap_request_serve(t_ecodec *x)
{
    ec_init_identity();
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd root, rdata, params, pdata, grantsf;
    if (!cbor_map_find(buf, len, 0, "root", &root)
        || !cbor_map_find(buf, len, root.pos, "data", &rdata)
        || !cbor_map_find(buf, len, rdata.pos, "params", &params)
        || !cbor_map_find(buf, len, params.pos, "data", &pdata)
        || !cbor_map_find(buf, len, pdata.pos, "grants", &grantsf)) { emit_error_response(x, 400, "bad_request"); return; }
    const unsigned char *gptr; size_t glen;
    if (cbor_value_slice(buf, len, grantsf.pos, &gptr, &glen) != 0) { emit_error_response(x, 400, "bad_request"); return; }
    /* §6.2 no scope widening: the requested grants MUST be within the caller's cap. */
    { cbor_rd callercap;
      if (!included_find(buf, len, g_authz.cap_h, &callercap)
          || !req_grants_within_cap(buf, len, grantsf.pos, callercap.pos)) {
          emit_error_response(x, 403, "scope_exceeds_authority"); return; } }

    wbuf gpd = {0}, tokd = {0}, sigd = {0}, resd = {0};
    wbuf tok_ent = {0}, gp_ent = {0}, sig_ent = {0}, inc = {0};
    unsigned char granter_h[33], token_h[33], sig_h[33], sig[64];
    int bad = 1;

    /* granter peer {key_type, public_key} = this peer → granter_h */
    if (wb_head(&gpd, 5, 2) || wb_text(&gpd, "key_type") || wb_text(&gpd, "ed25519")
        || wb_text(&gpd, "public_key") || wb_bytes(&gpd, g_pub, EC_ED25519_PUB_LEN)) goto done;
    if (ec_entity_hash("system/peer", gpd.p, gpd.len, granter_h)) goto done;

    /* token {grants (echoed), grantee=author, granter=local, created_at[, expires_at]}
     *
     * §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
     * convert the duration term against that same instant -- a second wall_ms() here
     * would skew the emitted created_at from the expiry computed off it.
     *
     * Note what this is NOT: an authorization decision. An over-long ttl_ms from a
     * bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
     * non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
     * (parent: null), so §5.6's parent-child attenuation never reaches it; without this
     * clamp, temporal attenuation is the one dimension a requester could escape.
     *
     * Key order is length-then-lex over the encoded key bytes, so created_at(10)
     * precedes expires_at(10) on the byte-lexicographic tiebreak. */
    {
        uint64_t now = wall_ms();
        uint64_t ceiling = 0; int have_ceiling = 0;
        /* caller cap's ABSOLUTE expiry */
        { cbor_rd cc;
          if (included_find(buf, len, g_authz.cap_h, &cc)) {
              uint64_t ce = 0;
              if (entity_data_uint(buf, len, &cc, "expires_at", &ce) == 1) {
                  ceiling = ce; have_ceiling = 1;
              }
          } }
        /* request ttl_ms as a DURATION, converted against `now`. §5.6 rule 3: an
         * unrepresentable conversion is treated as ABSENT -- it MUST NOT wrap and MUST
         * NOT saturate, since saturation manufactures a finite bound no reader can
         * distinguish from a deliberate one. ttl_ms == 0 is NOT special-cased: it falls
         * out as `now`, which is what keeps it from collapsing into "no bound". */
        { cbor_rd tf; int major; uint64_t arg;
          if (cbor_map_find(buf, len, pdata.pos, "ttl_ms", &tf)
              && cbor_head(&tf, &major, &arg) == 0 && major == 0) {
              uint64_t sum = now + arg;
              if (sum >= now && (!have_ceiling || sum < ceiling)) {
                  ceiling = sum; have_ceiling = 1;
              }
          } }
        if (wb_head(&tokd, 5, (uint64_t)(have_ceiling ? 5 : 4))
            || wb_text(&tokd, "grants")     || wb_raw(&tokd, gptr, glen)
            || wb_text(&tokd, "grantee")    || wb_bytes(&tokd, g_authz.author_h, 33)
            || wb_text(&tokd, "granter")    || wb_bytes(&tokd, granter_h, 33)
            || wb_text(&tokd, "created_at") || wb_head(&tokd, 0, now)) goto done;
        if (have_ceiling
            && (wb_text(&tokd, "expires_at") || wb_head(&tokd, 0, ceiling))) goto done;
    }
    if (ec_entity_hash("system/capability/token", tokd.p, tokd.len, token_h)) goto done;

    /* sign token_h; signature {signer, target, algorithm, signature} → sig_h */
    if (ec_ed25519_sign(g_priv, token_h, 33, sig) != EC_OK) goto done;
    if (wb_head(&sigd, 5, 4)
        || wb_text(&sigd, "signer")    || wb_bytes(&sigd, granter_h, 33)
        || wb_text(&sigd, "target")    || wb_bytes(&sigd, token_h, 33)
        || wb_text(&sigd, "algorithm") || wb_text(&sigd, "ed25519")
        || wb_text(&sigd, "signature") || wb_bytes(&sigd, sig, 64)) goto done;
    if (ec_entity_hash("system/signature", sigd.p, sigd.len, sig_h)) goto done;

    if (wb_entity(&tok_ent, "system/capability/token", tokd.p, tokd.len, token_h)) goto done;
    if (wb_entity(&gp_ent,  "system/peer",             gpd.p,  gpd.len,  granter_h)) goto done;
    if (wb_entity(&sig_ent, "system/signature",        sigd.p, sigd.len, sig_h)) goto done;

    /* included {hash → entity} ×3, keys canonically sorted (33B byte-lex) */
    {
        const unsigned char *hs[3] = { token_h, granter_h, sig_h };
        const wbuf *es[3] = { &tok_ent, &gp_ent, &sig_ent };
        for (int i = 0; i < 3; i++) for (int j = i + 1; j < 3; j++)
            if (memcmp(hs[i], hs[j], 33) > 0) {
                const unsigned char *th = hs[i]; hs[i] = hs[j]; hs[j] = th;
                const wbuf *te = es[i]; es[i] = es[j]; es[j] = te;
            }
        if (wb_head(&inc, 5, 3)) goto done;
        for (int i = 0; i < 3; i++)
            if (wb_bytes(&inc, hs[i], 33) || wb_raw(&inc, es[i]->p, es[i]->len)) goto done;
    }
    if (wb_head(&resd, 5, 1) || wb_text(&resd, "token") || wb_bytes(&resd, token_h, 33)) goto done;
    bad = 0;
done:
    if (!bad) emit_response_frame_inc(x, 200, "system/capability/grant", resd.p, resd.len, inc.p, inc.len);
    else emit_error_response(x, 500, "internal_error");
    free(gpd.p); free(tokd.p); free(sigd.p); free(resd.p);
    free(tok_ent.p); free(gp_ent.p); free(sig_ent.p); free(inc.p);
}

/* lowercase hex of a 33-byte content hash into out[67]. */
static void hex33(const unsigned char h[33], char out[67])
{
    for (int i = 0; i < 33; i++) sprintf(out + 2 * i, "%02x", h[i]);
    out[66] = '\0';
}

/* Emit 200 + an EMPTY primitive/any result (the no-payload handler outcome). */
static void emit_ok_empty(t_ecodec *x)
{
    static const unsigned char empty_map = 0xa0;
    emit_response_frame(x, 200, "primitive/any", &empty_map, 1);
}

/* [cap_revoke_serve( — §6.2 system/capability:revoke: the universal single-token
 * kill switch. params.data.token (33B, non-zero) required → 400 unexpected_params
 * otherwise. Writes a system/capability/revocation marker at
 * system/capability/revocations/{hex} (the §5.2 step-4 is_revoked surface; inline
 * -returned tokens have no storage path to unbind). → 200 empty. */
static void ecodec_cap_revoke_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd pent, pdata, tokf;
    unsigned char tok[33]; size_t tl = 0;
    if (!exec_params_entity(&pent, &pdata)
        || !cbor_map_find(buf, len, pdata.pos, "token", &tokf)) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }
    { cbor_rd tv = { buf, len, tokf.pos };
      if (cbor_get_bytes(&tv, tok, sizeof tok, &tl) != 0 || tl != 33) {
          emit_error_response(x, 400, "unexpected_params"); return; } }
    { int zero = 1; for (int i = 0; i < 33; i++) if (tok[i]) { zero = 0; break; }
      if (zero) { emit_error_response(x, 400, "unexpected_params"); return; } }

    /* marker data {token, revoked_at} (canonical: token(5) < revoked_at(10)) */
    wbuf md = {0};
    uint64_t now = wall_ms();
    if (wb_head(&md, 5, 2)
        || wb_text(&md, "token")      || wb_bytes(&md, tok, 33)
        || wb_text(&md, "revoked_at") || wb_head(&md, 0, now)) {
        free(md.p); emit_error_response(x, 500, "internal_error"); return;
    }
    char key[128] = "system/capability/revocations/";
    hex33(tok, key + strlen(key));
    int bad = dstore_bind(key, "system/capability/revocation", md.p, md.len);
    free(md.p);
    if (bad) { emit_error_response(x, 500, "internal_error"); return; }
    emit_ok_empty(x);
}

/* [cap_configure_serve( — §6.2 system/capability:configure: write a policy entry
 * at system/capability/policy/{peer_pattern}. peer_pattern MUST be the literal
 * `default` or a full content-hash hex (66 lowercase hex chars) or a peer id —
 * partial prefixes are NOT valid (v7.63 F8) → 400 invalid_peer_pattern. The
 * params entity itself (system/capability/policy-entry) is what is bound. */
static void ecodec_cap_configure_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd pent, pdata, ppf;
    char pp[160];
    if (!exec_params_entity(&pent, &pdata)
        || !cbor_map_find(buf, len, pdata.pos, "peer_pattern", &ppf)) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }
    { cbor_rd pv = { buf, len, ppf.pos };
      if (cbor_get_text(&pv, pp, sizeof pp) != 0) { emit_error_response(x, 400, "unexpected_params"); return; } }
    int is_hex = strlen(pp) == 66;
    if (is_hex) for (const char *c = pp; *c; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) { is_hex = 0; break; }
    /* peer-id form: base58 alphabet (no 0OIl, no '*' or '/'), plausible length */
    int is_pid = strlen(pp) >= 32 && strlen(pp) < 128;
    if (is_pid) for (const char *c = pp; *c; c++) {
        if (!((*c >= '1' && *c <= '9') || (*c >= 'A' && *c <= 'H') || (*c >= 'J' && *c <= 'N')
              || (*c >= 'P' && *c <= 'Z') || (*c >= 'a' && *c <= 'k') || (*c >= 'm' && *c <= 'z'))) { is_pid = 0; break; }
    }
    if (!(strcmp(pp, "default") == 0 || is_hex || is_pid)) {
        emit_error_response(x, 400, "invalid_peer_pattern"); return;
    }
    /* bind the params entity (type + data verbatim) at the policy path */
    cbor_rd ptypef, pdataf; char ptype[128];
    const unsigned char *pdp; size_t pdl;
    if (!cbor_map_find(buf, len, pent.pos, "type", &ptypef)
        || !cbor_map_find(buf, len, pent.pos, "data", &pdataf)
        || cbor_value_slice(buf, len, pdataf.pos, &pdp, &pdl) != 0) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }
    { cbor_rd tv = { buf, len, ptypef.pos };
      if (cbor_get_text(&tv, ptype, sizeof ptype) != 0) { emit_error_response(x, 400, "unexpected_params"); return; } }
    char key[300];
    int m = snprintf(key, sizeof key, "system/capability/policy/%s", pp);
    if (m < 0 || (size_t)m >= sizeof key) { emit_error_response(x, 400, "invalid_peer_pattern"); return; }
    if (dstore_bind(key, ptype, pdp, pdl)) { emit_error_response(x, 500, "internal_error"); return; }
    emit_ok_empty(x);
}

/* [cap_delegate_serve( — §6.2 system/capability:delegate. SAME-PEER-ONLY in v1
 * (§2.6 F1): a remote caller (author != this peer) gets 501 unsupported_operation
 * BEFORE any params validation (shape-independent verdict). A local caller must
 * supply a non-zero params.data.parent (33B) → else 400 unexpected_params. (The
 * local mint path is unreachable over the wire — the oracle is always remote —
 * so delegation minting lands with a local-caller surface, not here.) */
static void ecodec_cap_delegate_serve(t_ecodec *x)
{
    unsigned char lp[33];
    if (!(g_authz.valid && local_peer_hash(lp) == 0 && memcmp(g_authz.author_h, lp, 33) == 0)) {
        emit_error_response(x, 501, "unsupported_operation"); return;
    }
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd pent, pdata, pf;
    unsigned char parent[33]; size_t pl = 0;
    if (!exec_params_entity(&pent, &pdata)
        || !cbor_map_find(buf, len, pdata.pos, "parent", &pf)) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }
    { cbor_rd pv = { buf, len, pf.pos };
      if (cbor_get_bytes(&pv, parent, sizeof parent, &pl) != 0 || pl != 33) {
          emit_error_response(x, 400, "unexpected_params"); return; } }
    { int zero = 1; for (int i = 0; i < 33; i++) if (parent[i]) { zero = 0; break; }
      if (zero) { emit_error_response(x, 400, "unexpected_params"); return; } }
    emit_error_response(x, 501, "unsupported_operation");
}

/* ── §7a conformance handler bodies (EC_VALIDATE) ─────────────────────────────── */

/* [echo_serve( — system/validate/echo: result = the request's params entity,
 * verbatim (type + data re-emitted; the hash recomputes identically). */
static void ecodec_echo_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    cbor_rd pent, pdata, ptypef;
    char ptype[128];
    const unsigned char *pdp; size_t pdl;
    if (!exec_params_entity(&pent, &pdata)
        || !cbor_map_find(buf, len, pent.pos, "type", &ptypef)
        || cbor_value_slice(buf, len, pdata.pos, &pdp, &pdl) != 0) {
        emit_error_response(x, 400, "invalid_params"); return;
    }
    { cbor_rd tv = { buf, len, ptypef.pos };
      if (cbor_get_text(&tv, ptype, sizeof ptype) != 0) { emit_error_response(x, 400, "invalid_params"); return; } }
    emit_response_frame(x, 200, ptype, pdp, pdl);
}

/* Slice an ENTITY-valued field of the params data map plus its content_hash.
 * Returns 0 with *ep/*el = the whole entity map bytes and h33 = its hash field. */
static int param_entity_slice(const unsigned char *buf, size_t len, size_t pdata_pos,
                              const char *field, const unsigned char **ep, size_t *el,
                              unsigned char h33[33])
{
    cbor_rd f, hf;
    if (!cbor_map_find(buf, len, pdata_pos, field, &f)) return -1;
    if (cbor_value_slice(buf, len, f.pos, ep, el) != 0) return -1;
    if (!cbor_map_find(buf, len, f.pos, "content_hash", &hf)) return -1;
    cbor_rd hv = { buf, len, hf.pos }; size_t hl = 0;
    if (cbor_get_bytes(&hv, h33, 33, &hl) != 0 || hl != 33) return -1;
    return 0;
}

/* [outbound_serve( — system/validate/dispatch-outbound: the §6.13(b)/§6.11
 * transport-reentry relay. params.data = {target, operation, value,
 * reentry_capability, reentry_granter, reentry_cap_signature}: originate an
 * EXECUTE back to the caller OVER THE SAME inbound connection (no fresh dial),
 * forwarding `value` VERBATIM as the downstream params data (the 7b matrix
 * ruling #2 — re-wrapping double-nests), signed by OUR identity under the
 * caller-minted reentry authority; await the response and return
 * {status, result} verbatim. No live seam / timeout → 503 no_outbound_seam.
 * Single-threaded substrate: the wait is a bounded synchronous read on the one
 * fd; frames that are not our response are appended to the connection's buffer
 * so the normal peel loop dispatches them after this request completes. */
static void ecodec_outbound_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    ec_init_identity();
    cbor_rd pent, pdata;
    if (!exec_params_entity(&pent, &pdata)) { emit_error_response(x, 400, "invalid_params"); return; }

    char target[256] = "", operation[64] = "";
    { cbor_rd f;
      if (cbor_map_find(buf, len, pdata.pos, "target", &f)) {
          cbor_rd v = { buf, len, f.pos }; cbor_get_text(&v, target, sizeof target); }
      if (cbor_map_find(buf, len, pdata.pos, "operation", &f)) {
          cbor_rd v = { buf, len, f.pos }; cbor_get_text(&v, operation, sizeof operation); } }
    const unsigned char *valp = NULL; size_t vall = 0;
    { cbor_rd f;
      if (cbor_map_find(buf, len, pdata.pos, "value", &f))
          cbor_value_slice(buf, len, f.pos, &valp, &vall); }
    const unsigned char *capp, *grp, *csp; size_t capl, grl, csl;
    unsigned char cap_h[33], gr_h[33], cs_h[33];
    if (!valp
        || param_entity_slice(buf, len, pdata.pos, "reentry_capability", &capp, &capl, cap_h)
        || param_entity_slice(buf, len, pdata.pos, "reentry_granter", &grp, &grl, gr_h)
        || param_entity_slice(buf, len, pdata.pos, "reentry_cap_signature", &csp, &csl, cs_h)) {
        emit_error_response(x, 400, "invalid_params"); return;
    }
    if (g_cur_fd < 0 || !g_cur_conn) { emit_error_response(x, 503, "no_outbound_seam"); return; }

    /* downstream params entity: primitive/any wrapping `value` verbatim */
    static int out_counter = 0;
    char rid[32]; snprintf(rid, sizeof rid, "out-%d", ++out_counter);
    unsigned char pv_h[33], exec_h[33], lp_h[33], gp_h[33], es_h[33], sig[64];
    wbuf pv_ent = {0}, execd = {0}, exec_ent = {0}, gpd = {0}, gp_ent = {0};
    wbuf esd = {0}, es_ent = {0}, envd = {0}, frame = {0};
    int bad = 1;

    if (ec_entity_hash("primitive/any", valp, vall, pv_h)) goto done;
    if (wb_entity(&pv_ent, "primitive/any", valp, vall, pv_h)) goto done;
    if (local_peer_hash(lp_h)) goto done;

    /* EXECUTE data {uri, author, params, resource, operation, capability,
     * request_id} in canonical length-then-lex order */
    if (wb_head(&execd, 5, 7)
        || wb_text(&execd, "uri")        || wb_text(&execd, target)
        || wb_text(&execd, "author")     || wb_bytes(&execd, lp_h, 33)
        || wb_text(&execd, "params")     || wb_raw(&execd, pv_ent.p, pv_ent.len)) goto done;
    {
        char rt[300];
        int m = snprintf(rt, sizeof rt, "system/handler/%s", target);
        if (m < 0 || (size_t)m >= sizeof rt) goto done;
        if (wb_text(&execd, "resource") || wb_head(&execd, 5, 1)
            || wb_text(&execd, "targets") || wb_head(&execd, 4, 1) || wb_text(&execd, rt)) goto done;
    }
    if (wb_text(&execd, "operation")  || wb_text(&execd, operation)
        || wb_text(&execd, "capability") || wb_bytes(&execd, cap_h, 33)
        || wb_text(&execd, "request_id") || wb_text(&execd, rid)) goto done;
    if (ec_entity_hash("system/protocol/execute", execd.p, execd.len, exec_h)) goto done;
    if (wb_entity(&exec_ent, "system/protocol/execute", execd.p, execd.len, exec_h)) goto done;

    /* our peer identity entity + the EXECUTE signature (author-signed, §5.8) */
    if (wb_head(&gpd, 5, 2) || wb_text(&gpd, "key_type") || wb_text(&gpd, "ed25519")
        || wb_text(&gpd, "public_key") || wb_bytes(&gpd, g_pub, EC_ED25519_PUB_LEN)) goto done;
    if (ec_entity_hash("system/peer", gpd.p, gpd.len, gp_h)) goto done;
    if (wb_entity(&gp_ent, "system/peer", gpd.p, gpd.len, gp_h)) goto done;
    if (ec_ed25519_sign(g_priv, exec_h, 33, sig) != EC_OK) goto done;
    if (wb_head(&esd, 5, 4)
        || wb_text(&esd, "signer")    || wb_bytes(&esd, lp_h, 33)
        || wb_text(&esd, "target")    || wb_bytes(&esd, exec_h, 33)
        || wb_text(&esd, "algorithm") || wb_text(&esd, "ed25519")
        || wb_text(&esd, "signature") || wb_bytes(&esd, sig, 64)) goto done;
    if (ec_entity_hash("system/signature", esd.p, esd.len, es_h)) goto done;
    if (wb_entity(&es_ent, "system/signature", esd.p, esd.len, es_h)) goto done;

    /* included ×5 (§5.8 authority chain travels with the request), keys sorted */
    {
        const unsigned char *hs[5] = { cap_h, gr_h, gp_h, cs_h, es_h };
        struct { const unsigned char *p; size_t len; } es[5] = {
            { capp, capl }, { grp, grl }, { gp_ent.p, gp_ent.len },
            { csp, csl }, { es_ent.p, es_ent.len }
        };
        for (int i = 0; i < 5; i++) for (int j = i + 1; j < 5; j++)
            if (memcmp(hs[i], hs[j], 33) > 0) {
                const unsigned char *th = hs[i]; hs[i] = hs[j]; hs[j] = th;
                size_t tl = es[i].len; const unsigned char *tp = es[i].p;
                es[i] = es[j]; es[j].p = tp; es[j].len = tl;
            }
        if (wb_head(&envd, 5, 2) || wb_text(&envd, "root") || wb_raw(&envd, exec_ent.p, exec_ent.len)
            || wb_text(&envd, "included") || wb_head(&envd, 5, 5)) goto done;
        for (int i = 0; i < 5; i++)
            if (wb_bytes(&envd, hs[i], 33) || wb_raw(&envd, es[i].p, es[i].len)) goto done;
    }
    {
        uint32_t n = (uint32_t)envd.len;
        if (wb_byte(&frame, (n >> 24) & 255) || wb_byte(&frame, (n >> 16) & 255)
            || wb_byte(&frame, (n >> 8) & 255) || wb_byte(&frame, n & 255)
            || wb_raw(&frame, envd.p, envd.len)) goto done;
    }
    bad = 0;
done:
    free(pv_ent.p); free(execd.p); free(gpd.p); free(esd.p); free(envd.p);
    if (bad) {
        free(exec_ent.p); free(gp_ent.p); free(es_ent.p); free(frame.p);
        emit_error_response(x, 500, "internal_error"); return;
    }
    conn_send_all(g_cur_fd, frame.p, frame.len);
    free(frame.p); free(exec_ent.p); free(gp_ent.p); free(es_ent.p);

    /* synchronous bounded wait for the correlated EXECUTE_RESPONSE */
    {
        int fd = g_cur_fd;
        ec_conn *c = g_cur_conn;
        wbuf acc = {0};
        double deadline = ec_now_ms() + 8000.0;
        uint64_t dstatus = 0;
        const unsigned char *dresp = NULL; size_t dresl = 0;   /* result entity slice */
        unsigned char *respbody = NULL;
        int got = 0;
        while (!got) {
            double left = deadline - ec_now_ms();
            if (left <= 0) break;
            struct pollfd pf = { fd, POLLIN, 0 };
            int pr = poll(&pf, 1, (int)left);
            if (pr <= 0) { if (pr < 0 && errno == EINTR) continue; break; }
            unsigned char tmp[65536];
            ssize_t r = recv(fd, tmp, sizeof tmp, 0);
            if (r == 0) break;
            if (r < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) continue; break; }
            if (wb_raw(&acc, tmp, (size_t)r)) break;
            while (acc.len >= 4) {
                uint32_t fl = ((uint32_t)acc.p[0] << 24) | ((uint32_t)acc.p[1] << 16)
                            | ((uint32_t)acc.p[2] << 8) | (uint32_t)acc.p[3];
                if (fl > (uint32_t)ECODEC_MAX_FRAME) { acc.len = 0; break; }
                if (acc.len < 4 + (size_t)fl) break;
                const unsigned char *body = acc.p + 4;
                cbor_rd root, rdat, ridf;
                char gotrid[64] = "";
                int is_ours = 0;
                if (cbor_map_find(body, fl, 0, "root", &root)
                    && entity_type_is(body, fl, &root, "system/protocol/execute/response")
                    && cbor_map_find(body, fl, root.pos, "data", &rdat)
                    && cbor_map_find(body, fl, rdat.pos, "request_id", &ridf)) {
                    cbor_rd rv = { body, fl, ridf.pos };
                    if (cbor_get_text(&rv, gotrid, sizeof gotrid) == 0 && !strcmp(gotrid, rid)) {
                        is_ours = 1;
                        map_uint(body, fl, rdat.pos, "status", &dstatus);
                        cbor_rd rf;
                        if (cbor_map_find(body, fl, rdat.pos, "result", &rf)) {
                            const unsigned char *rp; size_t rl;
                            if (cbor_value_slice(body, fl, rf.pos, &rp, &rl) == 0) {
                                respbody = (unsigned char *)malloc(rl ? rl : 1);
                                if (respbody) { memcpy(respbody, rp, rl); dresp = respbody; dresl = rl; }
                            }
                        }
                        got = 1;
                    }
                }
                if (!is_ours) {
                    /* not our response — hand the frame back to the connection's
                     * assembler; the peel loop dispatches it after this request */
                    size_t need = c->rlen + 4 + (size_t)fl;
                    if (need <= (size_t)ECODEC_MAX_FRAME + 4) {
                        if (need > c->rcap) {
                            unsigned char *nb = (unsigned char *)realloc(c->rbuf, need);
                            if (nb) { c->rbuf = nb; c->rcap = need; }
                        }
                        if (c->rcap >= need) {
                            memcpy(c->rbuf + c->rlen, acc.p, 4 + (size_t)fl);
                            c->rlen += 4 + (size_t)fl;
                        }
                    }
                }
                size_t consumed = 4 + (size_t)fl;
                memmove(acc.p, acc.p + consumed, acc.len - consumed);
                acc.len -= consumed;
            }
        }
        free(acc.p);
        if (!got) { free(respbody); emit_error_response(x, 503, "no_outbound_seam"); return; }

        /* our result: primitive/any {result: <downstream result, verbatim>, status} */
        wbuf rd = {0};
        static const unsigned char empty_map = 0xa0;
        int rbad = wb_head(&rd, 5, 2) || wb_text(&rd, "result");
        if (!rbad) rbad = dresp ? wb_raw(&rd, dresp, dresl) : wb_byte(&rd, 0xa0);
        if (!rbad) rbad = wb_text(&rd, "status") || wb_head(&rd, 0, dstatus);
        free(respbody);
        (void)empty_map;
        if (rbad) { free(rd.p); emit_error_response(x, 500, "internal_error"); return; }
        emit_response_frame(x, 200, "primitive/any", rd.p, rd.len);
        free(rd.p);
    }
}

/* ── §6.13(a) handlers handler: register / unregister ─────────────────────────── */

/* The install pattern off the resource target ("system/handler/{pattern}") into
 * out[cap]. Returns 0 ok, -1 no target, -2 wrong shape. */
static int register_pattern(char *out, size_t cap)
{
    char target[512];
    int pr = exec_resource_path(target, sizeof target);
    if (pr == 0) return -1;
    if (pr < 0) return -2;
    const char *prefix = "system/handler/";
    size_t pl = strlen(prefix);
    if (strncmp(target, prefix, pl) != 0 || strlen(target) == pl) return -2;
    size_t rl = strlen(target + pl);
    if (rl + 1 > cap) return -2;
    memcpy(out, target + pl, rl + 1);
    return 0;
}

/* §6.2: "system" itself or any "system/..." prefix is reserved for system
 * handlers; user-installed handlers MUST NOT register there. */
static int is_reserved_system_pattern(const char *pattern)
{
    return strcmp(pattern, "system") == 0 || strncmp(pattern, "system/", 7) == 0;
}

/* [handler_register_serve( — the five normative §6.13(a)/§6.2 register writes:
 * (1) the system/handler MANIFEST at the pattern path (dispatch target,
 * interface-linked); (2) associated types (none installed — register-request
 * carries none in the core probes); (3) the handler's self-issued signed grant
 * at system/capability/grants/{pattern}; (4) the grant-signature entity at
 * system/signature/{grant_hash} (§3.5 invariant pointer); (5) the
 * system/handler/interface entity at system/handler/{pattern}. → 200
 * system/handler/register-result {pattern}. */
static void ecodec_handler_register_serve(t_ecodec *x)
{
    const unsigned char *buf = g_rbuf; size_t len = g_rbuf_len;
    ec_init_identity();
    char pattern[256];
    int pr = register_pattern(pattern, sizeof pattern);
    if (pr == -1) { emit_error_response(x, 400, "ambiguous_resource"); return; }
    if (pr == -2) { emit_error_response(x, 400, "invalid_resource"); return; }
    /* §6.2: refuse before any of the five normative writes below. */
    if (is_reserved_system_pattern(pattern)) { emit_error_response(x, 403, "forbidden_pattern"); return; }

    cbor_rd pent, pdata, ptypef;
    char ptype[128] = "";
    if (!exec_params_entity(&pent, &pdata)
        || !cbor_map_find(buf, len, pent.pos, "type", &ptypef)) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }
    { cbor_rd tv = { buf, len, ptypef.pos }; cbor_get_text(&tv, ptype, sizeof ptype); }
    if (strcmp(ptype, "system/handler/register-request") != 0) {
        emit_error_response(x, 400, "unexpected_params"); return;
    }

    /* manifest {name?, operations?} (a plain map field of the request data) */
    cbor_rd manf; int have_man = cbor_map_find(buf, len, pdata.pos, "manifest", &manf);
    char name[128] = "";
    const unsigned char *opsp = NULL; size_t opsl = 0;
    if (have_man) {
        cbor_rd f;
        if (cbor_map_find(buf, len, manf.pos, "name", &f)) {
            cbor_rd v = { buf, len, f.pos }; cbor_get_text(&v, name, sizeof name);
        }
        if (cbor_map_find(buf, len, manf.pos, "operations", &f))
            cbor_value_slice(buf, len, f.pos, &opsp, &opsl);
    }
    if (!name[0]) snprintf(name, sizeof name, "%s", pattern);

    /* (1) manifest entity {interface} at the pattern path */
    {
        char iface[300]; wbuf hm = {0};
        int m = snprintf(iface, sizeof iface, "system/handler/%s", pattern);
        int bad = m < 0 || (size_t)m >= sizeof iface
               || wb_head(&hm, 5, 1) || wb_text(&hm, "interface") || wb_text(&hm, iface)
               || dstore_bind(pattern, "system/handler", hm.p, hm.len);
        free(hm.p);
        if (bad) { emit_error_response(x, 500, "internal_error"); return; }
    }
    /* (3)+(4) self-issued signed grant + §3.5 grant-signature */
    {
        const unsigned char *scp = NULL; size_t scl = 0;
        cbor_rd f;
        if (cbor_map_find(buf, len, pdata.pos, "requested_scope", &f))
            cbor_value_slice(buf, len, f.pos, &scp, &scl);
        unsigned char lp[33], tok_h[33], sg_h[33], sig[64];
        wbuf tokd = {0}, sigd = {0};
        static const unsigned char empty_arr = 0x80;
        if (local_peer_hash(lp)) { emit_error_response(x, 500, "internal_error"); return; }
        uint64_t now = wall_ms();
        int bad = wb_head(&tokd, 5, 4)
               || wb_text(&tokd, "grants");
        if (!bad) bad = scp ? wb_raw(&tokd, scp, scl) : wb_byte(&tokd, empty_arr);
        if (!bad) bad = wb_text(&tokd, "grantee")    || wb_bytes(&tokd, lp, 33)
                     || wb_text(&tokd, "granter")    || wb_bytes(&tokd, lp, 33)
                     || wb_text(&tokd, "created_at") || wb_head(&tokd, 0, now)
                     || ec_entity_hash("system/capability/token", tokd.p, tokd.len, tok_h)
                     || ec_ed25519_sign(g_priv, tok_h, 33, sig) != EC_OK
                     || wb_head(&sigd, 5, 4)
                     || wb_text(&sigd, "signer")    || wb_bytes(&sigd, lp, 33)
                     || wb_text(&sigd, "target")    || wb_bytes(&sigd, tok_h, 33)
                     || wb_text(&sigd, "algorithm") || wb_text(&sigd, "ed25519")
                     || wb_text(&sigd, "signature") || wb_bytes(&sigd, sig, 64)
                     || ec_entity_hash("system/signature", sigd.p, sigd.len, sg_h);
        if (!bad) {
            char gpath[400], spath[128] = "system/signature/";
            int m = snprintf(gpath, sizeof gpath, "system/capability/grants/%s", pattern);
            hex33(tok_h, spath + strlen(spath));
            bad = m < 0 || (size_t)m >= sizeof gpath
               || dstore_bind(gpath, "system/capability/token", tokd.p, tokd.len)
               || dstore_bind(spath, "system/signature", sigd.p, sigd.len);
        }
        free(tokd.p); free(sigd.p);
        if (bad) { emit_error_response(x, 500, "internal_error"); return; }
    }
    /* (5) interface entity {name, pattern, operations} at system/handler/{pattern} */
    {
        char ipath[300]; wbuf id = {0};
        static const unsigned char empty_map = 0xa0;
        int m = snprintf(ipath, sizeof ipath, "system/handler/%s", pattern);
        int bad = m < 0 || (size_t)m >= sizeof ipath
               || wb_head(&id, 5, 3)
               || wb_text(&id, "name")    || wb_text(&id, name)
               || wb_text(&id, "pattern") || wb_text(&id, pattern)
               || wb_text(&id, "operations");
        if (!bad) bad = opsp ? wb_raw(&id, opsp, opsl) : wb_byte(&id, empty_map);
        if (!bad) bad = dstore_bind(ipath, "system/handler/interface", id.p, id.len);
        free(id.p);
        if (bad) { emit_error_response(x, 500, "internal_error"); return; }
    }
    /* result: register-result {pattern} */
    {
        wbuf rd = {0};
        if (wb_head(&rd, 5, 1) || wb_text(&rd, "pattern") || wb_text(&rd, pattern)) {
            free(rd.p); emit_error_response(x, 500, "internal_error"); return;
        }
        emit_response_frame(x, 200, "system/handler/register-result", rd.p, rd.len);
        free(rd.p);
    }
}

/* [handler_unregister_serve( — reverses the five register writes: the grant (and
 * its §3.5 signature, located via the stored grant's hash), the pattern-path
 * manifest, and the interface index entry are all unbound. → 200 empty. */
static void ecodec_handler_unregister_serve(t_ecodec *x)
{
    char pattern[256];
    int pr = register_pattern(pattern, sizeof pattern);
    if (pr == -1) { emit_error_response(x, 400, "ambiguous_resource"); return; }
    if (pr == -2) { emit_error_response(x, 400, "invalid_resource"); return; }

    char gpath[400], ipath[300];
    snprintf(gpath, sizeof gpath, "system/capability/grants/%s", pattern);
    snprintf(ipath, sizeof ipath, "system/handler/%s", pattern);
    dent *g = dstore_find(gpath);
    if (g && g->type) {
        char spath[128] = "system/signature/";
        hex33(g->hash, spath + strlen(spath));
        dstore_bind(spath, NULL, NULL, 0);
    }
    dstore_bind(gpath, NULL, NULL, 0);
    dstore_bind(pattern, NULL, NULL, 0);
    dstore_bind(ipath, NULL, NULL, 0);
    emit_ok_empty(x);
}

/* ── §6.11 transport: listen / accept / per-connection read + frame assembly ──── */

static void listen_accept(void *z, int fd);   /* fwd */
static void conn_free(ec_conn *c);             /* fwd */

/* §4.10(c) idle-connection reaper (periodic, 500ms). Closes any connection open
 * longer than EC_IDLE_REAP_MS that has NEVER sent a byte — i.e. a connection-flood
 * socket that TCP-connected but never began a handshake. A legit peer sends `hello`
 * within milliseconds (got_data set on first recv) and is exempt. Reaping idle flood
 * sockets frees admission slots (conn_free re-arms accepting), so the peer stays
 * self-bounded AND keeps serving genuine follow-up connections. */
static void reap_tick(void *z)
{
    (void)z;
    double now = ec_now_ms();
    for (int i = g_nconn - 1; i >= 0; i--) {
        ec_conn *c = g_conns[i];
        if (c && !c->got_data && (now - c->accept_ms) > EC_IDLE_REAP_MS) conn_free(c);
    }
    if (g_reap_clock) clock_delay(g_reap_clock, 500);
}

static void conn_free(ec_conn *c)
{
    if (!c) return;
    sys_rmpollfn(c->fd);
    sys_closesocket(c->fd);
    free(c->rbuf);
    for (int i = 0; i < g_nconn; i++)
        if (g_conns[i] == c) { g_conns[i] = g_conns[--g_nconn]; break; }
    free(c);
    /* a slot freed — resume accepting if we had paused at the admission bound */
    if (g_listen_paused && g_nconn < EC_MAX_CONN && g_listen_fd >= 0) {
        sys_addpollfn(g_listen_fd, (t_fdpollfn)listen_accept, g_self);
        g_listen_paused = 0;
    }
}

/* One complete frame assembled on connection `c`: copy the CBOR body into the
 * current-frame scratch (g_rbuf), mark `c` the reply target, and kick the canvas
 * decode→route→ladder→dispatch cascade SYNCHRONOUSLY. build_* funnels the response
 * back to c->fd (conn_send_all) within this call, so g_cur_fd/g_cur_conn are valid
 * throughout and cleared after. Per-request globals are single-owner here. */
static void dispatch_frame(ec_conn *c, const unsigned char *body, size_t bodylen)
{
    if (bodylen > g_rbuf_cap) {
        unsigned char *nb = (unsigned char *)realloc(g_rbuf, bodylen);
        if (!nb) return;
        g_rbuf = nb; g_rbuf_cap = bodylen;
    }
    memcpy(g_rbuf, body, bodylen);
    g_rbuf_len = bodylen;
    g_cur_fd = c->fd; g_cur_conn = c;
    if (g_self) ecodec_decode_frame(g_self);      /* → canvas dispatch → reply to c->fd */
    g_cur_fd = -1; g_cur_conn = NULL;
}

/* Poll callback: a connection fd is readable. Drain into the per-connection buffer,
 * then peel every complete §1.6 frame (4-byte BE length prefix + body). The 16 MiB
 * cap (§4.10) is enforced PER CONNECTION — an oversize frame closes ONLY that socket
 * and frees ONLY its buffer, so the next connection's handshake is unaffected (r1). */
static void conn_read(ec_conn *c, int fd)
{
    unsigned char tmp[65536];
    ssize_t r = recv(fd, tmp, sizeof tmp, 0);
    if (r == 0) { conn_free(c); return; }                 /* peer closed */
    if (r < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return; conn_free(c); return; }
    c->got_data = 1;                                       /* active — exempt from idle reaping */

    if (c->rlen + (size_t)r > c->rcap) {
        size_t ncap = c->rcap ? c->rcap : 4096;
        while (ncap < c->rlen + (size_t)r) ncap *= 2;
        if (ncap > (size_t)ECODEC_MAX_FRAME + 4) ncap = (size_t)ECODEC_MAX_FRAME + 4;
        if (c->rlen + (size_t)r > ncap) { conn_free(c); return; }   /* over §4.10 cap → close */
        unsigned char *nb = (unsigned char *)realloc(c->rbuf, ncap);
        if (!nb) { conn_free(c); return; }
        c->rbuf = nb; c->rcap = ncap;
    }
    memcpy(c->rbuf + c->rlen, tmp, (size_t)r);
    c->rlen += (size_t)r;

    for (;;) {
        if (!c->have_len) {
            if (c->rlen < 4) return;
            c->framelen = ((uint32_t)c->rbuf[0] << 24) | ((uint32_t)c->rbuf[1] << 16)
                        | ((uint32_t)c->rbuf[2] << 8) | (uint32_t)c->rbuf[3];
            if (c->framelen > (uint32_t)ECODEC_MAX_FRAME) { conn_free(c); return; }  /* §4.10 → close */
            c->have_len = 1;
        }
        if (c->rlen < 4 + (size_t)c->framelen) return;    /* body incomplete — await more */
        dispatch_frame(c, c->rbuf + 4, c->framelen);
        size_t consumed = 4 + (size_t)c->framelen;
        memmove(c->rbuf, c->rbuf + consumed, c->rlen - consumed);
        c->rlen -= consumed;
        c->have_len = 0;
        /* loop: a pipelined next frame may already be buffered */
    }
}

/* Poll callback: the listening socket has a pending connection. Accept it; refuse
 * (immediately close) past the admission cap so a connection flood cannot exhaust
 * memory/fds — the peer keeps serving its live connections (§6.11 r3). */
static void listen_accept(void *z, int fd)
{
    (void)z;
    /* §4.10(c) admission bound: at the cap, STOP accepting (remove the listen pollfn)
     * rather than accept-and-close. Pending SYNs fill the listen backlog and further
     * connects are refused by the OS with ECONNREFUSED — a clean TCP-level refusal the
     * initiator observes (accept-then-close would let its connect() succeed first, which
     * a flood test reads as "no refusal"). conn_free re-arms accepting when a slot frees. */
    if (g_nconn >= EC_MAX_CONN) {
        sys_rmpollfn(g_listen_fd);
        g_listen_paused = 1;
        return;
    }
    int cfd = accept(fd, NULL, NULL);
    if (cfd < 0) return;
    int fl = fcntl(cfd, F_GETFL, 0); if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
    ec_conn *c = (ec_conn *)calloc(1, sizeof *c);
    if (!c) { sys_closesocket(cfd); return; }
    c->fd = cfd;
    c->accept_ms = ec_now_ms();
    g_conns[g_nconn++] = c;
    sys_addpollfn(cfd, (t_fdpollfn)conn_read, c);
}

/* [net_listen <port>( — open the peer's TCP listener (§4.1). Replaces [netreceive]
 * on the composed peer: stock netreceive broadcasts replies and gives no per-conn id
 * (see the transport note above), so the peer owns its socket. Idempotent-ish: a
 * second call rebinds. */
static void ecodec_net_listen(t_ecodec *x, t_floatarg portf)
{
    int port = (int)portf;
    if (g_listen_fd >= 0) { sys_rmpollfn(g_listen_fd); sys_closesocket(g_listen_fd); g_listen_fd = -1; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { pd_error(x, "ecodec: net_listen socket() failed"); return; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY); sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { pd_error(x, "ecodec: net_listen bind(%d) failed", port); close(fd); return; }
    if (listen(fd, 16) < 0) { pd_error(x, "ecodec: net_listen listen() failed"); close(fd); return; }
    int fl = fcntl(fd, F_GETFL, 0); if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    g_listen_fd = fd;
    g_listen_paused = 0;
    sys_addpollfn(fd, (t_fdpollfn)listen_accept, x);
    if (!g_reap_clock) g_reap_clock = clock_new(x, (t_method)reap_tick);
    clock_delay(g_reap_clock, 500);
    post("ecodec: listening on TCP %d (per-connection transport, cap %d)", port, EC_MAX_CONN);
}

static void *ecodec_new(void)
{
    t_ecodec *x = (t_ecodec *)pd_new(ecodec_class);
    x->x_out = outlet_new(&x->x_obj, &s_anything);
    g_self = x;                                   /* poll callbacks emit through this instance */
    return (void *)x;
}

void ecodec_setup(void)
{
    ecodec_class = class_new(gensym("ecodec"),
        (t_newmethod)ecodec_new, 0, sizeof(t_ecodec), CLASS_DEFAULT, 0);
    class_addmethod(ecodec_class, (t_method)ecodec_info,       gensym("info"),       0);
    class_addmethod(ecodec_class, (t_method)ecodec_sha256test, gensym("sha256test"), 0);
    /* §6.11 transport: own the TCP listener (per-connection state; A-PD-002) */
    class_addmethod(ecodec_class, (t_method)ecodec_net_listen, gensym("net_listen"), A_FLOAT, 0);
    /* §1.6 frame primitives */
    class_addmethod(ecodec_class, (t_method)ecodec_buf_reset,    gensym("buf_reset"),    0);
    class_addmethod(ecodec_class, (t_method)ecodec_buf_append,   gensym("buf_append"),   A_FLOAT, 0);
    class_addmethod(ecodec_class, (t_method)ecodec_buf_read_len, gensym("buf_read_len"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_buf_body_len, gensym("buf_body_len"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_buf_body_out, gensym("buf_body_out"), 0);
    /* §3.1/§3.2 envelope decode */
    class_addmethod(ecodec_class, (t_method)ecodec_decode_frame, gensym("decode_frame"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_exec_field,   gensym("exec_field"),   A_SYMBOL, 0);
    /* §3.3 response build */
    class_addmethod(ecodec_class, (t_method)ecodec_build_response, gensym("build_response"), A_FLOAT, A_SYMBOL, 0);
    /* §4.1/§4.4 handshake: identity + hello response */
    class_addmethod(ecodec_class, (t_method)ecodec_peer_id,    gensym("peer_id"),    0);
    class_addmethod(ecodec_class, (t_method)ecodec_build_hello, gensym("build_hello"), 0);
    /* §4.6 authenticate proof-of-possession rungs (canvas guard ladder) */
    class_addmethod(ecodec_class, (t_method)ecodec_auth_check_established, gensym("auth_check_established"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_auth_decode,      gensym("auth_decode"),      0);
    class_addmethod(ecodec_class, (t_method)ecodec_auth_check_nonce, gensym("auth_check_nonce"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_auth_check_sig,   gensym("auth_check_sig"),   0);
    class_addmethod(ecodec_class, (t_method)ecodec_auth_check_bind,  gensym("auth_check_bind"),  0);
    class_addmethod(ecodec_class, (t_method)ecodec_auth_check_hello_binding, gensym("auth_check_hello_binding"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_build_grant,      gensym("build_grant"),      0);
    /* §4.7 connect-error rungs: which state is this hello in, and is this EXECUTE
     * addressed to the connect handler at all. */
    class_addmethod(ecodec_class, (t_method)ecodec_hello_state,      gensym("hello_state"),      0);
    class_addmethod(ecodec_class, (t_method)ecodec_uri_is_connect,   gensym("uri_is_connect"),   0);
    /* §5.2 verify_request authorization rungs (canvas guard ladder) */
    class_addmethod(ecodec_class, (t_method)ecodec_authz_decode,             gensym("authz_decode"),             0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_integrity,    gensym("authz_check_integrity"),    0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_reqsig,       gensym("authz_check_reqsig"),       0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_cap_present,  gensym("authz_check_cap_present"),  0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_grantee,      gensym("authz_check_grantee"),      0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_grantee_resolvable, gensym("authz_check_grantee_resolvable"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_capchain,     gensym("authz_check_capchain"),     0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_validity,     gensym("authz_check_validity"),     0);
    class_addmethod(ecodec_class, (t_method)ecodec_uri_targets_local,        gensym("uri_targets_local"),        0);
    class_addmethod(ecodec_class, (t_method)ecodec_op_supported,             gensym("op_supported"),             A_DEFSYM, 0);
    class_addmethod(ecodec_class, (t_method)ecodec_authz_check_perm,         gensym("authz_check_perm"),         A_DEFSYM, 0);
    /* §6.6 path-dispatch primitives */
    class_addmethod(ecodec_class, (t_method)ecodec_walk_nsegs,  gensym("walk_nsegs"),  0);
    class_addmethod(ecodec_class, (t_method)ecodec_walk_prefix, gensym("walk_prefix"), A_FLOAT, 0);
    class_addmethod(ecodec_class, (t_method)ecodec_tree_get,       gensym("tree_get"),       A_SYMBOL, 0);
    class_addmethod(ecodec_class, (t_method)ecodec_tree_get_serve, gensym("tree_get_serve"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_tree_put_serve, gensym("tree_put_serve"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_cap_request_serve, gensym("cap_request_serve"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_cap_revoke_serve,    gensym("cap_revoke_serve"),    0);
    class_addmethod(ecodec_class, (t_method)ecodec_cap_configure_serve, gensym("cap_configure_serve"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_cap_delegate_serve,  gensym("cap_delegate_serve"),  0);
    class_addmethod(ecodec_class, (t_method)ecodec_echo_serve,          gensym("echo_serve"),          0);
    class_addmethod(ecodec_class, (t_method)ecodec_outbound_serve,      gensym("outbound_serve"),      0);
    class_addmethod(ecodec_class, (t_method)ecodec_handler_register_serve,   gensym("handler_register_serve"),   0);
    class_addmethod(ecodec_class, (t_method)ecodec_handler_unregister_serve, gensym("handler_unregister_serve"), 0);
    class_addmethod(ecodec_class, (t_method)ecodec_dispatch_op,    gensym("dispatch_op"),    0);
    post("ecodec: entity-core codec/crypto seam loaded (%s)", ec_abi_version());
}
