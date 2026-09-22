/*
 * peer.c — the C HOST imperative shell of the SQL (authority-as-query) peer.
 *
 * THE SEAM SPLIT (the probe's central finding, A-SQL-003): this host owns ONLY what the SQL
 * substrate genuinely cannot do — BSD sockets + TCP_NODELAY, §1.6 length-prefix framing +
 * frame-cap, canonical CBOR bytes (via the S2 seam + a minimal writer), the §4 handshake
 * connection STATE MACHINE, the §6.5 dispatch SEQUENCING, and the store's byte I/O. The
 * authority DECISION — §5.2 verify ladder, §5.5 chain-walk, §5.4/§5.5a scope-match, §6.6
 * longest-prefix resolution — lives in the authored SQL (the src/sql query files), run against an
 * in-process SQLite store. The host projects request facts into tables, then asks SQL for the
 * verdict. Here you see the leak side of the split (stateful-sequential I/O + handshake) that
 * the profile's [authority_interior_expressibility] predicts stays host-side.
 *
 * v7.75 non-functional floor (baked in, not rediscovered at S4): §4.10(a) 16 MiB frame-cap →
 * 413 payload_too_large BEFORE buffering the body (length-prefix check); §4.10(b) chain-depth
 * pre-check → 400 chain_depth_exceeded (in the SQL verdict, BEFORE the authz walk); §4.9(c)
 * resilience frame — any host ROOT error maps to a coded response, never a silent drop/hang;
 * §7b TCP_NODELAY on the raw socket. Single-thread host loop, each frame dispatched to
 * completion (profile [async].style = host-single-thread-select — concurrency is host-owned,
 * NOT a new §7b shape).
 *
 * Adapts the proven canonical-CBOR reader/writer + §4.6 PoP primitives from the full-PASS
 * Pd peer (#33) into a plain C host — the substrate-hard parts are identical across peers;
 * only the authority interior differs (there: canvas; here: SQL).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _DEFAULT_SOURCE   /* usleep, TCP_NODELAY, htonl on glibc under -std=c11 */
#include "ec_seam.h"

#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FRAME_CAP 16777216u          /* §4.10(a) 16 MiB inbound payload cap */

static uint64_t wall_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ══════════════════════════ minimal CBOR reader (navigate the envelope) ══════════════════════ */
typedef struct { const unsigned char *p; size_t len, pos; } cbor_rd;
static int cbor_head(cbor_rd *r, int *major, uint64_t *arg) {
    if (r->pos >= r->len) return -1;
    unsigned char ib = r->p[r->pos++]; *major = ib >> 5; int ai = ib & 31; uint64_t v = 0;
    if (ai < 24) v = ai;
    else if (ai == 24) { if (r->pos + 1 > r->len) return -1; v = r->p[r->pos++]; }
    else if (ai == 25) { if (r->pos + 2 > r->len) return -1; v = ((uint64_t)r->p[r->pos] << 8) | r->p[r->pos+1]; r->pos += 2; }
    else if (ai == 26) { if (r->pos + 4 > r->len) return -1; v = ((uint64_t)r->p[r->pos]<<24)|((uint64_t)r->p[r->pos+1]<<16)|((uint64_t)r->p[r->pos+2]<<8)|r->p[r->pos+3]; r->pos += 4; }
    else if (ai == 27) { if (r->pos + 8 > r->len) return -1; v = 0; for (int i=0;i<8;i++) v=(v<<8)|r->p[r->pos+i]; r->pos += 8; }
    else return -1;
    *arg = v; return 0;
}
static int cbor_skip(cbor_rd *r) {
    int major; uint64_t arg;
    if (cbor_head(r, &major, &arg) != 0) return -1;
    switch (major) {
        case 0: case 1: case 7: return 0;
        case 2: case 3: if (r->pos + arg > r->len) return -1; r->pos += arg; return 0;
        case 4: for (uint64_t i=0;i<arg;i++) if (cbor_skip(r)) return -1; return 0;
        case 5: for (uint64_t i=0;i<arg;i++) { if (cbor_skip(r)) return -1; if (cbor_skip(r)) return -1; } return 0;
        case 6: return cbor_skip(r);
        default: return -1;
    }
}
/* find text key `key` in the map at map_pos; leave `out` at the value. 1 hit / 0 miss. */
static int cbor_map_find(const unsigned char *buf, size_t len, size_t map_pos, const char *key, cbor_rd *out) {
    cbor_rd r = { buf, len, map_pos }; int major; uint64_t n;
    if (cbor_head(&r, &major, &n) != 0 || major != 5) return 0;
    size_t klen = strlen(key);
    for (uint64_t i = 0; i < n; i++) {
        int kmaj; uint64_t kl; size_t khead = r.pos;
        if (cbor_head(&r, &kmaj, &kl) != 0 || kmaj != 3) { r.pos = khead; if (cbor_skip(&r)) return 0; if (cbor_skip(&r)) return 0; continue; }
        if (kl == klen && r.pos + kl <= len && memcmp(r.p + r.pos, key, kl) == 0) { r.pos += kl; out->p = buf; out->len = len; out->pos = r.pos; return 1; }
        r.pos += kl; if (cbor_skip(&r)) return 0;
    }
    return 0;
}
static int cbor_get_text(cbor_rd *r, char *out, size_t cap) {
    cbor_rd t = *r; int major; uint64_t arg;
    if (cbor_head(&t, &major, &arg) != 0 || major != 3 || arg >= cap || t.pos + arg > t.len) return -1;
    memcpy(out, t.p + t.pos, arg); out[arg] = 0; return 0;
}
static int cbor_get_bytes(cbor_rd *r, unsigned char *out, size_t cap, size_t *outlen) {
    cbor_rd t = *r; int major; uint64_t arg;
    if (cbor_head(&t, &major, &arg) != 0 || major != 2 || arg > cap || t.pos + arg > t.len) return -1;
    memcpy(out, t.p + t.pos, arg); *outlen = arg; return 0;
}
static int cbor_value_slice(const unsigned char *buf, size_t len, size_t pos, const unsigned char **sp, size_t *sl) {
    cbor_rd r = { buf, len, pos }; size_t start = r.pos;
    if (cbor_skip(&r) != 0) return -1;
    *sp = buf + start; *sl = r.pos - start; return 0;
}

/* ══════════════════════════ minimal canonical-CBOR writer (response build) ══════════════════ */
typedef struct { unsigned char *p; size_t len, cap; } wbuf;
static int wb_ensure(wbuf *w, size_t extra) {
    if (w->p && w->len + extra <= w->cap) return 0;
    size_t nc = w->cap ? w->cap : 64; while (nc < w->len + extra) nc *= 2;
    unsigned char *np = realloc(w->p, nc); if (!np) return -1; w->p = np; w->cap = nc; return 0;
}
static int wb_byte(wbuf *w, unsigned char b) { if (wb_ensure(w,1)) return -1; w->p[w->len++] = b; return 0; }
static int wb_raw(wbuf *w, const unsigned char *d, size_t n) { if (wb_ensure(w,n)) return -1; memcpy(w->p+w->len,d,n); w->len += n; return 0; }
static int wb_head(wbuf *w, int major, uint64_t n) {
    int m = major << 5;
    if (n < 24) return wb_byte(w, (unsigned char)(m|n));
    if (n < 256) return wb_byte(w,(unsigned char)(m|24)) || wb_byte(w,(unsigned char)n);
    if (n < 65536) return wb_byte(w,(unsigned char)(m|25)) || wb_byte(w,(unsigned char)(n>>8)) || wb_byte(w,(unsigned char)(n&255));
    if (n < 0x100000000ULL) return wb_byte(w,(unsigned char)(m|26)) || wb_byte(w,(unsigned char)(n>>24)) || wb_byte(w,(unsigned char)(n>>16)) || wb_byte(w,(unsigned char)(n>>8)) || wb_byte(w,(unsigned char)(n&255));
    if (wb_byte(w,(unsigned char)(m|27))) return -1;
    for (int i=7;i>=0;i--) if (wb_byte(w,(unsigned char)((n>>(i*8))&255))) return -1;
    return 0;
}
static int wb_text(wbuf *w, const char *s) { size_t n = strlen(s); return wb_head(w,3,n) || wb_raw(w,(const unsigned char*)s,n); }
static int wb_bytes(wbuf *w, const unsigned char *b, size_t n) { return wb_head(w,2,n) || wb_raw(w,b,n); }

/* 33-byte content_hash of {type, data_cbor}: 0x00 || SHA-256(ECF{data,type}). */
static int ec_entity_hash(const char *type, const unsigned char *data, size_t dlen, unsigned char out33[33]) {
    wbuf ecf = {0};
    int bad = wb_head(&ecf,5,2) || wb_text(&ecf,"data") || wb_raw(&ecf,data,dlen) || wb_text(&ecf,"type") || wb_text(&ecf,type);
    if (bad) { free(ecf.p); return -1; }
    unsigned char digest[EC_SHA256_LEN]; int32_t rc = ec_sha256(ecf.p, ecf.len, digest); free(ecf.p);
    if (rc != EC_OK) return -1;
    out33[0] = 0x00; memcpy(out33+1, digest, 32); return 0;
}
static int wb_entity(wbuf *w, const char *type, const unsigned char *data, size_t dlen, const unsigned char h33[33]) {
    return wb_head(w,5,3) || wb_text(w,"data") || wb_raw(w,data,dlen)
        || wb_text(w,"type") || wb_text(w,type)
        || wb_text(w,"content_hash") || wb_bytes(w,h33,33);
}

/* ── canonical `included` map: keys are 33-byte content hashes; canonical CBOR requires them
 *    length-then-lexicographically sorted. All keys same length → memcmp of the 33 bytes. ── */
typedef struct { unsigned char key[33]; const unsigned char *ent; size_t elen; } inc_ent;
static int cmp_inc(const void *a, const void *b) { return memcmp(((const inc_ent*)a)->key, ((const inc_ent*)b)->key, 33); }
static int wb_included(wbuf *w, inc_ent *e, int n) {
    qsort(e,(size_t)n,sizeof *e,cmp_inc);
    if (wb_head(w,5,(uint64_t)n)) return -1;
    for (int i=0;i<n;i++) if (wb_bytes(w,e[i].key,33) || wb_raw(w,e[i].ent,e[i].elen)) return -1;
    return 0;
}

/* ══════════════════════════ identity (§1.5/§7.4) ══════════════════════════ */
static unsigned char g_priv[EC_ED25519_PRIV_LEN], g_pub[EC_ED25519_PUB_LEN];
static char g_peer_id[128];
static unsigned char g_peer_hash[33];   /* 0x00||sha256(pubkey) — self identity hash */
static int g_open_grants = 0;           /* --debug-open-grants: mint the degenerate default→* seed */

static int b64_decode(const char *in, unsigned char *out, size_t outcap) {
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned v=0; int bits=0; size_t n=0;
    for (const char *p=in; *p; p++) {
        if (*p=='='||*p=='\n'||*p=='\r'||*p==' ') continue;
        const char *q = strchr(A,*p); if (!q) return -1;
        v=(v<<6)|(unsigned)(q-A); bits+=6;
        if (bits>=8) { bits-=8; if (n>=outcap) return -1; out[n++]=(unsigned char)(v>>bits); }
    }
    return (int)n;
}
static int load_named_seed(const char *name) {
    if (!name || !*name) return 0;
    const char *home = getenv("HOME"); if (!home||!*home) home = "/root";
    char path[512]; if (snprintf(path,sizeof path,"%s/.entity/peers/%s/keypair",home,name) <= 0) return 0;
    FILE *f = fopen(path,"rb"); if (!f) return 0;
    char buf[4096]; size_t len = fread(buf,1,sizeof buf-1,f); fclose(f); buf[len]=0;
    char b64[4096]; size_t bl=0;
    for (char *line=strtok(buf,"\r\n"); line; line=strtok(NULL,"\r\n")) {
        if (strncmp(line,"-----",5)==0) continue;
        for (char *p=line; *p && bl<sizeof b64-1; p++) if (*p!=' '&&*p!='\t') b64[bl++]=*p;
    }
    b64[bl]=0; unsigned char seed[64];
    if (b64_decode(b64,seed,sizeof seed)!=32) return 0;
    memcpy(g_priv,seed,32);
    return ec_ed25519_seed_to_pubkey(g_priv,g_pub)==EC_OK;
}
static void init_identity(const char *name) {
    if (!load_named_seed(name) && ec_ed25519_keygen(g_priv,g_pub)!=EC_OK) { g_peer_id[0]=0; return; }
    size_t out_len=0;
    if (ec_peerid_format(1,0,g_pub,EC_ED25519_PUB_LEN,(uint8_t*)g_peer_id,sizeof g_peer_id-1,&out_len)==EC_OK && out_len<sizeof g_peer_id)
        g_peer_id[out_len]=0;
    unsigned char dig[32]; ec_sha256(g_pub,32,dig); g_peer_hash[0]=0x00; memcpy(g_peer_hash+1,dig,32);
}

/* ══════════════════════════ framing (§1.6) + resilience ══════════════════════════ */
static ssize_t read_all(int fd, unsigned char *buf, size_t n) {
    size_t got=0; while (got<n) { ssize_t r=read(fd,buf+got,n-got); if (r<=0) return r; got+=(size_t)r; } return (ssize_t)got;
}
static int write_all(int fd, const unsigned char *buf, size_t n) {
    size_t put=0; while (put<n) { ssize_t w=write(fd,buf+put,n-put); if (w<=0) return -1; put+=(size_t)w; } return 0;
}
/* read one §1.6 frame. Returns: 1 ok, 0 eof, -1 error, -413 oversize (cap BEFORE buffering). */
static int read_frame(int fd, unsigned char **out, uint32_t *outlen) {
    unsigned char lp[4]; ssize_t r = read_all(fd, lp, 4); if (r==0) return 0; if (r<0) return -1;
    uint32_t n = ((uint32_t)lp[0]<<24)|((uint32_t)lp[1]<<16)|((uint32_t)lp[2]<<8)|lp[3];
    if (n > FRAME_CAP) return -413;                 /* §4.10(a): reject BEFORE allocating the body */
    unsigned char *b = malloc(n?n:1); if (!b) return -1;
    if (read_all(fd,b,n) <= 0 && n>0) { free(b); return -1; }
    *out=b; *outlen=n; return 1;
}
static int send_envelope(int fd, const unsigned char *env, size_t n) {
    unsigned char lp[4]; lp[0]=(n>>24)&255; lp[1]=(n>>16)&255; lp[2]=(n>>8)&255; lp[3]=n&255;
    if (write_all(fd,lp,4)) return -1;
    return write_all(fd,env,n);
}

/* ══════════════════════════ response builders (§3.3 / §4.4) ══════════════════════════ */
/* build + send an EXECUTE_RESPONSE {result, status, request_id} with an explicit included map. */
static int emit_response(int fd, const char *rid, unsigned status, const char *result_type,
                         const unsigned char *rdata, size_t rdlen, const unsigned char *inc, size_t inc_len) {
    wbuf resent={0}, respd={0}, respent={0}, envd={0}; unsigned char resh[33], resph[33]; int rc=-1;
    if (ec_entity_hash(result_type,rdata,rdlen,resh)) goto done;
    if (wb_entity(&resent,result_type,rdata,rdlen,resh)) goto done;
    if (wb_head(&respd,5,3)
        || wb_text(&respd,"result")     || wb_raw(&respd,resent.p,resent.len)
        || wb_text(&respd,"status")     || wb_head(&respd,0,status)
        || wb_text(&respd,"request_id") || wb_text(&respd,rid)) goto done;
    if (ec_entity_hash("system/protocol/execute/response",respd.p,respd.len,resph)) goto done;
    if (wb_entity(&respent,"system/protocol/execute/response",respd.p,respd.len,resph)) goto done;
    if (wb_head(&envd,5,2)
        || wb_text(&envd,"root")     || wb_raw(&envd,respent.p,respent.len)
        || wb_text(&envd,"included") || wb_raw(&envd,inc,inc_len)) goto done;
    rc = send_envelope(fd, envd.p, envd.len);
done:
    free(resent.p); free(respd.p); free(respent.p); free(envd.p); return rc;
}
static int emit_error(int fd, const char *rid, unsigned status, const char *code) {
    wbuf ed={0}; static const unsigned char empty=0xa0;
    if (wb_head(&ed,5,1) || wb_text(&ed,"code") || wb_text(&ed,code)) { free(ed.p); return -1; }
    int rc = emit_response(fd, rid, status, "system/protocol/error", ed.p, ed.len, &empty, 1);
    free(ed.p); return rc;
}

/* ══════════════════════════ per-connection handshake state ══════════════════════════ */
/* §6.11 reentry correlation map: an originated reentry EXECUTE (orid) is tracked against the
 * inbound dispatch-outbound request (rid) that spawned it; when its EXECUTE_RESPONSE arrives on
 * the same fd we emit the dispatch-outbound response for rid. Non-blocking → the single-fd loop
 * handles many concurrent pipelined reentries (the host correlation-map tax, per the profile). */
typedef struct { int established; unsigned char nonce[32]; int nonce_set;
    struct { char orid[48]; char rid[64]; } pend[128]; int npend; } conn_state;

/* §4.5 does the hello's advertised list for `key` (an array of text under params.data) EXCLUDE
 * our floor value `want`? (present + non-empty + want absent → disjoint → reject). */
static int advertised_excludes(const unsigned char *buf, size_t len, size_t pdata_pos, const char *key, const char *want) {
    cbor_rd lf; if (!cbor_map_find(buf,len,pdata_pos,key,&lf)) return 0;   /* absent → no constraint */
    cbor_rd a=lf; int am; uint64_t ac; if (cbor_head(&a,&am,&ac)!=0||am!=4||ac==0) return 0;
    for (uint64_t i=0;i<ac;i++){ char v[64]={0}; cbor_rd vv=a; if(cbor_get_text(&vv,v,sizeof v)==0 && strcmp(v,want)==0) return 0; if(cbor_skip(&a))break; }
    return 1;   /* list present, non-empty, want not found → disjoint */
}

/* §4.4 hello EXECUTE_RESPONSE: status 200, result = connect/hello {nonce,peer_id,protocols,ts}. */
static int handle_hello(int fd, const char *rid, conn_state *cs, const unsigned char *buf, size_t len) {
    /* §4.5 negotiation: reject a hello whose advertised hash_formats / key_types exclude our floor. */
    { cbor_rd root,rdata,params,pdata;
      if (cbor_map_find(buf,len,0,"root",&root) && cbor_map_find(buf,len,root.pos,"data",&rdata)
          && cbor_map_find(buf,len,rdata.pos,"params",&params) && cbor_map_find(buf,len,params.pos,"data",&pdata)) {
        if (advertised_excludes(buf,len,pdata.pos,"hash_formats","ecfv1-sha256")) return emit_error(fd,rid,400,"incompatible_hash_format");
        if (advertised_excludes(buf,len,pdata.pos,"key_types","ed25519")) return emit_error(fd,rid,400,"unsupported_key_type");
      }
    }
    unsigned char np[EC_ED25519_PRIV_LEN], nonce[EC_ED25519_PUB_LEN];
    if (ec_ed25519_keygen(np,nonce)!=EC_OK) memset(nonce,0,sizeof nonce);
    memcpy(cs->nonce, nonce, 32); cs->nonce_set = 1;
    uint64_t ts = wall_ms();
    wbuf rd={0}; static const unsigned char empty=0xa0;
    int bad = wb_head(&rd,5,6)
        || wb_text(&rd,"nonce")        || wb_bytes(&rd,nonce,sizeof nonce)
        || wb_text(&rd,"peer_id")      || wb_text(&rd,g_peer_id)
        || wb_text(&rd,"key_types")    || wb_head(&rd,4,1) || wb_text(&rd,"ed25519")
        || wb_text(&rd,"protocols")    || wb_head(&rd,4,1) || wb_text(&rd,"entity-core/1.0")
        || wb_text(&rd,"timestamp")    || wb_head(&rd,0,ts)
        || wb_text(&rd,"hash_formats") || wb_head(&rd,4,1) || wb_text(&rd,"ecfv1-sha256");
    if (bad) { free(rd.p); return -1; }
    int rc = emit_response(fd, rid, 200, "system/protocol/connect/hello", rd.p, rd.len, &empty, 1);
    free(rd.p); return rc;
}

/* §4.6 authenticate: PoP (nonce-echo, signature, identity-binding), then §4.4 grant response. */
static int handle_authenticate(int fd, const char *rid, conn_state *cs,
                               const unsigned char *buf, size_t len) {
    /* RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established connection must
     * not be re-processed (it would re-verify the same still-cached nonce and re-issue a grant).
     * The nonce is documented single-use — reject outright, before any nonce/signature work. */
    if (cs->established) return emit_error(fd, rid, 401, "invalid_nonce");
    cbor_rd root, rdata, params, pdata, f;
    char apeer[128]={0}, akt[32]={0}; unsigned char apub[64]; size_t apub_len=0, anonce_len=0; unsigned char anonce[64];
    if (!cbor_map_find(buf,len,0,"root",&root) || !cbor_map_find(buf,len,root.pos,"data",&rdata)
        || !cbor_map_find(buf,len,rdata.pos,"params",&params) || !cbor_map_find(buf,len,params.pos,"data",&pdata))
        return emit_error(fd, rid, 400, "connection_sequence_error");
    if (!cbor_map_find(buf,len,pdata.pos,"peer_id",&f) || cbor_get_text(&f,apeer,sizeof apeer))
        return emit_error(fd, rid, 401, "authentication_failed");
    if (!cbor_map_find(buf,len,pdata.pos,"key_type",&f) || cbor_get_text(&f,akt,sizeof akt) || strcmp(akt,"ed25519")!=0)
        return emit_error(fd, rid, 400, "unsupported_key_type");
    /* §4.5 the claimed peer_id must encode a supported key_type (ed25519 == 1). An unknown key_type
     * in the peer_id (e.g. 0xfd agility probe) is 400 unsupported_key_type, NOT a 401 id-mismatch. */
    { uint64_t kt=0,ht=0; unsigned char dg[64]; size_t dl=0;
      if (ec_peerid_parse((const unsigned char*)apeer,strlen(apeer),&kt,&ht,dg,&dl)==EC_OK && kt!=1)
          return emit_error(fd, rid, 400, "unsupported_key_type"); }
    if (!cbor_map_find(buf,len,pdata.pos,"public_key",&f) || cbor_get_bytes(&f,apub,sizeof apub,&apub_len) || apub_len!=32)
        return emit_error(fd, rid, 401, "authentication_failed");
    if (!cbor_map_find(buf,len,pdata.pos,"nonce",&f) || cbor_get_bytes(&f,anonce,sizeof anonce,&anonce_len))
        return emit_error(fd, rid, 401, "invalid_nonce");
    /* §4.6 step 1: nonce echo */
    if (!cs->nonce_set || anonce_len!=32 || memcmp(anonce,cs->nonce,32)!=0)
        return emit_error(fd, rid, 401, "invalid_nonce");
    /* recompute authenticate entity hash from verbatim params.data (§4.6 hardening) */
    const unsigned char *dptr; size_t dlen; unsigned char ahash[33];
    if (cbor_value_slice(buf,len,pdata.pos,&dptr,&dlen) || ec_entity_hash("system/protocol/connect/authenticate",dptr,dlen,ahash))
        return emit_error(fd, rid, 500, "internal_error");
    /* §4.6 step 2: locate + verify the authenticate signature against apub */
    const unsigned char *sigent=NULL; size_t siglen=0; int sig_ok=0;
    if (ec_envelope_find_signature_for(buf,len,ahash,33,&sigent,&siglen)==EC_OK && sigent) {
        cbor_rd sd, sf; unsigned char sig[64]; size_t ns=0;
        if (cbor_map_find(sigent,siglen,0,"data",&sd) && cbor_map_find(sigent,siglen,sd.pos,"signature",&sf)
            && cbor_get_bytes(&sf,sig,sizeof sig,&ns)==0 && ns==64
            && ec_ed25519_verify(apub,ahash,33,sig)==EC_OK) sig_ok=1;
    }
    if (!sig_ok) return emit_error(fd, rid, 401, "authentication_failed");
    /* §4.6 step 3: identity binding — peer_id derived from apub */
    char derived[128]; size_t olen=0;
    if (ec_peerid_format(1,0,apub,32,(uint8_t*)derived,sizeof derived-1,&olen)!=EC_OK || olen>=sizeof derived) return emit_error(fd, rid, 500, "internal_error");
    derived[olen]=0;
    if (strcmp(derived,apeer)!=0) return emit_error(fd, rid, 401, "identity_mismatch");

    /* §4.4 authenticate response: result = system/capability/grant {token: <cap_hash>}, with the
     * token/granter-peer/signature in included. A minimal SHOULD-floor grant, self-signed by this
     * peer (granter == local). Identity hashes are content_hash(system/peer entity) — NOT a raw
     * key hash — so the oracle's included[cap.granter] lookup resolves the granter peer entity. */
    wbuf gpeerd={0};
    if (wb_head(&gpeerd,5,2) || wb_text(&gpeerd,"key_type") || wb_text(&gpeerd,"ed25519")
        || wb_text(&gpeerd,"public_key") || wb_bytes(&gpeerd,g_pub,32)) { free(gpeerd.p); return emit_error(fd, rid, 500, "internal_error"); }
    unsigned char granter_hash[33]; ec_entity_hash("system/peer", gpeerd.p, gpeerd.len, granter_hash);  /* = content_hash(our peer) */
    /* grantee = content_hash(remote's system/peer entity {key_type, public_key: apub}) */
    wbuf rpeerd={0};
    if (wb_head(&rpeerd,5,2) || wb_text(&rpeerd,"key_type") || wb_text(&rpeerd,"ed25519")
        || wb_text(&rpeerd,"public_key") || wb_bytes(&rpeerd,apub,32)) { free(gpeerd.p); free(rpeerd.p); return emit_error(fd, rid, 500, "internal_error"); }
    unsigned char remote_hash[33]; ec_entity_hash("system/peer", rpeerd.p, rpeerd.len, remote_hash);
    free(rpeerd.p);
    uint64_t created = wall_ms();
    /* Section 4.4/6.9a seed grant. Under --debug-open-grants (the cohort conformance convention)
     * this is the degenerate wide-open scope: peers/handlers/operations = star, resources =
     * star + the absolute all-peers form (5.5a: the absolute all-peers pattern makes resources
     * universal, A-PD-017). Canonical grant-entry key order is length-then-lex:
     * peers(5), handlers(8), resources(9), operations(10). */
    wbuf grants={0};
    int gbad;
    if (g_open_grants) {
        gbad = wb_head(&grants,4,1)
            || wb_head(&grants,5,4)
            || wb_text(&grants,"peers")      || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,1) || wb_text(&grants,"*")
            || wb_text(&grants,"handlers")   || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,1) || wb_text(&grants,"*")
            || wb_text(&grants,"resources")  || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,2) || wb_text(&grants,"*") || wb_text(&grants,"/*/*")
            || wb_text(&grants,"operations") || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,1) || wb_text(&grants,"*");
    } else {
        gbad = wb_head(&grants,4,1)
            || wb_head(&grants,5,3)
            || wb_text(&grants,"handlers")   || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,1) || wb_text(&grants,"system/tree")
            || wb_text(&grants,"resources")  || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,2) || wb_text(&grants,"system/type/*") || wb_text(&grants,"system/handler/*")
            || wb_text(&grants,"operations") || wb_head(&grants,5,1) || wb_text(&grants,"include") || wb_head(&grants,4,1) || wb_text(&grants,"get");
    }
    /* cap token data — canonical key order: grants(6) < grantee(7) < granter(7) < created_at(10). */
    wbuf capd={0};
    int cbad = gbad || wb_head(&capd,5,4)
        || wb_text(&capd,"grants")     || wb_raw(&capd,grants.p,grants.len)
        || wb_text(&capd,"grantee")    || wb_bytes(&capd,remote_hash,33)
        || wb_text(&capd,"granter")    || wb_bytes(&capd,granter_hash,33)
        || wb_text(&capd,"created_at") || wb_head(&capd,0,created);
    unsigned char caph[33]; if (cbad || ec_entity_hash("system/capability/token",capd.p,capd.len,caph)) { free(grants.p); free(capd.p); free(gpeerd.p); return emit_error(fd, rid, 500, "internal_error"); }
    /* signature over the cap by this peer — canonical: signer(6) < target(6) < algorithm(9) < signature(9). */
    unsigned char csig[64]; int sbad = ec_ed25519_sign(g_priv,caph,33,csig)!=EC_OK;
    wbuf sigd={0};
    sbad = sbad || wb_head(&sigd,5,4)
        || wb_text(&sigd,"signer")    || wb_bytes(&sigd,granter_hash,33)
        || wb_text(&sigd,"target")    || wb_bytes(&sigd,caph,33)
        || wb_text(&sigd,"algorithm") || wb_text(&sigd,"ed25519")
        || wb_text(&sigd,"signature") || wb_bytes(&sigd,csig,64);
    unsigned char sigh[33]; if (sbad || ec_entity_hash("system/signature",sigd.p,sigd.len,sigh)) { free(grants.p);free(capd.p);free(gpeerd.p);free(sigd.p); return emit_error(fd, rid, 500, "internal_error"); }
    /* included map(3): keyed by content_hash (bstr keys) — canonical CBOR requires sorted keys. */
    wbuf te={0},pe={0},se={0};
    int ibad = wb_entity(&te,"system/capability/token",capd.p,capd.len,caph)
             || wb_entity(&pe,"system/peer",gpeerd.p,gpeerd.len,granter_hash)
             || wb_entity(&se,"system/signature",sigd.p,sigd.len,sigh);
    inc_ent ie[3]; memcpy(ie[0].key,caph,33); ie[0].ent=te.p; ie[0].elen=te.len;
    memcpy(ie[1].key,granter_hash,33); ie[1].ent=pe.p; ie[1].elen=pe.len;
    memcpy(ie[2].key,sigh,33); ie[2].ent=se.p; ie[2].elen=se.len;
    wbuf inc={0}; ibad = ibad || wb_included(&inc,ie,3);
    /* result: system/capability/grant {token: caph} */
    wbuf gr={0}; int rbad = ibad || wb_head(&gr,5,1) || wb_text(&gr,"token") || wb_bytes(&gr,caph,33);
    int rc;
    if (rbad) rc = emit_error(fd, rid, 500, "internal_error");
    else { rc = emit_response(fd, rid, 200, "system/capability/grant", gr.p, gr.len, inc.p, inc.len); cs->established = 1; }
    free(grants.p); free(capd.p); free(gpeerd.p); free(sigd.p); free(te.p); free(pe.p); free(se.p); free(inc.p); free(gr.p);
    return rc;
}

/* ══════════════════════════ §6.5 dispatch: projection + SQL verdict + handler bodies ══════════
 * THE S4 COMPLETION (wrapper-guard preserved). The host PROJECTS the request's §5.8 authority
 * chain (envelope.included → peer/cap/grant_scope/signature/multi_signer tables) and asks the
 * AUTHORED verify_ladder.sql for the (status, code) verdict — the §5.2 decision stays in SQL.
 * On 'ok' the host runs the resolved handler BODY (tree/type/capability/handler/validate). No
 * imperative allow/deny branch shadows src/sql — the verdict is the query's.
 *
 * Store model: g_store (file-backed, shared across the fork-per-connection children — a §7b
 * store-safety story via WAL) holds the tree (§6.3 nodes) + the §9.5 type registry + handler
 * registrations + revocation markers. g_db (per-child :memory:) is the AUTHORITY projection —
 * cleared + re-projected per request, so the verdict is a pure function of the request facts
 * (§5.10 determinism), never cross-request state. ══════════════════════════════════════════ */
#include <stdbool.h>
#include <stdarg.h>
static sqlite3 *g_db = NULL;        /* per-child authority projection (:memory:) */
static sqlite3 *g_store = NULL;     /* shared tree/type/handler store (file, WAL) */
static const char *g_store_path = "/tmp/ec-sql-store/store.db";
static unsigned char g_id_hash[33]; /* content_hash(system/peer{key_type,public_key}) — my identity */
static int g_validate = 0;          /* --validate: system/validate conformance handlers live */

static char HEXD[] = "0123456789abcdef";
static void hexof(const unsigned char *b, size_t n, char *out) {
    for (size_t i=0;i<n;i++){ out[2*i]=HEXD[b[i]>>4]; out[2*i+1]=HEXD[b[i]&15]; } out[2*n]=0;
}
static char *slurp(const char *path, long *outn) {
    FILE *f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    char *s=malloc((size_t)n+1); if(!s){fclose(f);return NULL;}
    if(fread(s,1,(size_t)n,f)!=(size_t)n){free(s);fclose(f);return NULL;}
    s[n]=0; fclose(f); if(outn)*outn=n; return s;
}
static void execf(sqlite3 *db, const char *fmt, ...) {
    char sql[2048]; va_list ap; va_start(ap,fmt); vsnprintf(sql,sizeof sql,fmt,ap); va_end(ap);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

/* my own system/peer entity {key_type,public_key} data bytes (canonical key order kt<pk) */
static int my_peer_data(wbuf *w) {
    return wb_head(w,5,2) || wb_text(w,"key_type") || wb_text(w,"ed25519")
        || wb_text(w,"public_key") || wb_bytes(w,g_pub,32);
}

/* ── the §9.5 core-type floor a core peer publishes (render-from-registry; the one legitimate
 *    byte-exact exception, AGENTS.md — the shared type-registry vectors ARE the spec's type
 *    definitions). Extension vocabularies are NOT pre-published (they arrive with the ext). ── */
static const char *CORE_TYPES[] = {
  "primitive/any","primitive/bool","primitive/bytes","primitive/float","primitive/int",
  "primitive/null","primitive/string","primitive/uint","entity","core/entity","core/envelope",
  "system/envelope","system/protocol/envelope","system/hash","system/peer","system/peer-id",
  "system/signature","system/protocol/connect/authenticate","system/protocol/connect/hello",
  "system/protocol/error","system/protocol/execute","system/protocol/execute/response",
  "system/protocol/resource-target","system/capability/grant","system/capability/grant-entry",
  "system/capability/id-scope","system/capability/path-scope","system/capability/request",
  "system/capability/revocation","system/capability/revoke-request",
  "system/capability/delegate-request","system/capability/delegation-caveats",
  "system/capability/policy-entry","system/capability/token","system/capability/multi-granter",
  "system/handler","system/handler/interface","system/handler/manifest",
  "system/handler/operation-spec","system/handler/register-request","system/handler/register-result",
  "system/tree/get-request","system/tree/put-request","system/tree/listing",
  "system/tree/listing-entry","system/tree/path","system/type","system/type/field-spec",
  "system/type/name","system/bounds","system/resource-limits","system/delivery-spec",
  "system/deletion-marker", NULL };
static int is_core_type(const char *n){ for(int i=0;CORE_TYPES[i];i++) if(!strcmp(CORE_TYPES[i],n)) return 1; return 0; }

/* the handler registration prefixes this peer serves (§6.2 MUST + §7a conformance). */
static const char *HANDLER_PATTERNS[] = {
  "system/protocol/connect","system/tree","system/capability","system/type","system/handler",NULL };

/* ── store: bind an entity {type,data} at a tree path (idempotent by path). ── */
static void store_bind(const char *path, const char *type, const unsigned char *data, size_t dlen) {
    if (!g_store) return;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_store,
        "INSERT INTO node(path,type,data) VALUES(?,?,?) "
        "ON CONFLICT(path) DO UPDATE SET type=excluded.type,data=excluded.data",-1,&st,NULL)!=SQLITE_OK) return;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,2,type,-1,SQLITE_TRANSIENT);
    sqlite3_bind_blob(st,3,data,(int)dlen,SQLITE_TRANSIENT);
    sqlite3_step(st); sqlite3_finalize(st);
}
/* fetch a node's {type,data} — caller frees *data. 1 hit / 0 miss. */
static int store_get(const char *path, char *type_out, size_t tcap, unsigned char **data, size_t *dlen) {
    if (!g_store) return 0;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_store,"SELECT type,data FROM node WHERE path=?",-1,&st,NULL)!=SQLITE_OK) return 0;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);
    int hit=0;
    if (sqlite3_step(st)==SQLITE_ROW) {
        const char *t=(const char*)sqlite3_column_text(st,0);
        const void *d=sqlite3_column_blob(st,1); int n=sqlite3_column_bytes(st,1);
        snprintf(type_out,tcap,"%s",t?t:"");
        *data=malloc(n?n:1); if(*data){ memcpy(*data,d,n); *dlen=(size_t)n; hit=1; }
    }
    sqlite3_finalize(st); return hit;
}

/* ── parse the shared type-registry vectors (array of {data,name,...}) and bind the CORE floor
 *    as system/type nodes at /{peer}/system/type/{name}. Called once by the parent. ── */
static void seed_types(void) {
    long n=0; char *buf=slurp("../shared/test-vectors/type-registry/type-registry-vectors.cbor",&n);
    if (!buf) { fprintf(stderr,"WARN: type-registry vectors not found\n"); return; }
    cbor_rd r={ (unsigned char*)buf, (size_t)n, 0 }; int maj; uint64_t cnt;
    if (cbor_head(&r,&maj,&cnt)!=0 || maj!=4) { free(buf); return; }
    for (uint64_t i=0;i<cnt;i++) {
        size_t mpos=r.pos;
        cbor_rd nf, df; char name[128]={0};
        if (cbor_map_find((unsigned char*)buf,(size_t)n,mpos,"name",&nf)) cbor_get_text(&nf,name,sizeof name);
        if (cbor_map_find((unsigned char*)buf,(size_t)n,mpos,"data",&df) && is_core_type(name)) {
            /* `data` is a CBOR byte string WRAPPING the ECF TypeDefinition map — store the inner
             * map bytes (the entity data), not the byte-string envelope. */
            cbor_rd dh=df; int dmaj; uint64_t dlen2;
            if (cbor_head(&dh,&dmaj,&dlen2)==0 && dmaj==2 && dh.pos+dlen2<=(size_t)n) {
                char path[256]; snprintf(path,sizeof path,"/%s/system/type/%s",g_peer_id,name);
                store_bind(path,"system/type",(const unsigned char*)buf+dh.pos,(size_t)dlen2);
            }
        }
        r.pos=mpos; if (cbor_skip(&r)) break;   /* advance past this map */
    }
    free(buf);
}

/* ── bootstrap the §6.1 handler-discovery entities: a system/handler/interface at
 *    /{peer}/system/handler/{pattern} ({name,pattern,operations}) + a system/handler manifest at
 *    /{peer}/{pattern} ({interface}). These make the §6 handler listing + interface fetch resolve. ── */
static void seed_one_handler(const char *pattern, const char *name, const char *const *ops, int nops) {
    /* interface data {name, pattern, operations:{op:{}}} — canonical: name<pattern<operations. */
    wbuf im={0};
    int bad = wb_head(&im,5,3)
        || wb_text(&im,"name") || wb_text(&im,name)
        || wb_text(&im,"pattern") || wb_text(&im,pattern)
        || wb_text(&im,"operations") || wb_head(&im,5,(uint64_t)nops);
    /* ops sorted length-then-lex */
    const char *sorted[16]; int ns=nops<16?nops:16; for(int i=0;i<ns;i++) sorted[i]=ops[i];
    for(int i=0;i<ns;i++)for(int j=i+1;j<ns;j++){ size_t li=strlen(sorted[i]),lj=strlen(sorted[j]); if(li>lj||(li==lj&&strcmp(sorted[i],sorted[j])>0)){const char*t=sorted[i];sorted[i]=sorted[j];sorted[j]=t;} }
    for (int i=0;i<ns;i++) bad = bad || wb_text(&im,sorted[i]) || wb_head(&im,5,0);
    if (!bad) { char ip[768]; snprintf(ip,sizeof ip,"/%s/system/handler/%s",g_peer_id,pattern); store_bind(ip,"system/handler/interface",im.p,im.len); }
    free(im.p);
    /* manifest data {interface: "system/handler/{pattern}"} */
    wbuf mm={0}; char iface[768]; snprintf(iface,sizeof iface,"system/handler/%s",pattern);
    if (!(wb_head(&mm,5,1)||wb_text(&mm,"interface")||wb_text(&mm,iface))) { char mp[768]; snprintf(mp,sizeof mp,"/%s/%s",g_peer_id,pattern); store_bind(mp,"system/handler",mm.p,mm.len); }
    free(mm.p);
}
static void seed_handler_entities(void) {
    static const char *ops_tree[]={"get","put","list"};
    static const char *ops_handler[]={"register","unregister"};
    static const char *ops_cap[]={"request","revoke","configure","delegate"};
    static const char *ops_connect[]={"hello","authenticate"};
    static const char *ops_type[]={"validate"};
    static const char *ops_echo[]={"echo"};
    static const char *ops_disp[]={"dispatch"};
    seed_one_handler("system/tree","Tree",ops_tree,3);
    seed_one_handler("system/handler","Handlers",ops_handler,2);
    seed_one_handler("system/capability","Capability",ops_cap,4);
    seed_one_handler("system/protocol/connect","Connect",ops_connect,2);
    seed_one_handler("system/type","Type",ops_type,1);
    if (g_validate) { seed_one_handler("system/validate/echo","ValidateEcho",ops_echo,1);
                      seed_one_handler("system/validate/dispatch-outbound","ValidateDispatch",ops_disp,1); }
}

/* ── seed the shared store file: schema + type registry + handler registrations. Parent-only. ── */
static void seed_store_file(void) {
    { char dir[256]; snprintf(dir,sizeof dir,"%s",g_store_path); char *sl=strrchr(dir,'/'); if(sl){*sl=0; char cmd[300]; snprintf(cmd,sizeof cmd,"mkdir -p %s",dir); system(cmd);} }
    unlink(g_store_path);
    if (sqlite3_open(g_store_path,&g_store)!=SQLITE_OK) { fprintf(stderr,"store open fail\n"); return; }
    sqlite3_busy_timeout(g_store,8000);
    sqlite3_exec(g_store,"PRAGMA journal_mode=WAL;",NULL,NULL,NULL);
    sqlite3_exec(g_store,
      "CREATE TABLE IF NOT EXISTS node(path TEXT PRIMARY KEY, type TEXT, data BLOB);"
      "CREATE TABLE IF NOT EXISTS handler_reg(path TEXT PRIMARY KEY);"
      "CREATE TABLE IF NOT EXISTS revoked(cap_hex TEXT PRIMARY KEY);", NULL,NULL,NULL);
    for (int i=0;HANDLER_PATTERNS[i];i++)
        execf(g_store,"INSERT OR IGNORE INTO handler_reg(path) VALUES('/%s/%s');",g_peer_id,HANDLER_PATTERNS[i]);
    if (g_validate) {
        execf(g_store,"INSERT OR IGNORE INTO handler_reg(path) VALUES('/%s/system/validate/echo');",g_peer_id);
        execf(g_store,"INSERT OR IGNORE INTO handler_reg(path) VALUES('/%s/system/validate/dispatch-outbound');",g_peer_id);
    }
    seed_types();
    seed_handler_entities();
    sqlite3_close(g_store); g_store=NULL;
}

/* ── per-child DB init: open the shared store (WAL) + a fresh :memory: authority db with the
 *    crypto seam fns + schema.sql + the (static + registered) handler table. ── */
static char *g_schema=NULL, *g_ladder=NULL, *g_resolve=NULL, *g_konf=NULL;
static void seed_auth_handlers(void) {
    sqlite3_exec(g_db,"DELETE FROM handler;",NULL,NULL,NULL);
    /* static MUST handlers */
    for (int i=0;HANDLER_PATTERNS[i];i++)
        execf(g_db,"INSERT OR IGNORE INTO handler(path) VALUES('/%s/%s');",g_peer_id,HANDLER_PATTERNS[i]);
    if (g_validate) { execf(g_db,"INSERT OR IGNORE INTO handler(path) VALUES('/%s/system/validate/echo');",g_peer_id);
                      execf(g_db,"INSERT OR IGNORE INTO handler(path) VALUES('/%s/system/validate/dispatch-outbound');",g_peer_id); }
    /* runtime-registered handlers from the shared store */
    if (g_store) {
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(g_store,"SELECT path FROM handler_reg",-1,&st,NULL)==SQLITE_OK) {
            while (sqlite3_step(st)==SQLITE_ROW)
                execf(g_db,"INSERT OR IGNORE INTO handler(path) VALUES('%s');",(const char*)sqlite3_column_text(st,0));
            sqlite3_finalize(st);
        }
    }
}
static int init_child_dbs(void) {
    if (sqlite3_open(g_store_path,&g_store)!=SQLITE_OK) g_store=NULL;
    if (g_store){ sqlite3_busy_timeout(g_store,8000); sqlite3_exec(g_store,"PRAGMA journal_mode=WAL;",NULL,NULL,NULL); }
    if (sqlite3_open(":memory:",&g_db)!=SQLITE_OK) return -1;
    ec_seam_register_sql_functions(g_db);
    if (!g_schema)  g_schema =slurp("src/sql/schema.sql",NULL);
    if (!g_ladder)  g_ladder =slurp("src/sql/verify_ladder.sql",NULL);
    if (!g_resolve) g_resolve=slurp("src/sql/resolve.sql",NULL);
    if (!g_konf)    g_konf   =slurp("src/sql/k_of_n.sql",NULL);
    if (g_schema) sqlite3_exec(g_db,g_schema,NULL,NULL,NULL);
    seed_auth_handlers();
    return 0;
}

/* §6.6 handler resolution via resolve.sql (longest-prefix). copies the pattern to out. 1/0. */
static int resolve_handler(const char *uri, char *out, size_t cap) {
    if (!g_resolve) return 0;
    sqlite3_stmt *st; if (sqlite3_prepare_v2(g_db,g_resolve,-1,&st,NULL)!=SQLITE_OK) return 0;
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st,":uri"), uri, -1, SQLITE_TRANSIENT);
    int found=0;
    if (sqlite3_step(st)==SQLITE_ROW) { const char *p=(const char*)sqlite3_column_text(st,0); if(p){ snprintf(out,cap,"%s",p); found=1; } }
    sqlite3_finalize(st); return found;
}

/* ══════════════════════════ §5.8 authority-chain projection (host → SQL tables) ══════════════ */
/* insert a peer row from a system/peer entity's data {key_type,public_key}, keyed by `hash`. */
static void project_peer(const unsigned char *hash33, const unsigned char *data, size_t dlen) {
    cbor_rd d={data,dlen,0}, f; unsigned char pk[64]; size_t pkl=0; char kt[32]={0};
    if (cbor_map_find(data,dlen,0,"public_key",&f)) cbor_get_bytes(&f,pk,sizeof pk,&pkl);
    if (cbor_map_find(data,dlen,0,"key_type",&f)) cbor_get_text(&f,kt,sizeof kt);
    (void)d;
    char pid[128]=""; size_t ol=0;
    if (pkl==32) { if (ec_peerid_format(1,0,pk,32,(uint8_t*)pid,sizeof pid-1,&ol)==EC_OK && ol<sizeof pid) pid[ol]=0; }
    char hh[80], pkh[160]; hexof(hash33,33,hh); if(pkl) hexof(pk,pkl,pkh); else pkh[0]=0;
    execf(g_db,"INSERT OR IGNORE INTO peer(hash,peer_id,public_key,key_type) VALUES(X'%s','%s',X'%s','%s');",
          hh,pid,pkh,kt[0]?kt:"ed25519");
}
/* insert a signature row from a system/signature entity's data {algorithm,signature,signer,target}. */
static void project_sig(const unsigned char *data, size_t dlen) {
    cbor_rd f; unsigned char tgt[33],sgnr[33],sig[64]; size_t tl=0,sl=0,gl=0;
    if (cbor_map_find(data,dlen,0,"target",&f)) cbor_get_bytes(&f,tgt,sizeof tgt,&tl);
    if (cbor_map_find(data,dlen,0,"signer",&f)) cbor_get_bytes(&f,sgnr,sizeof sgnr,&sl);
    if (cbor_map_find(data,dlen,0,"signature",&f)) cbor_get_bytes(&f,sig,sizeof sig,&gl);
    if (tl!=33||sl!=33||gl!=64) return;
    char th[80],sh[80],gh[160]; hexof(tgt,33,th); hexof(sgnr,33,sh); hexof(sig,64,gh);
    execf(g_db,"INSERT INTO signature(target,signer,algorithm,sig) VALUES(X'%s',X'%s','ed25519',X'%s');",th,sh,gh);
}
/* project one grant-entry (array element of grants[]) into cap_grant + grant_scope rows. */
/* Project one grant map into a (grant, scope) table pair. The pair is parameterised so
 * the SAME projection serves a capability's own grants (cap_grant/grant_scope) and the
 * grants a `capability/request` ASKS FOR (requested_grant/requested_scope) -- the §6.2
 * mint-bound rung compares the two, and a second copy of this walk is how the two
 * shapes would drift apart. */
static void project_grant_into(const unsigned char *buf, size_t len, size_t gpos,
                               const char *gtab, const char *stab, const char *cap_hh,
                               int gidx, const char *granter_pid) {
    execf(g_db,"INSERT OR IGNORE INTO %s(cap_hash,grant_idx) VALUES(X'%s',%d);",gtab,cap_hh,gidx);
    const char *dims[]={"handlers","resources","operations","peers",NULL};
    const char *kinds[]={"include","exclude",NULL};
    for (int di=0;dims[di];di++) {
        cbor_rd dimv;
        if (!cbor_map_find(buf,len,gpos,dims[di],&dimv)) continue;  /* dim = {include:[..],exclude:[..]} */
        for (int ki=0;kinds[ki];ki++) {
            cbor_rd arr;
            if (!cbor_map_find(buf,len,dimv.pos,kinds[ki],&arr)) continue;
            cbor_rd a=arr; int amaj; uint64_t acnt;
            if (cbor_head(&a,&amaj,&acnt)!=0||amaj!=4) continue;
            for (uint64_t j=0;j<acnt;j++) {
                char pat[256]={0}; cbor_rd pv=a;
                if (cbor_get_text(&pv,pat,sizeof pat)==0) {
                    /* escape single quotes defensively */
                    char esc[512]; size_t e=0; for (char *c=pat; *c && e<sizeof esc-2; c++){ if(*c=='\''){esc[e++]='\'';} esc[e++]=*c; } esc[e]=0;
                    execf(g_db,"INSERT INTO %s(cap_hash,grant_idx,dim,kind,pattern,granter_peer_id) "
                               "VALUES(X'%s',%d,'%s','%s','%s','%s');",stab,cap_hh,gidx,dims[di],kinds[ki],esc,granter_pid);
                }
                if (cbor_skip(&a)) break;
            }
        }
    }
}

static void project_grant(const unsigned char *buf, size_t len, size_t gpos, const char *cap_hh,
                          int gidx, const char *granter_pid) {
    project_grant_into(buf,len,gpos,"cap_grant","grant_scope",cap_hh,gidx,granter_pid);
}

/* project a system/capability/token entity (keyed by hash) into cap + grants + multi_signer. */
static void project_cap(const unsigned char *hash33, const unsigned char *buf, size_t len, size_t dpos) {
    cbor_rd f; char cap_hh[80]; hexof(hash33,33,cap_hh);
    /* grantee (bytes33) */
    char grantee_hh[80]="", parent_hh[80]="", granter_hh[80]="";
    unsigned char b[33]; size_t bl=0;
    if (cbor_map_find(buf,len,dpos,"grantee",&f) && cbor_get_bytes(&f,b,sizeof b,&bl)==0 && bl==33) hexof(b,33,grantee_hh);
    if (cbor_map_find(buf,len,dpos,"parent",&f) && cbor_get_bytes(&f,b,sizeof b,&bl)==0 && bl==33) hexof(b,33,parent_hh);
    /* granter: either bytes33 (single) OR a system/capability/multi-granter map (union) */
    int is_multi=0; long long threshold=0;
    if (cbor_map_find(buf,len,dpos,"granter",&f)) {
        cbor_rd g=f; int gmaj; uint64_t garg; cbor_rd probe=g;
        if (cbor_head(&probe,&gmaj,&garg)==0 && gmaj==2 && garg==33) {
            cbor_get_bytes(&g,b,sizeof b,&bl); if(bl==33) hexof(b,33,granter_hh);
        } else if (gmaj==5) {
            is_multi=1;
            cbor_rd thf; if (cbor_map_find(buf,len,g.pos,"threshold",&thf)) { int tm; uint64_t tv; cbor_rd t=thf; if(cbor_head(&t,&tm,&tv)==0&&tm==0) threshold=(long long)tv; }
            cbor_rd sgs; if (cbor_map_find(buf,len,g.pos,"signers",&sgs)) {
                cbor_rd a=sgs; int am; uint64_t ac;
                if (cbor_head(&a,&am,&ac)==0 && am==4) for (uint64_t j=0;j<ac;j++){ unsigned char sh[33]; size_t shl=0; cbor_rd sv=a; if(cbor_get_bytes(&sv,sh,sizeof sh,&shl)==0&&shl==33){ char shh[80]; hexof(sh,33,shh); execf(g_db,"INSERT INTO multi_signer(cap_hash,signer) VALUES(X'%s',X'%s');",cap_hh,shh);} if(cbor_skip(&a))break; }
            }
        }
    }
    /* §6.2 CAP-6a: a temporal field that is PRESENT but not uint64-representable is
     * MALFORMED, and MUST NOT be treated as absent. Reading it with the
     * `if (present && major==0)` idiom below silently drops it, leaving the column NULL
     * -- which is exactly the "no expiry" spelling -- so a hostile expires_at:-1 became
     * a never-expiring capability. The malformed case is recorded separately and denied
     * by its own ladder rung, before the range comparisons it defeats. */
    long long created=0, expires=-1, notbefore=-1; int temporal_bad=0;
    if (cbor_map_find(buf,len,dpos,"created_at",&f)) { int m;uint64_t v;cbor_rd t=f; if(cbor_head(&t,&m,&v)==0&&m==0) created=(long long)v; else temporal_bad=1; }
    if (cbor_map_find(buf,len,dpos,"expires_at",&f)) { int m;uint64_t v;cbor_rd t=f; if(cbor_head(&t,&m,&v)==0&&m==0) expires=(long long)v; else temporal_bad=1; }
    if (cbor_map_find(buf,len,dpos,"not_before",&f)) { int m;uint64_t v;cbor_rd t=f; if(cbor_head(&t,&m,&v)==0&&m==0) notbefore=(long long)v; else temporal_bad=1; }
    char exp[32],nb[32]; if(expires<0) snprintf(exp,sizeof exp,"NULL"); else snprintf(exp,sizeof exp,"%lld",expires);
    if(notbefore<0) snprintf(nb,sizeof nb,"NULL"); else snprintf(nb,sizeof nb,"%lld",notbefore);
    execf(g_db,"INSERT OR IGNORE INTO cap(hash,grantee,granter,parent,created_at,expires_at,not_before,is_multi,multi_threshold,temporal_malformed) "
               "VALUES(X'%s',%s%s%s,%s%s%s,%s%s%s,%lld,%s,%s,%d,%lld,%d);",
          cap_hh,
          grantee_hh[0]?"X'":"", grantee_hh[0]?grantee_hh:"NULL", grantee_hh[0]?"'":"",
          granter_hh[0]?"X'":"", granter_hh[0]?granter_hh:"NULL", granter_hh[0]?"'":"",
          parent_hh[0]?"X'":"",  parent_hh[0]?parent_hh:"NULL",   parent_hh[0]?"'":"",
          created, exp, nb, is_multi, threshold, temporal_bad);
    /* resolve granter's peer_id for the §5.5a canonicalization frame (fallback = local) */
    char granter_pid[128]; snprintf(granter_pid,sizeof granter_pid,"%s",g_peer_id);
    if (granter_hh[0]) {
        sqlite3_stmt *st; char q[160]; snprintf(q,sizeof q,"SELECT peer_id FROM peer WHERE hash=X'%s'",granter_hh);
        if (sqlite3_prepare_v2(g_db,q,-1,&st,NULL)==SQLITE_OK){ if(sqlite3_step(st)==SQLITE_ROW){ const char*p=(const char*)sqlite3_column_text(st,0); if(p&&p[0]) snprintf(granter_pid,sizeof granter_pid,"%s",p);} sqlite3_finalize(st);}
    }
    /* grants[] */
    cbor_rd gr;
    if (cbor_map_find(buf,len,dpos,"grants",&gr)) {
        cbor_rd a=gr; int am; uint64_t ac;
        if (cbor_head(&a,&am,&ac)==0 && am==4) for (uint64_t j=0;j<ac;j++){ project_grant(buf,len,a.pos,cap_hh,(int)j,granter_pid); if(cbor_skip(&a))break; }
    }
    /* revocation marker in the shared store? */
    if (g_store) {
        sqlite3_stmt *st; if (sqlite3_prepare_v2(g_store,"SELECT 1 FROM revoked WHERE cap_hex=?",-1,&st,NULL)==SQLITE_OK){
            sqlite3_bind_text(st,1,cap_hh,-1,SQLITE_TRANSIENT);
            if (sqlite3_step(st)==SQLITE_ROW) execf(g_db,"INSERT OR IGNORE INTO revocation(cap_hash) VALUES(X'%s');",cap_hh);
            sqlite3_finalize(st);
        }
    }
}

/* iterate envelope.included (map hash→entity), projecting peers (pass 1) then caps+sigs (pass 2). */
static void project_included(const unsigned char *buf, size_t len, size_t inc_map_pos, int pass) {
    cbor_rd r={buf,len,inc_map_pos}; int maj; uint64_t n;
    if (cbor_head(&r,&maj,&n)!=0 || maj!=5) return;
    for (uint64_t i=0;i<n;i++) {
        unsigned char key[33]; size_t kl=0; cbor_rd kv=r;
        if (cbor_get_bytes(&kv,key,sizeof key,&kl)!=0) { if(cbor_skip(&r))return; if(cbor_skip(&r))return; continue; }
        if (cbor_skip(&r)) return;                 /* advance past key */
        size_t entpos=r.pos;                       /* value = entity {data,type,content_hash} */
        cbor_rd tf,df; char etype[80]={0};
        if (cbor_map_find(buf,len,entpos,"type",&tf)) cbor_get_text(&tf,etype,sizeof etype);
        int have_d = cbor_map_find(buf,len,entpos,"data",&df);
        if (have_d && kl==33) {
            const unsigned char *dp=NULL; size_t dl=0;
            if (cbor_value_slice(buf,len,df.pos,&dp,&dl)!=0 || !dp) { if(cbor_skip(&r))return; continue; }
            if (pass==1 && !strcmp(etype,"system/peer")) project_peer(key,dp,dl);
            if (pass==2 && !strcmp(etype,"system/signature")) project_sig(dp,dl);
            if (pass==2 && !strcmp(etype,"system/capability/token")) project_cap(key,buf,len,df.pos);
        }
        if (cbor_skip(&r)) return;                 /* advance past value */
    }
}

/* Defined in handlers.inc.c, which is textually included below the projection: the
 * §6.2 mint-bound rung needs the params slice at PROJECTION time, not at handler time. */
static int exec_params_data(const unsigned char *buf, size_t len, size_t rdata_pos,
                            const unsigned char **dp, size_t *dl);

/* Project the full request + authority chain and run verify_ladder.sql → (status, code). */
static void project_and_verify(const unsigned char *buf, size_t len, size_t root_pos, size_t rdata_pos,
                               const char *uri, const char *op, char *status, char *code) {
    execf(g_db,"DELETE FROM peer;DELETE FROM cap;DELETE FROM multi_signer;DELETE FROM cap_grant;"
               "DELETE FROM grant_scope;DELETE FROM signature;DELETE FROM revocation;"
               "DELETE FROM request;DELETE FROM request_resource;"
               "DELETE FROM requested_grant;DELETE FROM requested_scope;");
    seed_auth_handlers();
    /* always project my own peer identity (the granter frame for the seed cap) */
    { wbuf pd={0}; if(!my_peer_data(&pd)){ char hh[80],pkh[160]; hexof(g_id_hash,33,hh); hexof(g_pub,32,pkh);
        execf(g_db,"INSERT OR IGNORE INTO peer(hash,peer_id,public_key,key_type) VALUES(X'%s','%s',X'%s','ed25519');",hh,g_peer_id,pkh);} free(pd.p); }
    /* included: pass 1 peers, pass 2 caps + sigs */
    cbor_rd incf;
    if (cbor_map_find(buf,len,0,"included",&incf)) { project_included(buf,len,incf.pos,1); project_included(buf,len,incf.pos,2); }
    /* the EXECUTE root hash (content_hash field the exec-sig targets) + author + capability */
    unsigned char rootch[33]; size_t rchl=0; char rootch_hh[80]="", author_hh[80]="", cap_hh[80]="";
    { cbor_rd cf; if (cbor_map_find(buf,len,root_pos,"content_hash",&cf) && cbor_get_bytes(&cf,rootch,sizeof rootch,&rchl)==0 && rchl==33) hexof(rootch,33,rootch_hh); }
    { cbor_rd af; unsigned char b[33]; size_t bl=0; if (cbor_map_find(buf,len,rdata_pos,"author",&af) && cbor_get_bytes(&af,b,sizeof b,&bl)==0 && bl==33) hexof(b,33,author_hh); }
    { cbor_rd cf; unsigned char b[33]; size_t bl=0; if (cbor_map_find(buf,len,rdata_pos,"capability",&cf) && cbor_get_bytes(&cf,b,sizeof b,&bl)==0 && bl==33) hexof(b,33,cap_hh); }
    /* §6.2 mint-bound: project the grants a capability request/delegate ASKS FOR, so the
     * ladder can check them against the presented caller cap as a subset query. Both
     * frames are LOCAL -- the mint is self-issued, so passing the caller's granter frame
     * to either side is the §5.5a over-scoping bug. */
    if (!strcmp(op,"request") || !strcmp(op,"delegate")) {
        const unsigned char *pd=NULL; size_t pl=0;
        exec_params_data(buf,len,rdata_pos,&pd,&pl);
        cbor_rd gr;
        if (pd && rootch_hh[0] && cbor_map_find(pd,pl,0,"grants",&gr)) {
            cbor_rd a=gr; int am; uint64_t ac;
            if (cbor_head(&a,&am,&ac)==0 && am==4)
                for (uint64_t j=0;j<ac;j++){
                    project_grant_into(pd,pl,a.pos,"requested_grant","requested_scope",
                                       rootch_hh,(int)j,g_peer_id);
                    if(cbor_skip(&a))break;
                }
        }
    }
    /* resource-target(s) → request_resource. `resource` is a bare map {targets:[...],exclude?:[...]}. */
    { cbor_rd rf; if (cbor_map_find(buf,len,rdata_pos,"resource",&rf)) {
            cbor_rd tf; if (cbor_map_find(buf,len,rf.pos,"targets",&tf)) {
                cbor_rd a=tf; int am; uint64_t ac; if(cbor_head(&a,&am,&ac)==0&&am==4) for(uint64_t j=0;j<ac;j++){ char t[512]={0}; cbor_rd tv=a; if(cbor_get_text(&tv,t,sizeof t)==0){ char pth[640]; if(strncmp(t,"entity://",9)==0)snprintf(pth,sizeof pth,"/%s",t+9); else if(t[0]=='/')snprintf(pth,sizeof pth,"%s",t); else snprintf(pth,sizeof pth,"/%s/%s",g_peer_id,t); char e[700];size_t k=0; for(char*c=pth;*c&&k<sizeof e-2;c++){if(*c=='\''){e[k++]='\'';}e[k++]=*c;}e[k]=0; execf(g_db,"INSERT INTO request_resource(kind,path) VALUES('target','%s');",e);} if(cbor_skip(&a))break; }
            }
    } }
    char esc_uri[600]; size_t k=0; for (const char*c=uri;*c&&k<sizeof esc_uri-2;c++){if(*c=='\''){esc_uri[k++]='\'';}esc_uri[k++]=*c;} esc_uri[k]=0;
    execf(g_db,"INSERT INTO request(content_hash,wire_hash,author,capability,uri,operation,now_ms,local_peer_id,supports_revocation) "
               "VALUES(%s%s%s,%s%s%s,%s%s%s,%s%s%s,'%s','%s',%llu,'%s',1);",
          rootch_hh[0]?"X'":"",rootch_hh[0]?rootch_hh:"NULL",rootch_hh[0]?"'":"",
          rootch_hh[0]?"X'":"",rootch_hh[0]?rootch_hh:"NULL",rootch_hh[0]?"'":"",   /* wire_hash == claimed root hash */
          author_hh[0]?"X'":"",author_hh[0]?author_hh:"NULL",author_hh[0]?"'":"",
          cap_hh[0]?"X'":"",cap_hh[0]?cap_hh:"NULL",cap_hh[0]?"'":"",
          esc_uri, op, (unsigned long long)wall_ms(), g_peer_id);
    /* run the AUTHORED verdict query */
    status[0]=code[0]=0;
    sqlite3_stmt *st;
    if (g_ladder && sqlite3_prepare_v2(g_db,g_ladder,-1,&st,NULL)==SQLITE_OK) {
        if (sqlite3_step(st)==SQLITE_ROW) {
            const unsigned char *s=sqlite3_column_text(st,0), *c=sqlite3_column_text(st,1);
            if(s) snprintf(status,8,"%s",s);
            if(c) snprintf(code,64,"%s",c);
        }
        sqlite3_finalize(st);
    }
    if (!status[0]) { snprintf(status,8,"500"); snprintf(code,64,"internal_error"); }
}

/* ══════════════════════════ handler bodies (run only after the SQL verdict = ok) ══════════════ */
static void dispatch_frame(int fd, conn_state *cs, const unsigned char *buf, size_t len);   /* fwd (§6.11 reentry) */
#include "handlers.inc.c"

/* Dispatch one decoded frame (§6.5). connect → handshake; else project facts, ask verify_ladder
 * for the verdict, and on 'ok' run the resolved handler body. */
static void dispatch_frame(int fd, conn_state *cs, const unsigned char *buf, size_t len) {
    cbor_rd root, rdata, f;
    char rtype[80]={0}, rid[128]={0}, uri[512]={0}, op[128]={0};
    if (!cbor_map_find(buf,len,0,"root",&root)) { (void)emit_error(fd,"",400,"protocol_error"); return; }
    { cbor_rd tf; if (cbor_map_find(buf,len,root.pos,"type",&tf)) cbor_get_text(&tf,rtype,sizeof rtype); }
    if (!cbor_map_find(buf,len,root.pos,"data",&rdata)) { (void)emit_error(fd,"",400,"protocol_error"); return; }
    if (cbor_map_find(buf,len,rdata.pos,"request_id",&f)) cbor_get_text(&f,rid,sizeof rid);
    if (cbor_map_find(buf,len,rdata.pos,"uri",&f)) cbor_get_text(&f,uri,sizeof uri);
    if (cbor_map_find(buf,len,rdata.pos,"operation",&f)) cbor_get_text(&f,op,sizeof op);

    if (strcmp(rtype,"system/protocol/execute")!=0) {
        if (strcmp(rtype,"system/protocol/execute/response")==0) { (void)reentry_route(fd, cs, buf, len); return; }  /* §6.11 reentry demux */
        (void)emit_error(fd, rid, 400, "protocol_error"); return;
    }

    /* §4.2: system/protocol/connect is the sole pre-authorized path. */
    if (strstr(uri,"system/protocol/connect")!=NULL) {
        if (strcmp(op,"hello")==0) {
            if (cs->established) { (void)emit_error(fd,rid,409,"connection_already_established"); return; }
            (void)handle_hello(fd, rid, cs, buf, len); return;
        }
        if (strcmp(op,"authenticate")==0) {
            /* FM-1 (§4.2, §4.7 row 6, 0.8.2.1): an authenticate arriving before any
             * hello nonce was issued is a captured authenticate replayed onto a fresh
             * connection — an authentication failure, so 401 invalid_nonce (the same
             * status handle_authenticate gives the established-connection replay), not
             * the out-of-order 400. §4.7's out-of-order row no longer names this input. */
            if (!cs->nonce_set) { (void)emit_error(fd,rid,401,"invalid_nonce"); return; }
            (void)handle_authenticate(fd, rid, cs, buf, len); return;
        }
        (void)emit_error(fd, rid, 400, "connection_sequence_error"); return;
    }

    if (!cs->established) { (void)emit_error(fd, rid, 403, "capability_denied"); return; }

    /* §1.4 normalize the dispatch URI: strip the entity:// scheme → an absolute /{peer}/... path
     * (the wire uri is entity://{peer}/rest; handler registration paths + resolve.sql are /{peer}/…). */
    char nuri[600];
    if (strncmp(uri,"entity://",9)==0) snprintf(nuri,sizeof nuri,"/%s",uri+9);
    else if (uri[0]=='/') snprintf(nuri,sizeof nuri,"%s",uri);
    else snprintf(nuri,sizeof nuri,"/%s/%s",g_peer_id,uri);

    /* §1.4 / §6.5 step 3: the ADDRESS gate. An inbound EXECUTE naming another
     * peer's namespace is refused here — after canonicalization, BEFORE handler
     * resolution and before the authority ladder runs — with 400 invalid_request.
     *
     * This is a gate, not an ordering preference (§6.5, 0.8.2.2). Reaching the
     * refusal by resolving the local handler at the remaining path and letting
     * §5.2 Dimension 4 deny is explicitly forbidden: it answers 403/404 for what
     * is specified as 400, and it ALLOWS the request outright whenever the
     * presented grant happens to carry a matching `peers` scope — a foreign-
     * namespace privilege escalation. Measured here before the gate existed:
     * (404, "not_found"), reached by resolution miss rather than by address. */
    {
        const char *seg = nuri + 1;                 /* nuri is always "/{peer}/…" */
        const char *end = strchr(seg, '/');
        size_t seglen = end ? (size_t)(end - seg) : strlen(seg);
        size_t locallen = strlen(g_peer_id);
        if (seglen != locallen || memcmp(seg, g_peer_id, locallen) != 0) {
            (void)emit_error(fd, rid, 400, "invalid_request"); return;
        }
    }

    /* §6.5: project the §5.8 chain, ask verify_ladder.sql for the (status,code) verdict. */
    char status[8], code[64];
    project_and_verify(buf,len,root.pos,rdata.pos,nuri,op,status,code);
    if (strcmp(status,"200")!=0) { (void)emit_error(fd, rid, (unsigned)atoi(status), code); return; }

    /* verdict = ok → run the resolved handler body. */
    char pattern[512];
    if (!resolve_handler(nuri,pattern,sizeof pattern)) { (void)emit_error(fd, rid, 404, "not_found"); return; }
    dispatch_body(fd, cs, rid, pattern, nuri, op, buf, len, rdata.pos);
}

/* ══════════════════════════ server loop (single-thread, per-conn to completion) ══════════════ */
static int serve(int port) {
    int ls = socket(AF_INET, SOCK_STREAM, 0); if (ls<0) return 2;
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons((uint16_t)port);
    if (bind(ls,(struct sockaddr*)&a,sizeof a)<0) { perror("bind"); return 2; }
    if (listen(ls,64)<0) { perror("listen"); return 2; }
    signal(SIGCHLD, SIG_IGN);       /* auto-reap connection children — no zombies (§4.9(b) bound fds) */
    signal(SIGPIPE, SIG_IGN);       /* a peer that closes mid-write is a per-request signal, not a crash */
    fprintf(stderr,"ec-sql-peer listening 127.0.0.1:%d as %s\n", port, g_peer_id);
    for (;;) {
        int cfd = accept(ls,NULL,NULL); if (cfd<0) continue;
        setsockopt(cfd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one);   /* §7b */
        /* §4.8: fork per connection — each connection gets its own process + store copy, so
         * inbound frames on DIFFERENT connections proceed concurrently (the oracle opens several
         * probe connections at once) and the store is race-free by process isolation. Each frame
         * within a connection is still dispatched to completion (host-serialized per conn). */
        pid_t kid = fork();
        if (kid == 0) {
            close(ls);
            init_child_dbs();          /* per-child authority :memory: db + shared store (WAL) */
            conn_state cs; memset(&cs,0,sizeof cs);
            for (;;) {
                unsigned char *fb; uint32_t fl; int r = read_frame(cfd,&fb,&fl);
                if (r==0 || r==-1) break;
                if (r==-413) { (void)emit_error(cfd,"",413,"payload_too_large"); break; }  /* §4.10(a) */
                dispatch_frame(cfd, &cs, fb, fl);                   /* §4.9(c): dispatch never drops silently */
                free(fb);
            }
            close(cfd); _exit(0);
        }
        close(cfd);   /* parent: keep accepting */
    }
}

/* ══════════════════════════ --selftest: self-driven smoke initiator ══════════════════════════ */
/* A minimal initiator that does §4.1 legs 1-2 (hello, authenticate) both-ways-complete for a
 * client-style initiator, then a post-auth EXECUTE to an unregistered path (expect 404), then
 * two interleaved requests with distinct request_ids to confirm the responder echoes each id
 * (§6.11 request_id demux). Runs in a forked child against the loopback listener. */
/* The disposition CODE of the last response read. A selftest line that prints only
 * a status says `401` and leaves the reader to guess which of the nine 401 sites
 * produced it; the code names it. Kept as a single global because this client runs
 * strictly one frame at a time on one fd. */
static char g_last_code[64];
static int recv_response(int fd, char *rid_out, unsigned *status_out, char *rtype_out) {
    unsigned char *fb; uint32_t fl; if (read_frame(fd,&fb,&fl)!=1) return -1;
    cbor_rd root, rdata, f;
    rid_out[0]=0; *status_out=0; rtype_out[0]=0; g_last_code[0]=0;
    if (cbor_map_find(fb,fl,0,"root",&root)) {
        cbor_rd tf; if (cbor_map_find(fb,fl,root.pos,"type",&tf)) cbor_get_text(&tf,rtype_out,80);
        if (cbor_map_find(fb,fl,root.pos,"data",&rdata)) {
            if (cbor_map_find(fb,fl,rdata.pos,"request_id",&f)) cbor_get_text(&f,rid_out,128);
            if (cbor_map_find(fb,fl,rdata.pos,"status",&f)) { int mj; uint64_t v; cbor_rd t=f; if (cbor_head(&t,&mj,&v)==0&&mj==0) *status_out=(unsigned)v; }
            /* result type */
            cbor_rd res; if (cbor_map_find(fb,fl,rdata.pos,"result",&res)) {
                cbor_rd rt; if (cbor_map_find(fb,fl,res.pos,"type",&rt)) cbor_get_text(&rt,rtype_out,80);
                cbor_rd rd2, cf; if (cbor_map_find(fb,fl,res.pos,"data",&rd2) && cbor_map_find(fb,fl,rd2.pos,"code",&cf)) cbor_get_text(&cf,g_last_code,sizeof g_last_code);
            }
        }
    }
    free(fb); return 0;
}
/* send an EXECUTE envelope on the connect path (no author/capability — §4.2 pre-authorized). */
static int send_execute(int fd, const char *rid, const char *uri, const char *op,
                        const unsigned char *params_data, size_t pdlen, const unsigned char *inc, size_t inc_len) {
    static const unsigned char empty=0xa0;
    if (!params_data) { params_data=&empty; pdlen=1; }
    unsigned char ph[33]; ec_entity_hash("primitive/any",params_data,pdlen,ph);
    wbuf par={0}; if (wb_entity(&par,"primitive/any",params_data,pdlen,ph)) { free(par.p); return -1; }
    wbuf ed={0};
    int bad = wb_head(&ed,5,4)
        || wb_text(&ed,"operation")  || wb_text(&ed,op)
        || wb_text(&ed,"params")     || wb_raw(&ed,par.p,par.len)
        || wb_text(&ed,"request_id") || wb_text(&ed,rid)
        || wb_text(&ed,"uri")        || wb_text(&ed,uri);
    unsigned char eh[33]; wbuf ee={0}, env={0};
    bad = bad || ec_entity_hash("system/protocol/execute",ed.p,ed.len,eh)
        || wb_entity(&ee,"system/protocol/execute",ed.p,ed.len,eh)
        || wb_head(&env,5,2) || wb_text(&env,"root") || wb_raw(&env,ee.p,ee.len)
        || wb_text(&env,"included") || wb_raw(&env, inc?inc:&empty, inc?inc_len:1);
    int rc = bad ? -1 : send_envelope(fd, env.p, env.len);
    free(par.p); free(ed.p); free(ee.p); free(env.p); return rc;
}
static int selftest_client(int port) {
    int fd = socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 2;
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons((uint16_t)port);
    for (int i=0;i<50 && connect(fd,(struct sockaddr*)&a,sizeof a)<0;i++) usleep(20000);
    int fails=0; char rid[128], rt[80]; unsigned st;

    /* leg 1: hello — parse the full response for status/type/rid AND the issued §4.6 nonce */
    unsigned char nonce[64]={0}; size_t nonce_len=0;
    if (send_execute(fd,"hello-1","system/protocol/connect","hello",NULL,0,NULL,0)) { fprintf(stderr,"send hello\n"); return 2; }
    { unsigned char *fb; uint32_t fl; if (read_frame(fd,&fb,&fl)!=1) { fprintf(stderr,"recv hello\n"); return 2; }
      cbor_rd root,tf,rdata,ridf,statf,res,resd,nf; st=0; rt[0]=rid[0]=0;
      if (cbor_map_find(fb,fl,0,"root",&root)) {
        if (cbor_map_find(fb,fl,root.pos,"type",&tf)) cbor_get_text(&tf,rt,sizeof rt);
        if (cbor_map_find(fb,fl,root.pos,"data",&rdata)) {
          if (cbor_map_find(fb,fl,rdata.pos,"request_id",&ridf)) cbor_get_text(&ridf,rid,sizeof rid);
          if (cbor_map_find(fb,fl,rdata.pos,"status",&statf)) { int mj; uint64_t v; cbor_rd t=statf; if (cbor_head(&t,&mj,&v)==0&&mj==0) st=(unsigned)v; }
          if (cbor_map_find(fb,fl,rdata.pos,"result",&res)) {
            cbor_rd rtt; if (cbor_map_find(fb,fl,res.pos,"type",&rtt)) cbor_get_text(&rtt,rt,sizeof rt);
            if (cbor_map_find(fb,fl,res.pos,"data",&resd) && cbor_map_find(fb,fl,resd.pos,"nonce",&nf))
              cbor_get_bytes(&nf,nonce,sizeof nonce,&nonce_len);
          }
        }
      }
      free(fb);
    }
    int ok1 = (st==200 && strcmp(rt,"system/protocol/connect/hello")==0 && strcmp(rid,"hello-1")==0 && nonce_len==32);
    printf("  [%s] leg1 hello              → status=%u type=%s rid=%s nonce=%zuB\n", ok1?"PASS":"FAIL", st, rt, rid, nonce_len); fails += !ok1;

    /* Build authenticate: our initiator uses its OWN generated identity. */
    unsigned char ipriv[32], ipub[32]; ec_ed25519_keygen(ipriv,ipub);
    char ipeer[128]; size_t iolen=0; ec_peerid_format(1,0,ipub,32,(uint8_t*)ipeer,sizeof ipeer-1,&iolen); ipeer[iolen]=0;
    /* authenticate entity data {key_type, nonce, peer_id, public_key} (canonical key order) */
    wbuf ad={0};
    int abad = wb_head(&ad,5,4)
        || wb_text(&ad,"key_type")   || wb_text(&ad,"ed25519")
        || wb_text(&ad,"nonce")      || wb_bytes(&ad,nonce,nonce_len)
        || wb_text(&ad,"peer_id")    || wb_text(&ad,ipeer)
        || wb_text(&ad,"public_key") || wb_bytes(&ad,ipub,32);
    unsigned char ahash[33]; abad = abad || ec_entity_hash("system/protocol/connect/authenticate",ad.p,ad.len,ahash);
    /* peer + signature entities for included */
    wbuf ipd={0}; abad = abad || wb_head(&ipd,5,2) || wb_text(&ipd,"key_type")||wb_text(&ipd,"ed25519")||wb_text(&ipd,"public_key")||wb_bytes(&ipd,ipub,32);
    unsigned char iph[33]; ec_entity_hash("system/peer",ipd.p,ipd.len,iph);
    unsigned char asig[64]; abad = abad || ec_ed25519_sign(ipriv,ahash,33,asig)!=EC_OK;
    wbuf sd={0}; abad = abad || wb_head(&sd,5,4)||wb_text(&sd,"algorithm")||wb_text(&sd,"ed25519")||wb_text(&sd,"signature")||wb_bytes(&sd,asig,64)||wb_text(&sd,"signer")||wb_bytes(&sd,iph,33)||wb_text(&sd,"target")||wb_bytes(&sd,ahash,33);
    unsigned char sh[33]; ec_entity_hash("system/signature",sd.p,sd.len,sh);
    wbuf inc={0}; abad = abad || wb_head(&inc,5,2) || wb_bytes(&inc,iph,33)||wb_entity(&inc,"system/peer",ipd.p,ipd.len,iph) || wb_bytes(&inc,sh,33)||wb_entity(&inc,"system/signature",sd.p,sd.len,sh);
    if (abad) { fprintf(stderr,"build auth\n"); return 2; }
    if (send_execute(fd,"auth-1","system/protocol/connect","authenticate",ad.p,ad.len,inc.p,inc.len)) return 2;
    if (recv_response(fd,rid,&st,rt)) return 2;
    int ok2 = (st==200 && strcmp(rt,"system/capability/grant")==0 && strcmp(rid,"auth-1")==0);
    printf("  [%s] leg2 authenticate (PoP) → status=%u type=%s rid=%s\n", ok2?"PASS":"FAIL", st, rt, rid); fails += !ok2;
    free(ad.p); free(ipd.p); free(sd.p); free(inc.p);

    /* post-auth EXECUTE to an unregistered path → 404 */
    char unreg[256]; snprintf(unreg,sizeof unreg,"/%s/local/nope/x", g_peer_id);
    if (send_execute(fd,"req-404",unreg,"get",NULL,0,NULL,0)) return 2;
    if (recv_response(fd,rid,&st,rt)) return 2;
    int ok3 = (st==404 && strcmp(rid,"req-404")==0);
    printf("  [%s] 404 unregistered path   → status=%u code=%s rid=%s\n", ok3?"PASS":"FAIL", st, g_last_code, rid); fails += !ok3;

    /* request_id demux: two interleaved requests, distinct ids, each response echoes its own id */
    char reg[256]; snprintf(reg,sizeof reg,"/%s/system/tree", g_peer_id);
    if (send_execute(fd,"rid-A",reg,"get",NULL,0,NULL,0)) return 2;
    if (send_execute(fd,"rid-B",unreg,"get",NULL,0,NULL,0)) return 2;
    char ridA[128], ridB[128]; unsigned stA, stB; char rtA[80], rtB[80];
    if (recv_response(fd,ridA,&stA,rtA) || recv_response(fd,ridB,&stB,rtB)) return 2;
    int ok4 = (strcmp(ridA,"rid-A")==0 && strcmp(ridB,"rid-B")==0 && stA==200 && stB==404);
    printf("  [%s] request_id demux        → (%s:%u)(%s:%u)\n", ok4?"PASS":"FAIL", ridA,stA, ridB,stB); fails += !ok4;

    close(fd);
    printf("== smoke: %d checks failed ==\n", fails);
    return fails ? 1 : 0;
}

/* ══════════════════════════ main ══════════════════════════ */
int main(int argc, char **argv) {
    const char *name = getenv("EC_NAME"); int port = 15250; int selftest = 0; int validate = 0;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--name") && i+1<argc) name = argv[++i];
        else if (!strcmp(argv[i],"--port") && i+1<argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--selftest")) selftest = 1;
        else if (!strcmp(argv[i],"--validate")) validate = 1;
        else if (!strcmp(argv[i],"--debug-open-grants")) g_open_grants = 1;
    }
    g_validate = validate;   /* --validate: system/validate conformance handlers live */
    init_identity(name);
    if (!g_peer_id[0]) { fprintf(stderr,"identity init failed\n"); return 2; }
    { wbuf pd={0}; if(!my_peer_data(&pd)) ec_entity_hash("system/peer",pd.p,pd.len,g_id_hash); free(pd.p); }

    /* Seed the shared store file (parent): schema + §9.5 type registry + handler registrations.
     * Each fork-child then opens it (WAL) + a fresh :memory: authority db for the SQL verdict. */
    seed_store_file();

    if (selftest) {
        printf("== ec-sql-peer --selftest (self-driven §4.1 handshake + §6.6 404 + §6.11 demux) ==\n");
        printf("   seam: %s\n", ec_seam_impl_info());
        pid_t pid = fork();
        if (pid==0) { /* child = server */ _exit(serve(port)); }
        int rc = selftest_client(port);
        kill(pid, 15); int ws; waitpid(pid,&ws,0);
        return rc;
    }
    return serve(port);
}
