/* Offline structural KAT for the §5.2 `peers` grant dimension
 * (HANDOFF-TO-ARCH-2026-08-13-peers-grant-dimension-oracle-gap.md). Unlike the
 * other authz-*-offline KATs, this one does NOT replay a captured validate-peer
 * wire vector: the handoff doc's headline finding is that the conformance oracle
 * has ZERO test coverage of this dimension (`grep -rn '"peers"' cmd/internal/
 * validate/*.go` @ entity-core-go returns nothing), so no such vector exists to
 * capture. `check_permission`'s scope matching is pure CBOR/logic (no crypto),
 * so this KAT hand-builds minimal synthetic capability-grant CBOR in memory and
 * exercises `cap_permits` (mirrored from `src/ecodec/ecodec.c`, post-fix) directly
 * — the regression guard for the fix, since the oracle cannot provide one.
 *
 * Build+run via `make authzpeerskat`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { const unsigned char *p; size_t len; size_t pos; } cbor_rd;
static int cbor_head(cbor_rd *r, int *major, uint64_t *arg) {
    if (r->pos >= r->len) return -1;
    unsigned char ib = r->p[r->pos++]; *major = ib >> 5; int ai = ib & 0x1f;
    if (ai < 24) { *arg = ai; return 0; }
    if (ai == 24) { if (r->pos+1>r->len) return -1; *arg = r->p[r->pos++]; return 0; }
    if (ai == 25) { if (r->pos+2>r->len) return -1; *arg=((uint64_t)r->p[r->pos]<<8)|r->p[r->pos+1]; r->pos+=2; return 0; }
    if (ai == 26) { if (r->pos+4>r->len) return -1; *arg=((uint64_t)r->p[r->pos]<<24)|((uint64_t)r->p[r->pos+1]<<16)|((uint64_t)r->p[r->pos+2]<<8)|r->p[r->pos+3]; r->pos+=4; return 0; }
    if (ai == 27) { if (r->pos+8>r->len) return -1; uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|r->p[r->pos+i]; r->pos+=8; *arg=v; return 0; }
    return -1;
}
static int cbor_skip(cbor_rd *r) {
    int major; uint64_t arg; if (cbor_head(r,&major,&arg)!=0) return -1;
    switch (major) {
        case 0: case 1: case 7: return 0;
        case 2: case 3: if (r->pos+arg>r->len) return -1; r->pos += (size_t)arg; return 0;
        case 4: for (uint64_t i=0;i<arg;i++) if (cbor_skip(r)!=0) return -1; return 0;
        case 5: for (uint64_t i=0;i<arg;i++){ if(cbor_skip(r)!=0)return -1; if(cbor_skip(r)!=0)return -1;} return 0;
        default: return -1;
    }
}
static int cbor_map_find(const unsigned char *buf, size_t len, size_t mp, const char *key, cbor_rd *out) {
    cbor_rd r = { buf, len, mp }; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=5) return 0;
    size_t kl0 = strlen(key);
    for (uint64_t i=0;i<n;i++){ int km; uint64_t kl; size_t kh=r.pos;
        if (cbor_head(&r,&km,&kl)!=0 || km!=3){ r.pos=kh; if(cbor_skip(&r)!=0)return 0; if(cbor_skip(&r)!=0)return 0; continue; }
        if (r.pos+kl>len) return 0;
        int m = (kl==kl0 && memcmp(r.p+r.pos,key,kl0)==0); r.pos += (size_t)kl;
        if (m){ out->p=buf; out->len=len; out->pos=r.pos; return 1; }
        if (cbor_skip(&r)!=0) return 0;
    }
    return 0;
}
static int cbor_get_text(cbor_rd *r, char *out, size_t cap) {
    int major; uint64_t arg; cbor_rd t=*r;
    if (cbor_head(&t,&major,&arg)!=0 || major!=3 || t.pos+arg>t.len || arg>=cap) return -1;
    memcpy(out,t.p+t.pos,(size_t)arg); out[arg]='\0'; return 0;
}

/* §5.4/§5.2 id-scope pattern matching (peer-relative forms), mirrors ecodec.c
 * `matches_pattern_rel` — bare `*` any, trailing "prefix/*" prefix, else exact. */
static int matches_pattern_rel(const char *path, const char *pat) {
    if (strcmp(pat,"*")==0) return 1;
    size_t pl=strlen(pat);
    if (pl>=2 && pat[pl-1]=='*' && pat[pl-2]=='/') return strncmp(path,pat,pl-1)==0;
    return strcmp(path,pat)==0;
}
static int array_any_match(const unsigned char *buf, size_t len, size_t ap, const char *v) {
    cbor_rd r={buf,len,ap}; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=4) return 0;
    for (uint64_t i=0;i<n;i++){ char e[256]; cbor_rd ev={buf,len,r.pos};
        if (cbor_get_text(&ev,e,sizeof e)!=0) return 0;
        if (matches_pattern_rel(v,e)) return 1;
        if (cbor_skip(&r)!=0) return 0;
    }
    return 0;
}
static int matches_scope_rel(const unsigned char *buf, size_t len, size_t sp, const char *v) {
    cbor_rd inc,exc;
    if (!cbor_map_find(buf,len,sp,"include",&inc)) return 0;
    if (!array_any_match(buf,len,inc.pos,v)) return 0;
    if (cbor_map_find(buf,len,sp,"exclude",&exc) && array_any_match(buf,len,exc.pos,v)) return 0;
    return 1;
}
/* §5.2 peers dimension: `grant.peers or {include: [local_peer_id]}`. Mirrors
 * ecodec.c `matches_peers_scope` post-fix. */
static int matches_peers_scope(const unsigned char *buf, size_t len, size_t ge,
                               const char *target_peer, const char *local_pid) {
    cbor_rd sc;
    if (!cbor_map_find(buf,len,ge,"peers",&sc)) return strcmp(target_peer,local_pid)==0;
    return matches_scope_rel(buf,len,sc.pos,target_peer);
}
/* §5.2 check_permission, mirrors ecodec.c `cap_permits` post-fix (all four
 * dimensions: operations, handlers, peers, resources). Resource dimension left
 * unexercised by this KAT (NULL throughout) — it is already covered by
 * authz-verify-offline.c / authz-deny-offline.c; this file is scoped to `peers`. */
static int cap_permits(const unsigned char *buf, size_t len, size_t cap_pos,
                       const char *op, const char *handler, const char *resource,
                       const char *local_pid, const char *target_peer) {
    cbor_rd d,grants;
    if (!cbor_map_find(buf,len,cap_pos,"data",&d)) return 0;
    if (!cbor_map_find(buf,len,d.pos,"grants",&grants)) return 0;
    cbor_rd r={buf,len,grants.pos}; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=4) return 0;
    for (uint64_t i=0;i<n;i++){ size_t ge=r.pos; cbor_rd sc; int okg=1;
        if (!cbor_map_find(buf,len,ge,"operations",&sc) || !matches_scope_rel(buf,len,sc.pos,op)) okg=0;
        if (okg && (!cbor_map_find(buf,len,ge,"handlers",&sc) || !matches_scope_rel(buf,len,sc.pos,handler))) okg=0;
        if (okg && !matches_peers_scope(buf,len,ge,target_peer,local_pid)) okg=0;
        if (okg && resource) { if (!cbor_map_find(buf,len,ge,"resources",&sc) || !matches_scope_rel(buf,len,sc.pos,resource)) okg=0; }
        if (okg) return 1;
        if (cbor_skip(&r)!=0) return 0;
    }
    return 0;
}

/* ── minimal definite-length CBOR writer (test-only construction) ──────────── */
typedef struct { unsigned char *p; size_t len, cap; } wbuf;
static void wb_put(wbuf *w, const unsigned char *b, size_t n) {
    if (w->len + n > w->cap) { fprintf(stderr,"wbuf overflow\n"); exit(2); }
    memcpy(w->p + w->len, b, n); w->len += n;
}
static void wb_head(wbuf *w, int major, uint64_t n) {
    unsigned char b[9];
    if (n < 24) { b[0]=(unsigned char)((major<<5)|n); wb_put(w,b,1); return; }
    if (n < 256) { b[0]=(unsigned char)((major<<5)|24); b[1]=(unsigned char)n; wb_put(w,b,2); return; }
    b[0]=(unsigned char)((major<<5)|25); b[1]=(unsigned char)(n>>8); b[2]=(unsigned char)n; wb_put(w,b,3);
}
static void wb_text(wbuf *w, const char *s) { size_t n=strlen(s); wb_head(w,3,n); wb_put(w,(const unsigned char*)s,n); }
static void wb_map(wbuf *w, uint64_t npairs) { wb_head(w,5,npairs); }
static void wb_arr(wbuf *w, uint64_t n) { wb_head(w,4,n); }
/* {include: [ids...]} id-scope */
static void wb_id_scope(wbuf *w, const char **incl, int n) {
    wb_map(w,1); wb_text(w,"include"); wb_arr(w,(uint64_t)n);
    for (int i=0;i<n;i++) wb_text(w,incl[i]);
}

#define CHECK(cond,msg) do { printf("  [%s] %s\n",(cond)?"PASS":"FAIL",msg); if(!(cond)) fails++; } while(0)

static const char *PEER_A = "LocalPeerAAAAAAAAAAAAAAAAAAAAAAAAA";   /* local */
static const char *PEER_B = "ForeignPeerBBBBBBBBBBBBBBBBBBBBBBBB";  /* not local */
static const char *PEER_C = "ForeignPeerCCCCCCCCCCCCCCCCCCCCCCCC";  /* also not local, not in any include */

/* Build a one-grant capability entity: {data: {grants: [{operations, handlers,
 * peers?}]}}. `peers_incl`/`n_peers` NULL/0 omits the `peers` field entirely
 * (exercises the default-to-local-only fallback). */
static size_t build_cap(unsigned char *out, size_t cap,
                        const char **peers_incl, int n_peers) {
    wbuf w = { out, 0, cap };
    const char *ops[1] = { "get" };
    const char *hdlrs[1] = { "system/tree" };
    int npairs = (peers_incl != NULL) ? 3 : 2;
    wb_map(&w,1); wb_text(&w,"data");
      wb_map(&w,1); wb_text(&w,"grants");
        wb_arr(&w,1);
          wb_map(&w,(uint64_t)npairs);
            wb_text(&w,"operations"); wb_id_scope(&w, ops, 1);
            wb_text(&w,"handlers");   wb_id_scope(&w, hdlrs, 1);
            if (peers_incl) { wb_text(&w,"peers"); wb_id_scope(&w, peers_incl, n_peers); }
    return w.len;
}

int main(void) {
    int fails=0;
    unsigned char buf[4096]; size_t len;

    printf("-- §5.2 peers dimension: explicit grant.peers scope --\n");
    {
        const char *incl[1] = { PEER_B };
        len = build_cap(buf, sizeof buf, incl, 1);
        /* ACCEPT: target_peer is in the explicit include list */
        CHECK( cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_B),
              "ALLOW target_peer==PEER_B, grant.peers={include:[PEER_B]}" );
        /* REJECT: target_peer is NOT in the explicit include list (a peers-scoped
         * grant restricted to PEER_B must not authorize dispatch to PEER_C — the
         * cross-peer-namespace case the spec's §3.6 worked example describes). */
        CHECK( !cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_C),
              "DENY  target_peer==PEER_C, grant.peers={include:[PEER_B]} (out of scope)" );
        /* REJECT: even the LOCAL peer is out of scope when peers narrows away from it. */
        CHECK( !cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_A),
              "DENY  target_peer==local PEER_A, grant.peers={include:[PEER_B]} (local excluded)" );
    }

    printf("-- §5.2 peers dimension: bare '*' include matches any peer --\n");
    {
        const char *incl[1] = { "*" };
        len = build_cap(buf, sizeof buf, incl, 1);
        CHECK( cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_A), "ALLOW target_peer==local, grant.peers={include:[*]}" );
        CHECK( cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_B), "ALLOW target_peer==foreign, grant.peers={include:[*]}" );
    }

    printf("-- §5.2 peers dimension: grant omits `peers` -> default {include:[local_peer_id]} --\n");
    {
        len = build_cap(buf, sizeof buf, NULL, 0);
        /* ACCEPT: target_peer == local -> covered by the implicit default. */
        CHECK( cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_A),
              "ALLOW target_peer==local PEER_A, grant omits peers (default local-only)" );
        /* REJECT (the regression this fix closes): before the fix, `peers` was
         * never checked at all when a grant omitted it, so a foreign target_peer
         * was silently treated as in-scope by omission -- equivalent to
         * `peers: {include: ["*"]}` on every grant. Post-fix this MUST deny. */
        CHECK( !cap_permits(buf,len,0,"get","system/tree",NULL, PEER_A, PEER_B),
              "DENY  target_peer==foreign PEER_B, grant omits peers (default local-only; was silently ALLOW pre-fix)" );
    }

    printf("\n%s (%d failure(s))\n", fails?"AUTHZ PEERS KAT FAIL":"AUTHZ PEERS KAT OK", fails);
    return fails ? 1 : 0;
}
