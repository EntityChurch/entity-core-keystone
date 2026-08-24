/* Offline KAT for the §5.2 verify_request DENY paths, exercising the discriminating
 * condition each new [ecodec] authz rung keys on, against REAL DENY frames captured
 * from validate-peer's `authz` category (test/vectors/authz-deny-*.bin — real Ed25519
 * crypto over real capabilities). Each vector pins one rung's verdict to the §5.2a
 * enumeration (status, code):
 *
 *   deny_default  → check_permission denies (resource out of grant scope) → 403 capability_denied
 *   grantee-401   → grantee != author AND grantee unresolvable            → 401 unresolvable_grantee
 *   no_catchall   → granter absent from included (chain unverifiable)      → 403 capability_denied
 *   expired       → expires_at < now (temporal validity)                  → 403 capability_denied
 *
 * The live oracle drives the seam end-to-end; this KAT cross-checks the branch LOGIC
 * offline, deterministically, with crypto no hand-rolled client can forge.
 * Build+run via `make authzdenykat`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "entitycore_codec.h"

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
static int cbor_get_bytes(cbor_rd *r, unsigned char *out, size_t cap, size_t *ol) {
    int major; uint64_t arg; cbor_rd t=*r;
    if (cbor_head(&t,&major,&arg)!=0 || major!=2 || t.pos+arg>t.len || arg>cap) return -1;
    memcpy(out,t.p+t.pos,(size_t)arg); *ol=(size_t)arg; return 0;
}
static int cbor_get_uint(cbor_rd *r, uint64_t *out) {
    int major; uint64_t arg; cbor_rd t=*r;
    if (cbor_head(&t,&major,&arg)!=0 || major!=0) return -1;
    *out=arg; return 0;
}
static int included_find(const unsigned char *buf, size_t len, const unsigned char k[33], cbor_rd *out) {
    cbor_rd inc; if (!cbor_map_find(buf,len,0,"included",&inc)) return 0;
    cbor_rd r={buf,len,inc.pos}; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=5) return 0;
    for (uint64_t i=0;i<n;i++){ size_t kh=r.pos; int km; uint64_t kl;
        if (cbor_head(&r,&km,&kl)!=0) return 0;
        if (km==2 && kl==33 && r.pos+33<=len && memcmp(r.p+r.pos,k,33)==0){ out->p=buf; out->len=len; out->pos=r.pos+33; return 1; }
        r.pos=kh; if (cbor_skip(&r)!=0 || cbor_skip(&r)!=0) return 0;
    }
    return 0;
}
static int entity_type_is(const unsigned char *buf, size_t len, const cbor_rd *ent, const char *want) {
    cbor_rd tf; char t[80];
    if (!cbor_map_find(buf,len,ent->pos,"type",&tf)) return 0;
    if (cbor_get_text(&tf,t,sizeof t)!=0) return 0;
    return strcmp(t,want)==0;
}
static int entity_data_bytes(const unsigned char *buf, size_t len, const cbor_rd *ent, const char *nm, unsigned char *out, size_t cap, size_t *ol) {
    cbor_rd d,f;
    if (!cbor_map_find(buf,len,ent->pos,"data",&d)) return -1;
    if (!cbor_map_find(buf,len,d.pos,nm,&f)) return -1;
    return cbor_get_bytes(&f,out,cap,ol);
}
static int entity_data_uint(const unsigned char *buf, size_t len, const cbor_rd *ent, const char *nm, uint64_t *out) {
    cbor_rd d,f;
    if (!cbor_map_find(buf,len,ent->pos,"data",&d)) return 0;
    if (!cbor_map_find(buf,len,d.pos,nm,&f)) return 0;
    return cbor_get_uint(&f,out)==0 ? 1 : -1;
}
/* §5.4 scope matching (peer-relative), mirrors ecodec.c. */
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
static int cap_permits(const unsigned char *buf, size_t len, size_t cap_pos,
                       const char *op, const char *handler, const char *resource) {
    cbor_rd d,grants;
    if (!cbor_map_find(buf,len,cap_pos,"data",&d)) return 0;
    if (!cbor_map_find(buf,len,d.pos,"grants",&grants)) return 0;
    cbor_rd r={buf,len,grants.pos}; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=4) return 0;
    for (uint64_t i=0;i<n;i++){ size_t ge=r.pos; cbor_rd sc; int okg=1;
        if (!cbor_map_find(buf,len,ge,"operations",&sc) || !matches_scope_rel(buf,len,sc.pos,op)) okg=0;
        if (okg && (!cbor_map_find(buf,len,ge,"handlers",&sc) || !matches_scope_rel(buf,len,sc.pos,handler))) okg=0;
        if (okg && resource) { if (!cbor_map_find(buf,len,ge,"resources",&sc) || !matches_scope_rel(buf,len,sc.pos,resource)) okg=0; }
        if (okg) return 1;
        if (cbor_skip(&r)!=0) return 0;
    }
    return 0;
}
static const char *to_peer_relative(const char *in) {
    const char *p=in;
    if (strncmp(p,"entity://",9)==0){ p+=9; const char *s=strchr(p,'/'); return s?s+1:p; }
    if (p[0]=='/'){ const char *s=strchr(p+1,'/'); return s?s+1:p+1; }
    return p;
}

/* Load a vector, extract author/cap hashes + cap entity reader. Returns 0 ok. */
static int load(const char *path, unsigned char *buf, size_t cap, size_t *len,
                cbor_rd *rdata, unsigned char author[33], unsigned char caph[33]) {
    FILE *f=fopen(path,"rb"); if(!f){ perror(path); return -1; }
    *len=fread(buf,1,cap,f); fclose(f);
    cbor_rd root,fld; size_t n;
    if (!cbor_map_find(buf,*len,0,"root",&root)) return -1;
    if (!cbor_map_find(buf,*len,root.pos,"data",rdata)) return -1;
    if (!cbor_map_find(buf,*len,rdata->pos,"author",&fld) || cbor_get_bytes(&fld,author,33,&n)!=0 || n!=33) return -1;
    if (!cbor_map_find(buf,*len,rdata->pos,"capability",&fld) || cbor_get_bytes(&fld,caph,33,&n)!=0 || n!=33) return -1;
    return 0;
}

#define CHECK(cond,msg) do { printf("  [%s] %s\n",(cond)?"PASS":"FAIL",msg); if(!(cond)) fails++; } while(0)

int main(void) {
    int fails=0;
    static unsigned char buf[65536]; size_t len;
    cbor_rd rdata, cap, gent; unsigned char author[33], caph[33], hbuf[33]; size_t n;
    char op[64], rawres[512];

    /* ── deny_default: get on system/tree, resource out of grant scope → 403 capability_denied ── */
    printf("-- authz-deny-deny_default.bin (→ 403 capability_denied via check_permission) --\n");
    if (load("test/vectors/authz-deny-deny_default.bin",buf,sizeof buf,&len,&rdata,author,caph)==0) {
        cbor_rd rf,tf; const char *res=NULL;
        if (cbor_map_find(buf,len,rdata.pos,"resource",&rf) && cbor_map_find(buf,len,rf.pos,"targets",&tf)) {
            cbor_rd r={buf,len,tf.pos}; int mj; uint64_t cnt;
            if (cbor_head(&r,&mj,&cnt)==0 && mj==4 && cnt>=1) { cbor_rd e={buf,len,r.pos};
                if (cbor_get_text(&e,rawres,sizeof rawres)==0) res=to_peer_relative(rawres); }
        }
        (void)cbor_map_find(buf,len,rdata.pos,"operation",&rf); cbor_get_text(&rf,op,sizeof op);
        CHECK(included_find(buf,len,caph,&cap) && entity_type_is(buf,len,&cap,"system/capability/token"), "cap present (cap_ok)");
        CHECK(res!=NULL, "resource target extracted");
        CHECK(!cap_permits(buf,len,cap.pos,op,"system/tree",res), "check_permission DENIES (op=get handler=system/tree resource out of scope)");
    } else { CHECK(0,"load deny_default"); }

    /* ── grantee-401: grantee != author AND grantee unresolvable → 401 unresolvable_grantee ── */
    printf("-- authz-deny-grantee-401.bin (→ 401 unresolvable_grantee) --\n");
    if (load("test/vectors/authz-deny-grantee-401.bin",buf,sizeof buf,&len,&rdata,author,caph)==0) {
        unsigned char grantee[33];
        CHECK(included_find(buf,len,caph,&cap) && entity_type_is(buf,len,&cap,"system/capability/token"), "cap present (cap_ok)");
        CHECK(entity_data_bytes(buf,len,&cap,"grantee",grantee,33,&n)==0 && n==33, "grantee extracted");
        CHECK(memcmp(grantee,author,33)!=0, "grantee != author (grantee_ok == 0)");
        CHECK(!(included_find(buf,len,grantee,&gent) && entity_type_is(buf,len,&gent,"system/peer")),
              "grantee UNRESOLVABLE → 401 unresolvable_grantee (grantee_res_ok == 0)");
    } else { CHECK(0,"load grantee-401"); }

    /* ── no_catchall: granter absent from included → chain unverifiable → 403 capability_denied ── */
    printf("-- authz-deny-no_catchall.bin (→ 403 capability_denied, granter unresolvable) --\n");
    if (load("test/vectors/authz-deny-no_catchall.bin",buf,sizeof buf,&len,&rdata,author,caph)==0) {
        unsigned char granter[33];
        CHECK(included_find(buf,len,caph,&cap), "cap present");
        CHECK(entity_data_bytes(buf,len,&cap,"granter",granter,33,&n)==0 && n==33, "granter hash extracted");
        CHECK(!(included_find(buf,len,granter,&gent) && entity_type_is(buf,len,&gent,"system/peer")),
              "granter UNRESOLVABLE → capchain fails → 403 capability_denied (capchain_ok == 0)");
    } else { CHECK(0,"load no_catchall"); }

    /* ── expired: expires_at < now → 403 capability_denied ── */
    printf("-- authz-deny-expired.bin (→ 403 capability_denied, temporal) --\n");
    if (load("test/vectors/authz-deny-expired.bin",buf,sizeof buf,&len,&rdata,author,caph)==0) {
        uint64_t now=(uint64_t)time(NULL)*1000ULL, exp=0;
        CHECK(included_find(buf,len,caph,&cap), "cap present");
        int have=entity_data_uint(buf,len,&cap,"expires_at",&exp);
        CHECK(have==1, "expires_at present");
        printf("     expires_at=%llu  now=%llu\n",(unsigned long long)exp,(unsigned long long)now);
        CHECK(exp < now, "expires_at < now → expired → 403 capability_denied (validity_ok == 0)");
    } else { CHECK(0,"load expired"); }

    /* ── sanity: the ALLOW vector's cap PERMITS its in-scope get (accept path unbroken) ── */
    printf("-- authenticated-execute-frame.bin (accept path: cap PERMITS in-scope get) --\n");
    if (load("test/vectors/authenticated-execute-frame.bin",buf,sizeof buf,&len,&rdata,author,caph)==0) {
        CHECK(included_find(buf,len,caph,&cap), "cap present");
        CHECK(cap_permits(buf,len,cap.pos,"get","system/tree","system/type/foo"),
              "check_permission ALLOWS get system/tree on system/type/foo (grant floor)");
    } else { CHECK(0,"load allow vector"); }

    (void)hbuf;
    printf("\n%s (%d failure(s))\n", fails?"AUTHZ DENY KAT FAIL":"AUTHZ DENY KAT OK", fails);
    return fails ? 1 : 0;
}
