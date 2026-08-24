/* Offline KAT for the §5.2 verify_request path (steps 1-4), exercising the C-ABI
 * primitives the [ecodec] authz_* rungs use against a REAL authenticated EXECUTE
 * captured from validate-peer (test/vectors/authenticated-execute-frame.bin — real
 * oracle Ed25519 crypto over a real capability this peer would have granted). It
 * validates, all from the envelope's own included map: (1) content-hash integrity,
 * (2) the request signature (author-signed over the execute hash), (3a) grantee ==
 * author, (3b) the single-link capability-chain signature (granter-signed over the
 * token hash). check_permission (step 5, scope matching) is a separate increment.
 *
 * Build+run via `make authzkat`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
static int cbor_value_slice(const unsigned char *buf, size_t len, size_t pos, const unsigned char **op, size_t *ol) {
    cbor_rd r={buf,len,pos}; size_t s=r.pos; if (cbor_skip(&r)!=0) return -1; *op=buf+s; *ol=r.pos-s; return 0;
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
static int entity_data_bytes(const unsigned char *buf, size_t len, const cbor_rd *ent, const char *nm, unsigned char *out, size_t cap, size_t *ol) {
    cbor_rd d,f;
    if (!cbor_map_find(buf,len,ent->pos,"data",&d)) return -1;
    if (!cbor_map_find(buf,len,d.pos,nm,&f)) return -1;
    return cbor_get_bytes(&f,out,cap,ol);
}
static int entity_hash(const char *type, const unsigned char *data, size_t dlen, unsigned char out33[33]) {
    return ec_content_hash((const uint8_t*)type, strlen(type), data, dlen, out33) == EC_OK ? 0 : -1;
}
/* §5.4/§5.2 scope matching (peer-relative forms), mirrors ecodec.c. */
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

static int sig_verify_for(const unsigned char *buf, size_t len, const unsigned char target[33],
                          const unsigned char expect_signer[33], const unsigned char pubkey[32]) {
    const unsigned char *se=NULL; size_t sl=0;
    if (ec_envelope_find_signature_for(buf,len,target,33,&se,&sl)!=EC_OK || !se) return 0;
    cbor_rd sd,sf; unsigned char signer[33], sig[64]; size_t ns=0,nsig=0;
    if (!cbor_map_find(se,sl,0,"data",&sd)) return 0;
    if (!cbor_map_find(se,sl,sd.pos,"signer",&sf) || cbor_get_bytes(&sf,signer,33,&ns)!=0 || ns!=33) return 0;
    if (memcmp(signer,expect_signer,33)!=0) return 0;
    if (!cbor_map_find(se,sl,sd.pos,"signature",&sf) || cbor_get_bytes(&sf,sig,64,&nsig)!=0 || nsig!=64) return 0;
    return ec_ed25519_verify(pubkey, target, 33, sig) == EC_OK;
}

#define CHECK(cond,msg) do { printf("  [%s] %s\n",(cond)?"PASS":"FAIL",msg); if(!(cond)) fails++; } while(0)

int main(int argc, char **argv) {
    const char *path = argc>1 ? argv[1] : "test/vectors/authenticated-execute-frame.bin";
    FILE *f=fopen(path,"rb"); if(!f){ perror("open"); return 2; }
    static unsigned char buf[65536]; size_t len=fread(buf,1,sizeof buf,f); fclose(f);
    printf("loaded %s (%zu bytes)\n", path, len);
    int fails=0;

    cbor_rd root, rdata, fld;
    if (!cbor_map_find(buf,len,0,"root",&root)) { printf("no root\n"); return 1; }
    if (!cbor_map_find(buf,len,root.pos,"data",&rdata)) { printf("no root.data\n"); return 1; }

    unsigned char author_h[33], cap_h[33]; char op[64]; size_t n=0;
    CHECK(cbor_map_find(buf,len,rdata.pos,"author",&fld) && cbor_get_bytes(&fld,author_h,33,&n)==0 && n==33, "extract author");
    CHECK(cbor_map_find(buf,len,rdata.pos,"capability",&fld) && cbor_get_bytes(&fld,cap_h,33,&n)==0 && n==33, "extract capability");
    CHECK(cbor_map_find(buf,len,rdata.pos,"operation",&fld) && cbor_get_text(&fld,op,sizeof op)==0, "extract operation");
    printf("  operation=%s\n", op);

    /* step 1: content-hash integrity */
    const unsigned char *dptr; size_t dlen; unsigned char exec_h[33], wire[33];
    CHECK(cbor_value_slice(buf,len,rdata.pos,&dptr,&dlen)==0, "slice root.data");
    CHECK(entity_hash("system/protocol/execute",dptr,dlen,exec_h)==0, "recompute content_hash(execute)");
    CHECK(cbor_map_find(buf,len,root.pos,"content_hash",&fld) && cbor_get_bytes(&fld,wire,33,&n)==0 && n==33
          && memcmp(exec_h,wire,33)==0, "step1: recomputed exec hash == wire content_hash");

    /* step 2: request signature (author-signed over exec hash) */
    cbor_rd authent; unsigned char apk[64]; size_t napk=0;
    CHECK(included_find(buf,len,author_h,&authent), "author peer entity present in included");
    CHECK(entity_data_bytes(buf,len,&authent,"public_key",apk,sizeof apk,&napk)==0 && napk==32, "extract author public_key");
    CHECK(sig_verify_for(buf,len,exec_h,author_h,apk), "step2: request signature verifies (signer==author)");

    /* step 3a: grantee == author */
    cbor_rd cap; unsigned char grantee[33], granter[33];
    CHECK(included_find(buf,len,cap_h,&cap), "step3: capability present in included");
    CHECK(entity_data_bytes(buf,len,&cap,"grantee",grantee,33,&n)==0 && n==33 && memcmp(grantee,author_h,33)==0,
          "step3a: capability.grantee == author");

    /* step 3b: single-link capability-chain signature (granter-signed over cap hash) */
    cbor_rd grent; unsigned char gpk[64]; size_t ngpk=0;
    CHECK(entity_data_bytes(buf,len,&cap,"granter",granter,33,&n)==0 && n==33, "extract capability.granter");
    CHECK(included_find(buf,len,granter,&grent), "granter peer entity present in included");
    CHECK(entity_data_bytes(buf,len,&grent,"public_key",gpk,sizeof gpk,&ngpk)==0 && ngpk==32, "extract granter public_key");
    CHECK(sig_verify_for(buf,len,cap_h,granter,gpk), "step3b: capability-chain signature verifies (signer==granter)");

    /* negative control: a tampered exec hash must NOT find a matching request signature */
    unsigned char bad[33]; memcpy(bad,exec_h,33); bad[5]^=0xff;
    CHECK(!sig_verify_for(buf,len,bad,author_h,apk), "negative: tampered exec hash -> no valid request signature");

    /* §5.2 step 5 check_permission against the real floor grants in this cap */
    printf("  -- check_permission (§5.2 step 5) --\n");
    CHECK( cap_permits(buf,len,cap.pos,"get","system/tree","system/type/foo"),      "ALLOW get system/tree on system/type/foo (grant 1)");
    CHECK( cap_permits(buf,len,cap.pos,"get","system/tree","system/handler/x"),     "ALLOW get system/tree on system/handler/x (grant 1)");
    CHECK( cap_permits(buf,len,cap.pos,"request","system/capability",NULL),         "ALLOW request system/capability (grant 2, no resource)");
    CHECK(!cap_permits(buf,len,cap.pos,"get","system/tree","system/tree"),          "DENY  get system/tree on system/tree (resource out of scope)");
    CHECK(!cap_permits(buf,len,cap.pos,"put","system/tree","system/type/foo"),      "DENY  put (operation not granted)");
    CHECK(!cap_permits(buf,len,cap.pos,"get","system/other","system/type/foo"),     "DENY  get on system/other (handler not granted)");

    printf("\n%s (%d failure(s))\n", fails?"AUTHZ KAT FAIL":"AUTHZ KAT OK", fails);
    return fails ? 1 : 0;
}
