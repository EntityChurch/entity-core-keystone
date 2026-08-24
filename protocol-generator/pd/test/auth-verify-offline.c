/* Offline KAT for the §4.6 authenticate verification path, exercising the exact
 * C-ABI primitives [ecodec] uses (ec_content_hash / ec_envelope_find_signature_for
 * / ec_ed25519_verify / ec_peerid_format) against a REAL authenticate frame
 * captured from validate-peer (build/auth-frame.bin — real oracle Ed25519 crypto,
 * which hand-rolled Python clients cannot produce). This validates the seam logic
 * without pd or the oracle: recompute authenticate_hash, find the target-matching
 * signature in envelope.included, verify it against public_key, and confirm the
 * peer_id↔public_key identity binding. The nonce-echo rung is NOT covered here
 * (it needs the peer's per-connection issued nonce — oracle-tested).
 *
 * Build+run via `make authkat` (or manually, container, links co-located .so):
 *   gcc -I../../ffi-generator/c-abi/spec test/auth-verify-offline.c \
 *       -Lbuild -lentitycore_codec -Wl,-rpath,'$ORIGIN' -o build/auth-offline
 *   ./build/auth-offline test/vectors/authenticate-frame.bin
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "entitycore_codec.h"

/* ── minimal CBOR reader (mirrors ecodec.c) ─────────────────────────────────── */
typedef struct { const unsigned char *p; size_t len; size_t pos; } cbor_rd;

static int cbor_head(cbor_rd *r, int *major, uint64_t *arg) {
    if (r->pos >= r->len) return -1;
    unsigned char ib = r->p[r->pos++]; *major = ib >> 5; int ai = ib & 0x1f;
    if (ai < 24) { *arg = ai; return 0; }
    if (ai == 24) { if (r->pos + 1 > r->len) return -1; *arg = r->p[r->pos++]; return 0; }
    if (ai == 25) { if (r->pos + 2 > r->len) return -1; *arg = ((uint64_t)r->p[r->pos] << 8) | r->p[r->pos+1]; r->pos += 2; return 0; }
    if (ai == 26) { if (r->pos + 4 > r->len) return -1; *arg = ((uint64_t)r->p[r->pos] << 24)|((uint64_t)r->p[r->pos+1]<<16)|((uint64_t)r->p[r->pos+2]<<8)|r->p[r->pos+3]; r->pos += 4; return 0; }
    if (ai == 27) { if (r->pos + 8 > r->len) return -1; uint64_t v=0; for (int i=0;i<8;i++) v=(v<<8)|r->p[r->pos+i]; r->pos += 8; *arg=v; return 0; }
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
static int cbor_map_find(const unsigned char *buf, size_t len, size_t map_pos, const char *key, cbor_rd *out) {
    cbor_rd r = { buf, len, map_pos }; int major; uint64_t n;
    if (cbor_head(&r,&major,&n)!=0 || major!=5) return 0;
    size_t klen = strlen(key);
    for (uint64_t i=0;i<n;i++){ int kmaj; uint64_t kl; size_t kh=r.pos;
        if (cbor_head(&r,&kmaj,&kl)!=0 || kmaj!=3){ r.pos=kh; if(cbor_skip(&r)!=0)return 0; if(cbor_skip(&r)!=0)return 0; continue; }
        if (r.pos+kl>len) return 0;
        int m = (kl==klen && memcmp(r.p+r.pos,key,klen)==0); r.pos += (size_t)kl;
        if (m){ out->p=buf; out->len=len; out->pos=r.pos; return 1; }
        if (cbor_skip(&r)!=0) return 0;
    }
    return 0;
}
static int cbor_get_text(cbor_rd *r, char *out, size_t cap) {
    int major; uint64_t arg; cbor_rd t=*r;
    if (cbor_head(&t,&major,&arg)!=0 || major!=3) return -1;
    if (t.pos+arg>t.len || arg>=cap) return -1;
    memcpy(out,t.p+t.pos,(size_t)arg); out[arg]='\0'; return 0;
}
static int cbor_get_bytes(cbor_rd *r, unsigned char *out, size_t cap, size_t *outlen) {
    int major; uint64_t arg; cbor_rd t=*r;
    if (cbor_head(&t,&major,&arg)!=0 || major!=2) return -1;
    if (t.pos+arg>t.len || arg>cap) return -1;
    memcpy(out,t.p+t.pos,(size_t)arg); *outlen=(size_t)arg; return 0;
}
static int cbor_value_slice(const unsigned char *buf, size_t len, size_t pos, const unsigned char **op, size_t *ol) {
    cbor_rd r={buf,len,pos}; size_t s=r.pos; if (cbor_skip(&r)!=0) return -1; *op=buf+s; *ol=r.pos-s; return 0;
}

/* content_hash({type, data-verbatim}) via the C-ABI (33 bytes: 0x00 || sha256). */
static int entity_hash(const char *type, const unsigned char *data, size_t dlen, unsigned char out33[33]) {
    return ec_content_hash((const uint8_t*)type, strlen(type), data, dlen, out33) == EC_OK ? 0 : -1;
}

#define CHECK(cond, msg) do { printf("  [%s] %s\n", (cond)?"PASS":"FAIL", msg); if(!(cond)) fails++; } while(0)

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "test/vectors/authenticate-frame.bin";
    FILE *f = fopen(path, "rb"); if (!f) { perror("open"); return 2; }
    static unsigned char buf[65536]; size_t len = fread(buf, 1, sizeof buf, f); fclose(f);
    printf("loaded %s (%zu bytes)\n", path, len);
    int fails = 0;

    cbor_rd root, rdata, params, pdata, fld;
    if (!cbor_map_find(buf,len,0,"root",&root)) { printf("no root\n"); return 1; }
    if (!cbor_map_find(buf,len,root.pos,"data",&rdata)) { printf("no root.data\n"); return 1; }
    if (!cbor_map_find(buf,len,rdata.pos,"params",&params)) { printf("no params\n"); return 1; }
    if (!cbor_map_find(buf,len,params.pos,"data",&pdata)) { printf("no params.data\n"); return 1; }

    char peer_id[128], key_type[32]; unsigned char public_key[64], nonce[64]; size_t pk_len=0, n_len=0;
    CHECK(cbor_map_find(buf,len,pdata.pos,"peer_id",&fld) && cbor_get_text(&fld,peer_id,sizeof peer_id)==0, "extract peer_id");
    CHECK(cbor_map_find(buf,len,pdata.pos,"key_type",&fld) && cbor_get_text(&fld,key_type,sizeof key_type)==0, "extract key_type");
    CHECK(cbor_map_find(buf,len,pdata.pos,"public_key",&fld) && cbor_get_bytes(&fld,public_key,sizeof public_key,&pk_len)==0, "extract public_key");
    CHECK(cbor_map_find(buf,len,pdata.pos,"nonce",&fld) && cbor_get_bytes(&fld,nonce,sizeof nonce,&n_len)==0, "extract nonce");
    printf("  peer_id=%s key_type=%s pk_len=%zu nonce_len=%zu\n", peer_id, key_type, pk_len, n_len);

    /* recompute authenticate_hash from verbatim params.data */
    const unsigned char *dptr; size_t dlen; unsigned char auth_hash[33];
    CHECK(cbor_value_slice(buf,len,pdata.pos,&dptr,&dlen)==0, "slice params.data");
    CHECK(entity_hash("system/protocol/connect/authenticate", dptr, dlen, auth_hash)==0, "recompute authenticate_hash");
    printf("  authenticate_hash=%02x%02x%02x%02x..\n", auth_hash[0],auth_hash[1],auth_hash[2],auth_hash[3]);

    /* cross-check: recomputed hash equals the wire params.content_hash */
    unsigned char wire_ch[33]; size_t wl=0;
    if (cbor_map_find(buf,len,params.pos,"content_hash",&fld) && cbor_get_bytes(&fld,wire_ch,sizeof wire_ch,&wl)==0)
        CHECK(wl==33 && memcmp(wire_ch,auth_hash,33)==0, "recomputed hash == wire params.content_hash");

    /* §4.6 step 2: find target-matching signature in envelope.included + verify */
    const unsigned char *sigent=NULL; size_t siglen=0;
    int found = (ec_envelope_find_signature_for(buf,len,auth_hash,33,&sigent,&siglen)==EC_OK && sigent);
    CHECK(found, "ec_envelope_find_signature_for locates the signature (bare {root,included} wire envelope)");
    if (found) {
        cbor_rd sdata, sf; unsigned char sig[64]; size_t ns=0;
        int got = cbor_map_find(sigent,siglen,0,"data",&sdata)
               && cbor_map_find(sigent,siglen,sdata.pos,"signature",&sf)
               && cbor_get_bytes(&sf,sig,sizeof sig,&ns)==0 && ns==64;
        CHECK(got, "extract 64-byte signature from signature entity");
        if (got) CHECK(ec_ed25519_verify(public_key, auth_hash, 33, sig)==EC_OK, "ed25519 signature verifies against public_key");
    }

    /* §4.6 step 3: identity binding — derive peer_id from public_key */
    char derived[128]; size_t ol=0;
    int df = (ec_peerid_format(1,0,public_key,pk_len,(uint8_t*)derived,sizeof derived-1,&ol)==EC_OK && ol<sizeof derived);
    if (df) derived[ol]='\0';
    CHECK(df, "ec_peerid_format derives a peer_id from public_key");
    if (df) { printf("  derived=%s\n", derived); CHECK(strcmp(derived,peer_id)==0, "derived peer_id == authenticate.peer_id (identity binding)"); }

    printf("\n%s (%d failure(s))\n", fails?"OFFLINE KAT FAIL":"OFFLINE KAT OK", fails);
    return fails ? 1 : 0;
}
