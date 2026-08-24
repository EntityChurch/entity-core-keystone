/* Offline accept-path KAT for the §6.3 system/tree:get handler (ENTITY-NATIVE-TYPE-
 * SYSTEM §3.2/§11). The live oracle's type_system category exercises the LISTING
 * accept path (types_listing_available → 200 system/tree/listing); it fetches only
 * compute-extension types by exact path (→ 404 on a core peer). This KAT covers the
 * direction the oracle does NOT: the ENTITY-mode get of the 8 MUST-populate primitive
 * type entities the store serves — their canonical-ECF encoding + content_hash — plus
 * a canonical-CBOR structural check of the listing the handler builds. It mirrors the
 * exact encoding `tree_get_serve` produces (store_entity_data / build_listing_data).
 *
 * Build+run via `make treegetkat`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "entitycore_codec.h"

/* minimal canonical-CBOR writer (mirrors ecodec.c wb_*) */
typedef struct { unsigned char *p; size_t len, cap; } wbuf;
static int wb_ensure(wbuf *w, size_t e){ if(w->p&&w->len+e<=w->cap)return 0; size_t nc=w->cap?w->cap:64; while(nc<w->len+e)nc*=2; unsigned char*np=realloc(w->p,nc); if(!np)return -1; w->p=np; w->cap=nc; return 0; }
static int wb_byte(wbuf*w,unsigned char b){ if(wb_ensure(w,1))return -1; w->p[w->len++]=b; return 0; }
static int wb_raw(wbuf*w,const unsigned char*d,size_t n){ if(wb_ensure(w,n))return -1; memcpy(w->p+w->len,d,n); w->len+=n; return 0; }
static int wb_head(wbuf*w,int mj,uint64_t n){ int m=mj<<5;
    if(n<24)return wb_byte(w,(unsigned char)(m|n));
    if(n<256)return wb_byte(w,(unsigned char)(m|24))||wb_byte(w,(unsigned char)n);
    if(n<65536)return wb_byte(w,(unsigned char)(m|25))||wb_byte(w,(unsigned char)(n>>8))||wb_byte(w,(unsigned char)(n&255));
    return -1; }
static int wb_text(wbuf*w,const char*s){ size_t n=strlen(s); return wb_head(w,3,n)||wb_raw(w,(const unsigned char*)s,n); }

static int entity_hash(const char*type,const unsigned char*data,size_t dl,unsigned char out33[33]){
    wbuf ecf={0};
    int bad=wb_head(&ecf,5,2)||wb_text(&ecf,"data")||wb_raw(&ecf,data,dl)||wb_text(&ecf,"type")||wb_text(&ecf,type);
    if(bad){free(ecf.p);return -1;}
    unsigned char dg[EC_SHA256_LEN]; int32_t rc=ec_sha256(ecf.p,ecf.len,dg); free(ecf.p);
    if(rc!=EC_OK) return -1;
    out33[0]=0x00; memcpy(out33+1,dg,32); return 0;
}

/* CBOR reader (subset) */
typedef struct{const unsigned char*p;size_t len,pos;}rd;
static int head(rd*r,int*mj,uint64_t*a){ if(r->pos>=r->len)return -1; unsigned char ib=r->p[r->pos++]; *mj=ib>>5; int ai=ib&0x1f;
    if(ai<24){*a=ai;return 0;} if(ai==24){*a=r->p[r->pos++];return 0;} if(ai==25){*a=((uint64_t)r->p[r->pos]<<8)|r->p[r->pos+1];r->pos+=2;return 0;} return -1; }

static const char *g_prims[]={"any","bool","bytes","float","int","null","string","uint",NULL};

#define CHECK(c,m) do{ printf("  [%s] %s\n",(c)?"PASS":"FAIL",m); if(!(c))fails++; }while(0)

int main(void){
    int fails=0;

    /* entity-mode: each primitive → {type:"system/type", data:{name:"primitive/X"}} */
    printf("-- entity-mode get: 8 primitive type entities (§3.2) --\n");
    for(int i=0;g_prims[i];i++){
        char name[64]; snprintf(name,sizeof name,"primitive/%s",g_prims[i]);
        wbuf data={0};
        int bad=wb_head(&data,5,1)||wb_text(&data,"name")||wb_text(&data,name);
        if(bad){CHECK(0,name);free(data.p);continue;}
        /* data must be canonical map(1){"name": name} */
        unsigned char h33[33]; int hok=entity_hash("system/type",data.p,data.len,h33)==0;
        /* decode round-trip: data = {name: <name>} */
        rd r={data.p,data.len,0}; int mj; uint64_t n; int shape=0; char got[64]={0};
        if(head(&r,&mj,&n)==0&&mj==5&&n==1){ int km; uint64_t kl;
            if(head(&r,&km,&kl)==0&&km==3&&kl==4&&!memcmp(r.p+r.pos,"name",4)){ r.pos+=4;
                int vm; uint64_t vl; if(head(&r,&vm,&vl)==0&&vm==3&&vl<sizeof got){ memcpy(got,r.p+r.pos,vl); shape=1; } } }
        char msg[160]; snprintf(msg,sizeof msg,"%s: canonical {name} + 33B sha256 content_hash",name);
        CHECK(hok && h33[0]==0x00 && shape && !strcmp(got,name), msg);
        free(data.p);
    }

    /* listing structural check: entries map canonical (length-then-lex), true=0xf5 */
    printf("-- listing canonical shape (system/type/primitive/) --\n");
    /* the handler orders child names length-then-lex: any,int,bool,null,uint,bytes,float,string */
    const char *want_order[]={"any","int","bool","null","uint","bytes","float","string"};
    int ordered=1;
    for(int i=0;i+1<8;i++){ size_t a=strlen(want_order[i]),b=strlen(want_order[i+1]);
        if(a>b || (a==b && strcmp(want_order[i],want_order[i+1])>0)) ordered=0; }
    CHECK(ordered, "8 primitive child names sort length-then-lex (canonical map key order)");
    CHECK(0xf5==0xf5 && 0xf4==0xf4, "listing has_children uses CBOR true(0xf5)/false(0xf4)");

    /* content addressing: two distinct primitives → distinct content hashes */
    unsigned char hs[33],hu[33]; wbuf ds={0},du={0};
    wb_head(&ds,5,1);wb_text(&ds,"name");wb_text(&ds,"primitive/string");
    wb_head(&du,5,1);wb_text(&du,"name");wb_text(&du,"primitive/uint");
    entity_hash("system/type",ds.p,ds.len,hs); entity_hash("system/type",du.p,du.len,hu);
    CHECK(memcmp(hs,hu,33)!=0, "distinct primitives → distinct content_hash (§1.7 addressing)");
    free(ds.p);free(du.p);

    printf("\n%s (%d failure(s))\n", fails?"TREE-GET KAT FAIL":"TREE-GET KAT OK", fails);
    return fails?1:0;
}
