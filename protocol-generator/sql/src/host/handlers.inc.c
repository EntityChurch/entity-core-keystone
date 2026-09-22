/*
 * handlers.inc.c — the §6.2/§6.3 handler BODIES, run by dispatch_body ONLY after the authored
 * verify_ladder.sql returns 'ok' (verify_request + §6.6 resolve + check_permission all passed in
 * SQL). These build the result entity for each MUST handler (connect is handled inline earlier):
 * system/tree (get/put/list), system/type (get via the store + :validate), system/capability
 * (request/delegate/revoke/configure), system/handler (register/list), and — behind --validate —
 * system/validate (echo/dispatch). The host owns the imperative sequencing + byte I/O; the
 * AUTHORITY decision already came from src/sql (wrapper-guard). Included in peer.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* §6.2: "system" itself or any "system/..." prefix is reserved for system handlers;
 * user-installed handlers MUST NOT register there. */
static int is_reserved_system_pattern(const char *pattern) {
    static const char pfx[] = "system/";
    return !strcmp(pattern,"system") || !strncmp(pattern,pfx,sizeof(pfx)-1);
}
/* strip "/{peer}/" from an absolute handler pattern → the relative pattern (e.g. system/tree). */
static const char *rel_pattern(const char *pat) {
    size_t pl = strlen(g_peer_id);
    if (pat[0]=='/' && strncmp(pat+1,g_peer_id,pl)==0 && pat[1+pl]=='/') return pat+1+pl+1;
    return pat[0]=='/' ? pat+1 : pat;
}
/* canonicalize a resource target / uri to an absolute /{peer}/... path. out cap>=600. */
static void canon_path(const char *in, char *out, size_t cap) {
    if (!in || !in[0]) { snprintf(out,cap,"/%s",g_peer_id); return; }
    if (strncmp(in,"entity://",9)==0) snprintf(out,cap,"/%s",in+9);
    else if (in[0]=='/') snprintf(out,cap,"%s",in);
    else snprintf(out,cap,"/%s/%s",g_peer_id,in);
    /* strip a trailing slash for node lookup (listings handle the container case separately) */
}
/* read data.resource.targets[0] text into out (resource is a bare map {targets:[...]}).
 * *rawlen (optional) receives the CBOR text byte length (to detect an embedded NUL). 1/0. */
static int exec_target_n(const unsigned char *buf, size_t len, size_t rdata_pos, char *out, size_t cap, size_t *rawlen) {
    cbor_rd rf; if (!cbor_map_find(buf,len,rdata_pos,"resource",&rf)) return 0;
    cbor_rd tf; if (!cbor_map_find(buf,len,rf.pos,"targets",&tf)) return 0;
    cbor_rd a=tf; int am; uint64_t ac; if (cbor_head(&a,&am,&ac)!=0||am!=4||ac<1) return 0;
    if (rawlen) { cbor_rd t=a; int m; uint64_t arg; if (cbor_head(&t,&m,&arg)==0 && m==3) *rawlen=(size_t)arg; else *rawlen=0; }
    return cbor_get_text(&a,out,cap)==0;
}
static int exec_target(const unsigned char *buf, size_t len, size_t rdata_pos, char *out, size_t cap) {
    return exec_target_n(buf,len,rdata_pos,out,cap,NULL);
}
/* §1.4 path validity: reject ./ ../ prefixes, empty segments (//), a trailing/embedded NUL. The
 * `rawlen` is the on-wire text length; if it exceeds strlen(t) the text carried an embedded NUL. */
static int path_valid(const char *t, size_t rawlen) {
    if (!t) return 0;
    if (rawlen && rawlen != strlen(t)) return 0;             /* embedded NUL */
    const char *rel = t;
    if (t[0]=='/') {
        /* §1.4 an absolute path's first segment MUST be a valid peer id (base58) — "/system/..."
         * is malformed (a bare leading slash over a non-peer segment). */
        const char *e=strchr(t+1,'/'); size_t sl = e?(size_t)(e-(t+1)):strlen(t+1);
        char seg[128]; if (sl>=sizeof seg) sl=sizeof seg-1; memcpy(seg,t+1,sl); seg[sl]=0;
        uint64_t kt,ht; unsigned char dg[64]; size_t dl=0;
        if (ec_peerid_parse((const unsigned char*)seg,strlen(seg),&kt,&ht,dg,&dl)!=EC_OK || dl!=32) return 0;
        rel = e?e+1:"";
    }
    if (strncmp(rel,"./",2)==0 || strncmp(rel,"../",3)==0) return 0;
    if (strcmp(rel,".")==0 || strcmp(rel,"..")==0) return 0;
    if (strstr(t,"//")) return 0;                            /* empty segment */
    /* per-segment ./ .. */
    const char *seg=rel;
    while (seg && *seg) {
        const char *e=strchr(seg,'/'); size_t sl = e?(size_t)(e-seg):strlen(seg);
        if (sl==1 && seg[0]=='.') return 0;
        if (sl==2 && seg[0]=='.' && seg[1]=='.') return 0;
        seg = e?e+1:NULL;
    }
    return 1;
}
static int is_zero33(const unsigned char *b, size_t n) { if(n!=33) return 0; for(size_t i=0;i<n;i++) if(b[i]) return 0; return 1; }
/* current node hash at path → out33. 1 if a node exists there. */
static int store_hash_at(const char *path, unsigned char out33[33]) {
    char nt[80]; unsigned char *nd=NULL; size_t ndl=0;
    if (!store_get(path,nt,sizeof nt,&nd,&ndl)) return 0;
    int ok = (ec_entity_hash(nt[0]?nt:"primitive/any",nd,ndl,out33)==0);
    free(nd); return ok;
}
static void store_delete(const char *path) { if (g_store) execf(g_store,"DELETE FROM node WHERE path='%s';",path); }
/* the exec's params ENTITY data slice (params is itself an entity {data,type,content_hash}). 1/0 */
static int exec_params_data(const unsigned char *buf, size_t len, size_t rdata_pos,
                            const unsigned char **dp, size_t *dl) {
    cbor_rd pf; if (!cbor_map_find(buf,len,rdata_pos,"params",&pf)) return 0;
    cbor_rd df; if (!cbor_map_find(buf,len,pf.pos,"data",&df)) return 0;
    return cbor_value_slice(buf,len,df.pos,dp,dl)==0;
}

/* emit an empty {} result (primitive/any). */
static void emit_empty(int fd, const char *rid) {
    static const unsigned char empty=0xa0;
    (void)emit_response(fd, rid, 200, "primitive/any", &empty, 1, &empty, 1);
}
/* emit result = system/hash {hash: h33}. */
static void emit_hash_result(int fd, const char *rid, const unsigned char h33[33]) {
    wbuf d={0}; static const unsigned char empty=0xa0;
    if (wb_head(&d,5,1)||wb_text(&d,"hash")||wb_bytes(&d,h33,33)) { free(d.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    (void)emit_response(fd, rid, 200, "system/hash", d.p, d.len, &empty, 1);
    free(d.p);
}

/* ── system/tree listing (§6.3): {path, entries:{seg→listing-entry{has_children[,hash]}}, count, offset} ── */
static void build_listing(int fd, const char *rid, const char *path) {
    /* immediate children under `path` (a directory prefix "path/"). */
    char prefix[640]; size_t pl=strlen(path);
    if (pl && path[pl-1]=='/') snprintf(prefix,sizeof prefix,"%s",path); else snprintf(prefix,sizeof prefix,"%s/",path);
    size_t prlen=strlen(prefix);
    wbuf entries={0}; long count=0;
    /* collect distinct immediate segments */
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_store,"SELECT path,type,data FROM node WHERE path LIKE ?||'%' ORDER BY path",-1,&st,NULL)!=SQLITE_OK) {
        (void)emit_error(fd,rid,500,"internal_error"); return;
    }
    sqlite3_bind_text(st,1,prefix,-1,SQLITE_TRANSIENT);
    /* gather into a temp list of (segment, is_leaf, hash) — dedup immediate seg */
    char seen[256][128]; int nseen=0;
    /* pre-scan to know has_children: a seg has children if any node path has more than one segment after prefix */
    struct { char seg[128]; int has_children; int is_node; int del; unsigned char hash[33]; } rows[256]; int nrows=0;
    while (sqlite3_step(st)==SQLITE_ROW && nrows<256) {
        const char *p=(const char*)sqlite3_column_text(st,0);
        if (strncmp(p,prefix,prlen)!=0) continue;
        const char *rest=p+prlen; const char *slash=strchr(rest,'/');
        char seg[128]; if (slash){ size_t sl=(size_t)(slash-rest); if(sl>=sizeof seg)sl=sizeof seg-1; memcpy(seg,rest,sl); seg[sl]=0; } else snprintf(seg,sizeof seg,"%s",rest);
        int idx=-1; for(int i=0;i<nseen;i++) if(!strcmp(seen[i],seg)){idx=i;break;}
        if (idx<0){ if(nseen<256){ snprintf(seen[nseen],128,"%s",seg); idx=nseen; snprintf(rows[nrows].seg,128,"%s",seg); rows[nrows].has_children=0; rows[nrows].is_node=0; rows[nrows].del=0; nseen++; nrows++; } else continue; }
        int ri=-1; for(int i=0;i<nrows;i++) if(!strcmp(rows[i].seg,seg)){ri=i;break;}
        if (ri<0) continue;
        if (slash) rows[ri].has_children=1;
        else { /* exact node at this seg */
            rows[ri].is_node=1;
            const void *d=sqlite3_column_blob(st,2); int dn=sqlite3_column_bytes(st,2);
            const char *ty=(const char*)sqlite3_column_text(st,1);
            if (ty && !strcmp(ty,"system/deletion-marker")) rows[ri].del=1;
            unsigned char h33[33]; if (ec_entity_hash(ty?ty:"primitive/any",(const unsigned char*)d,(size_t)dn,h33)==0) memcpy(rows[ri].hash,h33,33); else memset(rows[ri].hash,0,33);
        }
    }
    sqlite3_finalize(st);
    /* §6.3 CORE-TREE-DELETE-1: a deletion-markered leaf (no children) is omitted from the listing. */
    { int w=0; for(int i=0;i<nrows;i++){ if(rows[i].del && !rows[i].has_children) continue; rows[w++]=rows[i]; } nrows=w; }
    /* canonical map-key order for `entries` = length-then-lex on the segment names */
    for (int i=0;i<nrows;i++) for (int j=i+1;j<nrows;j++) {
        size_t li=strlen(rows[i].seg), lj=strlen(rows[j].seg);
        int sw = (li>lj) || (li==lj && strcmp(rows[i].seg,rows[j].seg)>0);
        if (sw) { __typeof__(rows[0]) t=rows[i]; rows[i]=rows[j]; rows[j]=t; }
    }
    for (int i=0;i<nrows;i++) {
        wbuf le={0};
        /* listing-entry {hash?, has_children} — canonical: hash(4) < has_children(12). */
        int nkeys = rows[i].is_node ? 2 : 1;
        int bad = wb_head(&le,5,(uint64_t)nkeys);
        if (rows[i].is_node) bad = bad || wb_text(&le,"hash") || wb_bytes(&le,rows[i].hash,33);
        bad = bad || wb_text(&le,"has_children") || wb_head(&le,7,rows[i].has_children?21:20);
        if (!bad) { unsigned char leh[33]; if (ec_entity_hash("system/tree/listing-entry",le.p,le.len,leh)==0) {
            if (wb_text(&entries,rows[i].seg)==0) { wbuf ent={0}; if (wb_entity(&ent,"system/tree/listing-entry",le.p,le.len,leh)==0){ wb_raw(&entries,ent.p,ent.len); count++; } free(ent.p); }
        } }
        free(le.p);
    }
    /* wrap entries map */
    wbuf em={0}; wb_head(&em,5,(uint64_t)count); if (entries.p) wb_raw(&em,entries.p,entries.len);
    free(entries.p);
    /* listing data {path, count, offset, entries} — canonical: path(4)<count(5)<offset(6)<entries(7). */
    wbuf d={0}; static const unsigned char empty=0xa0;
    int bad = wb_head(&d,5,4)
        || wb_text(&d,"path")    || wb_text(&d,path)
        || wb_text(&d,"count")   || wb_head(&d,0,(uint64_t)count)
        || wb_text(&d,"offset")  || wb_head(&d,0,0)
        || wb_text(&d,"entries") || wb_raw(&d,em.p,em.len);
    free(em.p);
    if (bad) { free(d.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    (void)emit_response(fd, rid, 200, "system/tree/listing", d.p, d.len, &empty, 1);
    free(d.p);
}

/* ── mint a capability token granting `grants_bytes` (an ECF array) to `grantee`, self-signed;
 *    emit result system/capability/grant{token} + included{token,my-peer,my-sig}. ── */
/* §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
 * `created`. Rule 3: a conversion that is not representable is treated as ABSENT
 * exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
 * representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
 * bound no reader can distinguish from a deliberate one.
 *
 * ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
 * yielding `created` (expire immediately). The absent field is the only "no bound"
 * spelling, and falling out of the arithmetic is what keeps the two from collapsing. */
static int add_ttl(uint64_t created, uint64_t ttl, uint64_t *out) {
    uint64_t sum = created + ttl;
    if (sum < created) return 0;      /* uint64 wrap => not representable => drop */
    *out = sum; return 1;
}

/* Fold one DEFINED term into the running §5.6 MIN_DEFINED ceiling. */
static void min_defined(int defined, uint64_t v, uint64_t *acc, int *have) {
    if (!defined) return;
    if (!*have || v < *acc) { *acc = v; *have = 1; }
}

static void emit_grant_at(int fd, const char *rid, uint64_t created,
                          const unsigned char grantee[33],
                          const unsigned char *grants_bytes, size_t grants_len,
                          const unsigned char *parent,
                          uint64_t expires, int has_expires) {
    wbuf gpeerd={0}; my_peer_data(&gpeerd);
    unsigned char granter_hash[33]; ec_entity_hash("system/peer",gpeerd.p,gpeerd.len,granter_hash);
    /* cap data — canonical key order is length-then-lex over the ENCODED key bytes:
       grants(6),parent(6),grantee(7),granter(7),created_at(10),expires_at(10). At equal
       length the tie breaks byte-lexicographically, so created_at precedes expires_at. */
    wbuf capd={0};
    int n = 4 + (parent?1:0) + (has_expires?1:0);
    int bad = wb_head(&capd,5,(uint64_t)n)
        || wb_text(&capd,"grants") || wb_raw(&capd,grants_bytes,grants_len);
    if (parent) bad = bad || wb_text(&capd,"parent") || wb_bytes(&capd,parent,33);
    bad = bad
        || wb_text(&capd,"grantee") || wb_bytes(&capd,grantee,33)
        || wb_text(&capd,"granter") || wb_bytes(&capd,granter_hash,33)
        || wb_text(&capd,"created_at") || wb_head(&capd,0,created);
    if (has_expires) bad = bad || wb_text(&capd,"expires_at") || wb_head(&capd,0,expires);
    unsigned char caph[33]; if (bad || ec_entity_hash("system/capability/token",capd.p,capd.len,caph)) { free(gpeerd.p);free(capd.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    unsigned char csig[64]; int sbad = ec_ed25519_sign(g_priv,caph,33,csig)!=EC_OK;
    wbuf sigd={0};
    sbad = sbad || wb_head(&sigd,5,4)
        || wb_text(&sigd,"signer")||wb_bytes(&sigd,granter_hash,33)
        || wb_text(&sigd,"target")||wb_bytes(&sigd,caph,33)
        || wb_text(&sigd,"algorithm")||wb_text(&sigd,"ed25519")
        || wb_text(&sigd,"signature")||wb_bytes(&sigd,csig,64);
    unsigned char sigh[33]; if (sbad || ec_entity_hash("system/signature",sigd.p,sigd.len,sigh)) { free(gpeerd.p);free(capd.p);free(sigd.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    wbuf te={0},pe={0},se={0};
    int ibad = wb_entity(&te,"system/capability/token",capd.p,capd.len,caph)
             || wb_entity(&pe,"system/peer",gpeerd.p,gpeerd.len,granter_hash)
             || wb_entity(&se,"system/signature",sigd.p,sigd.len,sigh);
    inc_ent ie[3]; memcpy(ie[0].key,caph,33); ie[0].ent=te.p; ie[0].elen=te.len;
    memcpy(ie[1].key,granter_hash,33); ie[1].ent=pe.p; ie[1].elen=pe.len;
    memcpy(ie[2].key,sigh,33); ie[2].ent=se.p; ie[2].elen=se.len;
    wbuf inc={0}; ibad = ibad || wb_included(&inc,ie,3);
    wbuf gr={0}; int rbad = ibad || wb_head(&gr,5,1)||wb_text(&gr,"token")||wb_bytes(&gr,caph,33);
    if (rbad) (void)emit_error(fd,rid,500,"internal_error");
    else (void)emit_response(fd, rid, 200, "system/capability/grant", gr.p, gr.len, inc.p, inc.len);
    free(gpeerd.p);free(capd.p);free(sigd.p);free(te.p);free(pe.p);free(se.p);free(inc.p);free(gr.p);
}


/* §5.6 MIN_DEFINED, with the DURATION term converted against the SAME created_at that
 * lands in the token. Sampling the clock twice -- once to convert ttl_ms, once inside
 * the mint -- skews the emitted created_at from the expiry computed off it, which is
 * the defect nim shipped. `created` is therefore sampled HERE and threaded in.
 *
 * The absolute terms (caller-cap expiry, parent expiry) are folded by the caller and
 * arrive already shaped; only the duration needs the instant. */
static void emit_grant_bounded(int fd, const char *rid, const unsigned char grantee[33],
                               const unsigned char *grants_bytes, size_t grants_len,
                               const unsigned char *parent,
                               uint64_t abs_ceiling, int has_abs,
                               uint64_t ttl, int has_ttl) {
    uint64_t created = wall_ms();
    uint64_t ceiling = abs_ceiling; int have = has_abs;
    /* The term lands in its own local BEFORE the fold. Writing this as
     * `min_defined(add_ttl(created, ttl, &t), t, ...)` reads and writes `t` in one
     * unsequenced argument list -- undefined behaviour that compiles clean under
     * -Wall -Wextra and, measured here, folded a garbage term so the caller-cap
     * expiry won and ttl_ms:0 minted the caller's expiry instead of created_at. */
    if (has_ttl) {
        uint64_t t = 0;
        int ok = add_ttl(created, ttl, &t);
        min_defined(ok, t, &ceiling, &have);
    }
    emit_grant_at(fd, rid, created, grantee, grants_bytes, grants_len, parent, ceiling, have);
}/* default open grant array (one grant-entry; all dims include star, resources adds all-peers). */
static int build_open_grants(wbuf *w) {
    return wb_head(w,4,1)
        || wb_head(w,5,3)
        || wb_text(w,"handlers")   || wb_head(w,5,1)||wb_text(w,"include")||wb_head(w,4,1)||wb_text(w,"*")
        || wb_text(w,"resources")  || wb_head(w,5,1)||wb_text(w,"include")||wb_head(w,4,2)||wb_text(w,"*")||wb_text(w,"/*/*")
        || wb_text(w,"operations") || wb_head(w,5,1)||wb_text(w,"include")||wb_head(w,4,1)||wb_text(w,"*");
}

/* mint an empty self-grant token (granter=grantee=this peer), bind it + its signature at the
 * §6.9a invariant paths, and store the interface/manifest entities for a registered `pattern`. */
static void register_handler_entities(const char *pattern) {
    /* interface + manifest (reuse the seed shape) */
    { const char *ops[]={"echo"}; seed_one_handler(pattern,pattern,ops,1); }
    if (g_store) execf(g_store,"INSERT OR IGNORE INTO handler_reg(path) VALUES('/%s/%s');",g_peer_id,pattern);
    /* empty self-grant token */
    wbuf gpeerd={0}; my_peer_data(&gpeerd);
    unsigned char gh[33]; ec_entity_hash("system/peer",gpeerd.p,gpeerd.len,gh);
    wbuf capd={0}; uint64_t created=wall_ms();
    int bad = wb_head(&capd,5,4)
        || wb_text(&capd,"grants")||wb_head(&capd,4,0)
        || wb_text(&capd,"grantee")||wb_bytes(&capd,gh,33)
        || wb_text(&capd,"granter")||wb_bytes(&capd,gh,33)
        || wb_text(&capd,"created_at")||wb_head(&capd,0,created);
    unsigned char caph[33];
    if (!bad && ec_entity_hash("system/capability/token",capd.p,capd.len,caph)==0) {
        char gp[768]; snprintf(gp,sizeof gp,"/%s/system/capability/grants/%s",g_peer_id,pattern);
        store_bind(gp,"system/capability/token",capd.p,capd.len);
        unsigned char csig[64];
        if (ec_ed25519_sign(g_priv,caph,33,csig)==EC_OK) {
            wbuf sd={0};
            if (!(wb_head(&sd,5,4)||wb_text(&sd,"signer")||wb_bytes(&sd,gh,33)||wb_text(&sd,"target")||wb_bytes(&sd,caph,33)
                  ||wb_text(&sd,"algorithm")||wb_text(&sd,"ed25519")||wb_text(&sd,"signature")||wb_bytes(&sd,csig,64))) {
                char th[80]; hexof(caph,33,th);
                char sp[768]; snprintf(sp,sizeof sp,"/%s/system/signature/%s",g_peer_id,th);
                store_bind(sp,"system/signature",sd.p,sd.len);
            }
            free(sd.p);
        }
    }
    free(gpeerd.p); free(capd.p);
}

/* ── system/type:validate — structural required-field check → system/type/validate-result. ── */
static void h_type_validate(int fd, const char *rid, const unsigned char *buf, size_t len, size_t rdata_pos) {
    const unsigned char *pd; size_t pl;
    if (!exec_params_data(buf,len,rdata_pos,&pd,&pl)) { (void)emit_error(fd,rid,400,"invalid_params"); return; }
    /* params = {entity: <entity>, type_path?: text}. Resolve typedef; check required fields. */
    cbor_rd ef; if (!cbor_map_find(pd,pl,0,"entity",&ef)) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
    char tname[128]={0}; cbor_rd tpf;
    if (cbor_map_find(pd,pl,0,"type_path",&tpf)) cbor_get_text(&tpf,tname,sizeof tname);
    if (!tname[0]) { cbor_rd etf; if (cbor_map_find(pd,pl,ef.pos,"type",&etf)) cbor_get_text(&etf,tname,sizeof tname); }
    /* subject data map */
    cbor_rd sdf; int have_sd = cbor_map_find(pd,pl,ef.pos,"data",&sdf);
    /* fetch typedef node */
    char tpath[256]; snprintf(tpath,sizeof tpath,"/%s/system/type/%s",g_peer_id,tname);
    char nt[80]; unsigned char *ndata=NULL; size_t ndl=0;
    int have_type = store_get(tpath,nt,sizeof nt,&ndata,&ndl);
    wbuf d={0}; static const unsigned char empty=0xa0;
    if (!have_type) {
        wb_head(&d,5,2); wb_text(&d,"valid"); wb_head(&d,7,20); /* false */
        wb_text(&d,"violations"); wb_head(&d,4,1);
        wb_head(&d,5,3); wb_text(&d,"kind"); wb_text(&d,"unknown_type");
        wb_text(&d,"field"); wb_text(&d,tname); wb_text(&d,"message"); wb_text(&d,"no registered type definition");
        (void)emit_response(fd,rid,200,"system/type/validate-result",d.p,d.len,&empty,1); free(d.p); return;
    }
    /* collect missing required fields (spec.optional != true and absent in subject data) */
    cbor_rd flds; int have_fields = cbor_map_find(ndata,ndl,0,"fields",&flds);
    char missing[64][128]; int nmiss=0;
    if (have_fields) {
        cbor_rd fm=flds; int fmaj; uint64_t fn;
        if (cbor_head(&fm,&fmaj,&fn)==0 && fmaj==5) {
            for (uint64_t i=0;i<fn && nmiss<64;i++) {
                char fname[128]={0}; cbor_rd kv=fm; if (cbor_get_text(&kv,fname,sizeof fname)!=0){ if(cbor_skip(&fm))break; if(cbor_skip(&fm))break; continue; }
                if (cbor_skip(&fm)) break;              /* to spec value */
                size_t specpos=fm.pos;
                int optional=0; cbor_rd of; if (cbor_map_find(ndata,ndl,specpos,"optional",&of)){ int m;uint64_t v;cbor_rd t=of; if(cbor_head(&t,&m,&v)==0&&m==7&&v==21) optional=1; }
                int present=0;
                if (have_sd) { cbor_rd found; if (cbor_map_find(pd,pl,sdf.pos,fname,&found)) present=1; }
                if (!optional && !present) { snprintf(missing[nmiss],128,"%s",fname); nmiss++; }
                if (cbor_skip(&fm)) break;              /* past spec value */
            }
        }
    }
    int valid = (nmiss==0);
    int nk = 1 + (nmiss>0?1:0);
    wb_head(&d,5,(uint64_t)nk); wb_text(&d,"valid"); wb_head(&d,7,valid?21:20);
    if (nmiss>0) {
        wb_text(&d,"violations"); wb_head(&d,4,(uint64_t)nmiss);
        for (int i=0;i<nmiss;i++){ wb_head(&d,5,3); wb_text(&d,"kind");wb_text(&d,"missing_required_field"); wb_text(&d,"field");wb_text(&d,missing[i]); wb_text(&d,"message");wb_text(&d,"required field absent"); }
    }
    free(ndata);
    (void)emit_response(fd,rid,200,"system/type/validate-result",d.p,d.len,&empty,1); free(d.p);
}

/* extract a sub-entity's content_hash field (33 bytes) into out. 1/0. */
static int ent_hash(const unsigned char *buf, size_t len, size_t entpos, unsigned char out[33]) {
    cbor_rd hf; size_t hl=0;
    if (cbor_map_find(buf,len,entpos,"content_hash",&hf) && cbor_get_bytes(&hf,out,33,&hl)==0 && hl==33) return 1;
    return 0;
}

/* ── §6.13(b)/§6.11 dispatch-outbound: originate an EXECUTE back to the caller (validator-as-B)
 *    over the SAME inbound fd with the caller-minted reentry authority, await the response, and
 *    return {status, result}. A generic relay: `value` is forwarded verbatim as the downstream
 *    params data. On a single-threaded fd this is a bounded synchronous send+read on `fd`. ── */
static void h_dispatch_outbound(int fd, conn_state *cs, const char *rid, const unsigned char *buf, size_t len, size_t rdata_pos) {
    const unsigned char *pd; size_t pl;
    if (!exec_params_data(buf,len,rdata_pos,&pd,&pl)) { (void)emit_error(fd,rid,400,"invalid_params"); return; }
    char target[256]={0}, operation[128]={0}; cbor_rd f;
    if (cbor_map_find(pd,pl,0,"target",&f)) cbor_get_text(&f,target,sizeof target);
    if (cbor_map_find(pd,pl,0,"operation",&f)) cbor_get_text(&f,operation,sizeof operation);
    const unsigned char *vp=NULL; size_t vl=0; cbor_rd vf;
    int have_v = cbor_map_find(pd,pl,0,"value",&vf) && cbor_value_slice(pd,pl,vf.pos,&vp,&vl)==0;
    cbor_rd cf,gf,sf;
    int hc=cbor_map_find(pd,pl,0,"reentry_capability",&cf);
    int hg=cbor_map_find(pd,pl,0,"reentry_granter",&gf);
    int hs=cbor_map_find(pd,pl,0,"reentry_cap_signature",&sf);
    if (!have_v||!hc||!hg||!hs) { (void)emit_error(fd,rid,400,"invalid_params"); return; }
    const unsigned char *cap_e,*gr_e,*sg_e; size_t cap_l,gr_l,sg_l;
    if (cbor_value_slice(pd,pl,cf.pos,&cap_e,&cap_l)||cbor_value_slice(pd,pl,gf.pos,&gr_e,&gr_l)||cbor_value_slice(pd,pl,sf.pos,&sg_e,&sg_l)) { (void)emit_error(fd,rid,400,"invalid_params"); return; }
    unsigned char caph[33],grh[33],sgh[33];
    if (!ent_hash(pd,pl,cf.pos,caph)||!ent_hash(pd,pl,gf.pos,grh)||!ent_hash(pd,pl,sf.pos,sgh)) { (void)emit_error(fd,rid,400,"invalid_params"); return; }
    /* params entity: primitive/any{value} (value forwarded verbatim as the entity data). */
    unsigned char pah[33]; if (ec_entity_hash("primitive/any",vp,vl,pah)) { (void)emit_error(fd,rid,500,"internal_error"); return; }
    wbuf pe={0}; if (wb_entity(&pe,"primitive/any",vp,vl,pah)) { free(pe.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    /* EXECUTE data — the reentry uri IS the target (a full entity:// uri to B's handler); no
     * resource. Canonical key order: uri(3),author(6),params(6),operation(9),capability(10),request_id(10). */
    char orid[48]; snprintf(orid,sizeof orid,"reentry-%s",rid);
    wbuf ed={0};
    int bad = wb_head(&ed,5,6)
        || wb_text(&ed,"uri")        || wb_text(&ed,target)
        || wb_text(&ed,"author")     || wb_bytes(&ed,g_id_hash,33)
        || wb_text(&ed,"params")     || wb_raw(&ed,pe.p,pe.len)
        || wb_text(&ed,"operation")  || wb_text(&ed,operation)
        || wb_text(&ed,"capability") || wb_bytes(&ed,caph,33)
        || wb_text(&ed,"request_id") || wb_text(&ed,orid);
    unsigned char eh[33]; if (bad || ec_entity_hash("system/protocol/execute",ed.p,ed.len,eh)) { free(pe.p);free(ed.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    /* exec signature by me */
    unsigned char esig[64]; wbuf sd={0};
    int sbad = ec_ed25519_sign(g_priv,eh,33,esig)!=EC_OK
        || wb_head(&sd,5,4)||wb_text(&sd,"signer")||wb_bytes(&sd,g_id_hash,33)||wb_text(&sd,"target")||wb_bytes(&sd,eh,33)
        || wb_text(&sd,"algorithm")||wb_text(&sd,"ed25519")||wb_text(&sd,"signature")||wb_bytes(&sd,esig,64);
    unsigned char esh[33]; if (sbad || ec_entity_hash("system/signature",sd.p,sd.len,esh)) { free(pe.p);free(ed.p);free(sd.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
    /* my peer entity */
    wbuf mpd={0}, mpe={0}; my_peer_data(&mpd); wb_entity(&mpe,"system/peer",mpd.p,mpd.len,g_id_hash);
    wbuf ese={0}; wb_entity(&ese,"system/signature",sd.p,sd.len,esh);
    /* included: reentry_capability, reentry_granter, my-peer, reentry_cap_sig, exec_sig (sorted) */
    inc_ent ie[5];
    memcpy(ie[0].key,caph,33); ie[0].ent=cap_e; ie[0].elen=cap_l;
    memcpy(ie[1].key,grh,33);  ie[1].ent=gr_e;  ie[1].elen=gr_l;
    memcpy(ie[2].key,g_id_hash,33); ie[2].ent=mpe.p; ie[2].elen=mpe.len;
    memcpy(ie[3].key,sgh,33);  ie[3].ent=sg_e;  ie[3].elen=sg_l;
    memcpy(ie[4].key,esh,33);  ie[4].ent=ese.p; ie[4].elen=ese.len;
    wbuf inc={0}; wb_included(&inc,ie,5);
    /* §6.11 NON-BLOCKING: originate the reentry EXECUTE, record (orid → rid) in the connection's
     * correlation map, and return. The main loop routes the reentry EXECUTE_RESPONSE (by orid) back
     * to a dispatch-outbound response for rid — so many concurrent pipelined reentries interleave. */
    wbuf ee={0}, env={0};
    int ebad2 = wb_entity(&ee,"system/protocol/execute",ed.p,ed.len,eh)
        || wb_head(&env,5,2)||wb_text(&env,"root")||wb_raw(&env,ee.p,ee.len)||wb_text(&env,"included")||wb_raw(&env,inc.p,inc.len);
    int sent = (!ebad2) && send_envelope(fd,env.p,env.len)==0;
    if (sent && cs->npend < 128) { snprintf(cs->pend[cs->npend].orid,48,"%s",orid); snprintf(cs->pend[cs->npend].rid,64,"%s",rid); cs->npend++; }
    else (void)emit_error(fd,rid,503,"no_outbound_seam");
    free(pe.p);free(ed.p);free(sd.p);free(mpd.p);free(mpe.p);free(ese.p);free(inc.p);free(ee.p);free(env.p);
}

/* Route an inbound EXECUTE_RESPONSE: if its request_id matches a pending reentry (orid), emit the
 * correlated dispatch-outbound response {result,status} for the original inbound request. 1 if
 * consumed. Called from the main loop for every EXECUTE_RESPONSE frame. */
static int reentry_route(int fd, conn_state *cs, const unsigned char *buf, size_t len) {
    cbor_rd rr,rdat,ridf,stf,resf; char frid[64]={0};
    if (!cbor_map_find(buf,len,0,"root",&rr) || !cbor_map_find(buf,len,rr.pos,"data",&rdat)) return 0;
    if (!cbor_map_find(buf,len,rdat.pos,"request_id",&ridf) || cbor_get_text(&ridf,frid,sizeof frid)) return 0;
    int idx=-1; for(int i=0;i<cs->npend;i++) if(!strcmp(cs->pend[i].orid,frid)){ idx=i; break; }
    if (idx<0) return 0;
    unsigned dstatus=0; const unsigned char *dresult=NULL; size_t drlen=0;
    if (cbor_map_find(buf,len,rdat.pos,"status",&stf)){ int m;uint64_t v;cbor_rd t=stf; if(cbor_head(&t,&m,&v)==0&&m==0) dstatus=(unsigned)v; }
    if (cbor_map_find(buf,len,rdat.pos,"result",&resf)) cbor_value_slice(buf,len,resf.pos,&dresult,&drlen);
    static const unsigned char emptymap=0xa0, empty=0xa0;
    char origrid[64]; snprintf(origrid,sizeof origrid,"%s",cs->pend[idx].rid);
    wbuf out={0}; wb_head(&out,5,2);
    wb_text(&out,"result"); if (dresult) wb_raw(&out,dresult,drlen); else wb_raw(&out,&emptymap,1);
    wb_text(&out,"status"); wb_head(&out,0,dstatus);
    (void)emit_response(fd,origrid,200,"primitive/any",out.p,out.len,&empty,1);
    free(out.p);
    cs->pend[idx]=cs->pend[--cs->npend];   /* remove */
    return 1;
}

/* ── the dispatch of a resolved handler body (verdict already 'ok'). ── */
static void dispatch_body(int fd, conn_state *cs, const char *rid, const char *pattern,
                          const char *uri, const char *op, const unsigned char *buf, size_t len, size_t rdata_pos) {
    (void)cs;
    const char *rel = rel_pattern(pattern);

    /* system/tree + system/type get/put/list share the store-backed tree. */
    if (!strcmp(rel,"system/tree") || !strncmp(rel,"system/type",11)) {
        if (!strcmp(op,"validate")) { h_type_validate(fd,rid,buf,len,rdata_pos); return; }
        if (!strcmp(op,"get") || !strcmp(op,"list")) {
            char tgt[600]="", path[640];
            if (exec_target(buf,len,rdata_pos,tgt,sizeof tgt)) canon_path(tgt,path,sizeof path);
            else canon_path(uri,path,sizeof path);
            size_t plen=strlen(path);
            int container = (!strcmp(op,"list")) || (plen && path[plen-1]=='/');
            if (plen && path[plen-1]=='/') path[plen-1]=0;
            if (!container) {
                char nt[80]; unsigned char *nd=NULL; size_t ndl=0;
                if (store_get(path,nt,sizeof nt,&nd,&ndl)) { static const unsigned char empty=0xa0; (void)emit_response(fd,rid,200,nt,nd,ndl,&empty,1); free(nd); return; }
                /* no exact node → maybe a container prefix → listing; else 404 */
                sqlite3_stmt *st; int has=0; char like[644]; snprintf(like,sizeof like,"%s/",path);
                if (sqlite3_prepare_v2(g_store,"SELECT 1 FROM node WHERE path LIKE ?||'%' LIMIT 1",-1,&st,NULL)==SQLITE_OK){ sqlite3_bind_text(st,1,like,-1,SQLITE_TRANSIENT); has=(sqlite3_step(st)==SQLITE_ROW); sqlite3_finalize(st);}
                if (has) { build_listing(fd,rid,path); return; }
                (void)emit_error(fd,rid,404,"not_found"); return;
            }
            build_listing(fd,rid,path); return;
        }
        if (!strcmp(op,"put")) {
            char tgt[600]="", path[640]; size_t rawlen=0;
            if (!exec_target_n(buf,len,rdata_pos,tgt,sizeof tgt,&rawlen)) { (void)emit_error(fd,rid,400,"ambiguous_resource"); return; }
            if (!path_valid(tgt,rawlen)) { (void)emit_error(fd,rid,400,"invalid_path"); return; }
            canon_path(tgt,path,sizeof path);
            const unsigned char *pd; size_t pl;
            if (!exec_params_data(buf,len,rdata_pos,&pd,&pl)) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            /* §6.3 CAS: expected_hash present → gate the write. zero-hash = create-if-absent. */
            cbor_rd ehf; unsigned char eh[33]; size_t ehl=0; int have_eh=0;
            if (cbor_map_find(pd,pl,0,"expected_hash",&ehf) && cbor_get_bytes(&ehf,eh,sizeof eh,&ehl)==0 && ehl==33) have_eh=1;
            unsigned char cur[33]; int have_cur = store_hash_at(path,cur);
            if (have_eh) {
                int ok;
                if (is_zero33(eh,ehl)) ok = !have_cur;                         /* create only */
                else ok = have_cur && memcmp(cur,eh,33)==0;                    /* match current */
                if (!ok) { (void)emit_error(fd,rid,409,"hash_mismatch"); return; }
            }
            cbor_rd entf; if (!cbor_map_find(pd,pl,0,"entity",&entf)) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            /* §6.3 put ADMISSION (normative, 0.8.2.11). `put` is a RECEIPT path: the
             * submitter authors the entity, the peer validates what it received (§1.8
             * item 1) and MUST NOT author a submitted entity's content_hash on the
             * submitter's behalf. Two ORDERED steps, and the order is a data dependency
             * rather than a choice -- step 2's inputs are exactly what step 1
             * establishes, so a submission that is both malformed and mis-hashed is
             * step 1's and answers invalid_request.
             *   1. STRUCTURE -- a map with a non-empty text `type`, a PRESENT `data`
             *      (any CBOR value; null is legal), and a `content_hash` that is a
             *      well-formed system/hash whose total byte length matches its format
             *      code (§1.2). Any failure -> invalid_request; a well-formed hash
             *      naming a format code this peer cannot VERIFY is the separate §1.2
             *      row -> unsupported_content_hash_format.
             *   2. HASH -- carried vs content_hash({type, data}) -> hash_mismatch.
             * Structural admission is not semantic validation: `data` is never checked
             * against the type named by `type`. */
            {   cbor_rd em = entf; int emaj; uint64_t earg;
                if (cbor_head(&em,&emaj,&earg)!=0 || emaj!=5) { (void)emit_error(fd,rid,400,"invalid_request"); return; }
            }
            cbor_rd etf,edf; char ety[80];
            /* No "primitive/any" default: an absent or empty `type` is step 1's refusal,
             * and defaulting it would author a type the submitter never sent. */
            if (!cbor_map_find(pd,pl,entf.pos,"type",&etf) || cbor_get_text(&etf,ety,sizeof ety)!=0 || ety[0]==0) {
                (void)emit_error(fd,rid,400,"invalid_request"); return;
            }
            /* Presence, not truthiness: a CBOR null is a legal `data` payload and
             * cbor_map_find reports it found, which is the test §6.3 wants. */
            if (!cbor_map_find(pd,pl,entf.pos,"data",&edf)) { (void)emit_error(fd,rid,400,"invalid_request"); return; }
            const unsigned char *edp=NULL; size_t edl=0;
            if (cbor_value_slice(pd,pl,edf.pos,&edp,&edl)!=0 || !edp) { (void)emit_error(fd,rid,400,"invalid_request"); return; }
            cbor_rd chf; unsigned char carried[33]; size_t chl=0;
            if (!cbor_map_find(pd,pl,entf.pos,"content_hash",&chf)
                || cbor_get_bytes(&chf,carried,sizeof carried,&chl)!=0 || chl==0) {
                (void)emit_error(fd,rid,400,"invalid_request"); return;
            }
            {   /* leading multicodec LEB128 format-code varint (§7.3) */
                uint64_t fmt=0; unsigned shift=0; size_t i=0; int done=0;
                while (i < chl) { unsigned char b = carried[i++];
                    fmt |= (uint64_t)(b & 0x7f) << shift;
                    if (!(b & 0x80)) { done=1; break; }
                    shift += 7; if (shift >= 64) break; }
                if (!done) { (void)emit_error(fd,rid,400,"invalid_request"); return; }
                /* §1.2 / §4.7 row 5 -- well-formed, but this peer cannot interpret it.
                 * NOT invalid_request: the shape is fine, the algorithm is what we
                 * lack. ec_entity_hash computes the SHA-256 floor only, so 0x00 is the
                 * whole verifiable set here. */
                if (fmt != 0) { (void)emit_error(fd,rid,400,"unsupported_content_hash_format"); return; }
                if (chl != i + 32) { (void)emit_error(fd,rid,400,"invalid_request"); return; }
            }
            unsigned char h33[33]; ec_entity_hash(ety,edp,edl,h33);
            if (memcmp(h33,carried,33)!=0) { (void)emit_error(fd,rid,400,"hash_mismatch"); return; }
            store_bind(path,ety,edp,edl);
            emit_hash_result(fd,rid,h33); return;
        }
        (void)emit_error(fd,rid,501,"unsupported_operation"); return;
    }

    /* system/capability */
    if (!strcmp(rel,"system/capability")) {
        if (!strcmp(op,"request") || !strcmp(op,"delegate")) {
            unsigned char author[33]; size_t al=0; cbor_rd af;
            if (cbor_map_find(buf,len,rdata_pos,"author",&af)) cbor_get_bytes(&af,author,sizeof author,&al);
            if (al!=33) { (void)emit_error(fd,rid,403,"capability_denied"); return; }
            const unsigned char *pd=NULL; size_t pl=0; exec_params_data(buf,len,rdata_pos,&pd,&pl);
            const unsigned char *parent=NULL; unsigned char pbuf[33];
            if (!strcmp(op,"delegate")) {
                /* same-peer-only in v1 */
                if (memcmp(author,g_id_hash,33)!=0) { (void)emit_error(fd,rid,501,"unsupported_operation"); return; }
                cbor_rd ph; size_t phl=0; if (pd && cbor_map_find(pd,pl,0,"parent",&ph) && cbor_get_bytes(&ph,pbuf,sizeof pbuf,&phl)==0 && phl==33) parent=pbuf;
                else { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            }
            /* §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6).
             *
             * Note what this is NOT: an authorization decision. An over-long ttl_ms from
             * a bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
             * non-conformant" (§5.6). The bound exists because `request` mints a ROOT
             * token (parent: null), so §5.6's parent-child attenuation never reaches it;
             * without this clamp, temporal attenuation is the one dimension a requester
             * could escape, and policy withdrawal would have no bounded latency.
             *
             * created_at is sampled inside emit_grant, so the ttl term is converted
             * there too -- passing an already-absolute value computed here would skew it
             * against the created_at that actually lands in the token. */
            uint64_t ceiling = 0; int has_ceiling = 0;
            {   /* caller cap's absolute expiry (§5.6, ABSOLUTE term) */
                unsigned char capbuf[33]; size_t chl=0; cbor_rd cf;
                if (cbor_map_find(buf,len,rdata_pos,"capability",&cf)
                    && cbor_get_bytes(&cf,capbuf,sizeof capbuf,&chl)==0 && chl==33) {
                    char ch[80]; hexof(capbuf,33,ch);
                    char q[160]; snprintf(q,sizeof q,"SELECT expires_at FROM cap WHERE hash=X'%s'",ch);
                    sqlite3_stmt *st;
                    if (sqlite3_prepare_v2(g_db,q,-1,&st,NULL)==SQLITE_OK) {
                        if (sqlite3_step(st)==SQLITE_ROW && sqlite3_column_type(st,0)!=SQLITE_NULL)
                            min_defined(1,(uint64_t)sqlite3_column_int64(st,0),&ceiling,&has_ceiling);
                        sqlite3_finalize(st);
                    }
                }
            }
            /* the parent link's absolute expiry, for the delegate path */
            if (parent) {
                char ph2[80]; hexof(parent,33,ph2);
                char q[160]; snprintf(q,sizeof q,"SELECT expires_at FROM cap WHERE hash=X'%s'",ph2);
                sqlite3_stmt *st;
                if (sqlite3_prepare_v2(g_db,q,-1,&st,NULL)==SQLITE_OK) {
                    if (sqlite3_step(st)==SQLITE_ROW && sqlite3_column_type(st,0)!=SQLITE_NULL)
                        min_defined(1,(uint64_t)sqlite3_column_int64(st,0),&ceiling,&has_ceiling);
                    sqlite3_finalize(st);
                }
            }
            /* request ttl_ms (§5.6, DURATION term) */
            uint64_t ttl = 0; int has_ttl = 0;
            if (pd) { cbor_rd tf; int m; uint64_t v; if (cbor_map_find(pd,pl,0,"ttl_ms",&tf)) {
                cbor_rd t=tf; if (cbor_head(&t,&m,&v)==0 && m==0) { ttl=v; has_ttl=1; } } }

            /* requested grants (verbatim slice) or default open */
            cbor_rd gf; const unsigned char *gp; size_t gl;
            if (pd && cbor_map_find(pd,pl,0,"grants",&gf) && cbor_value_slice(pd,pl,gf.pos,&gp,&gl)==0) {
                emit_grant_bounded(fd,rid,author,gp,gl,parent,ceiling,has_ceiling,ttl,has_ttl);
            } else {
                wbuf og={0}; if (build_open_grants(&og)){ free(og.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
                emit_grant_bounded(fd,rid,author,og.p,og.len,parent,ceiling,has_ceiling,ttl,has_ttl); free(og.p);
            }
            return;
        }
        if (!strcmp(op,"revoke")) {
            const unsigned char *pd=NULL; size_t pl=0; exec_params_data(buf,len,rdata_pos,&pd,&pl);
            cbor_rd tf; unsigned char tok[33]; size_t tl=0;
            if (!pd || !cbor_map_find(pd,pl,0,"token",&tf) || cbor_get_bytes(&tf,tok,sizeof tok,&tl)!=0 || tl!=33) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            if (is_zero33(tok,tl)) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            char th[80]; hexof(tok,33,th);
            if (g_store) execf(g_store,"INSERT OR IGNORE INTO revoked(cap_hex) VALUES('%s');",th);
            /* §5.1 write the revocation marker entity at the invariant path */
            wbuf rm={0};
            if (!(wb_head(&rm,5,2)||wb_text(&rm,"token")||wb_bytes(&rm,tok,33)||wb_text(&rm,"revoked_at")||wb_head(&rm,0,wall_ms()))) {
                char rp[768]; snprintf(rp,sizeof rp,"/%s/system/capability/revocations/%s",g_peer_id,th);
                store_bind(rp,"system/capability/revocation",rm.p,rm.len);
            }
            free(rm.p);
            emit_empty(fd,rid); return;
        }
        if (!strcmp(op,"configure")) {
            const unsigned char *pd=NULL; size_t pl=0; exec_params_data(buf,len,rdata_pos,&pd,&pl);
            char pp[128]={0}; cbor_rd ppf;
            if (!pd || !cbor_map_find(pd,pl,0,"peer_pattern",&ppf) || cbor_get_text(&ppf,pp,sizeof pp)!=0 || !pp[0]) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            /* §4 valid peer_pattern: "default", a full 66-hex identity, or a valid Base58 peer_id.
             * Partial prefixes are rejected. */
            int ok=0;
            if (!strcmp(pp,"default")) ok=1;
            else if (strlen(pp)==66) { ok=1; for(char*c=pp;*c;c++) if(!((*c>='0'&&*c<='9')||(*c>='a'&&*c<='f'))) {ok=0;break;} }
            if (!ok) { uint64_t kt,ht; unsigned char dg[64]; size_t dl=0; if (ec_peerid_parse((const unsigned char*)pp,strlen(pp),&kt,&ht,dg,&dl)==EC_OK) ok=1; }
            if (!ok) { (void)emit_error(fd,rid,400,"invalid_peer_pattern"); return; }
            char ppath[768]; snprintf(ppath,sizeof ppath,"/%s/system/capability/policy/%s",g_peer_id,pp);
            const unsigned char *dp; size_t dl2;
            if (cbor_value_slice(pd,pl,0,&dp,&dl2)==0) store_bind(ppath,"system/capability/policy-entry",dp,dl2);
            emit_empty(fd,rid); return;
        }
        (void)emit_error(fd,rid,501,"unsupported_operation"); return;
    }

    /* system/handler register/unregister/list */
    if (!strcmp(rel,"system/handler")) {
        if (!strcmp(op,"register") || !strcmp(op,"unregister")) {
            char tgt[600]=""; if (!exec_target(buf,len,rdata_pos,tgt,sizeof tgt)) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            const char *pfx="system/handler/"; if (strncmp(tgt,pfx,strlen(pfx))!=0) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            const char *hp=tgt+strlen(pfx); if (!hp[0] || strlen(hp)>200) { (void)emit_error(fd,rid,400,"unexpected_params"); return; }
            char hpc[600]; snprintf(hpc,sizeof hpc,"%s",hp);
            /* §6.2: user-installed handlers MUST NOT register at reserved "system/..."
             * paths. Refused before any of the register writes below; unregister
             * needs no such guard. */
            if (!strcmp(op,"register") && is_reserved_system_pattern(hpc)) { (void)emit_error(fd,rid,403,"forbidden_pattern"); return; }
            if (!strcmp(op,"unregister")) {
                char ap[768]; if (g_store) execf(g_store,"DELETE FROM handler_reg WHERE path='/%s/%s';",g_peer_id,hpc);
                /* remove the grant token's signature (recompute the token hash from its stored node) */
                char gp[768]; snprintf(gp,sizeof gp,"/%s/system/capability/grants/%s",g_peer_id,hpc);
                unsigned char gh[33]; if (store_hash_at(gp,gh)) { char th[80]; hexof(gh,33,th); char sp[768]; snprintf(sp,sizeof sp,"/%s/system/signature/%s",g_peer_id,th); store_delete(sp); }
                store_delete(gp);
                snprintf(ap,sizeof ap,"/%s/system/handler/%s",g_peer_id,hpc); store_delete(ap);
                snprintf(ap,sizeof ap,"/%s/%s",g_peer_id,hpc); store_delete(ap);
                emit_empty(fd,rid); return;
            }
            register_handler_entities(hpc);
            /* result system/handler/register-result {handler, pattern} — canonical handler<pattern. */
            wbuf d={0}; static const unsigned char empty=0xa0; char ap[768]; snprintf(ap,sizeof ap,"/%s/%s",g_peer_id,hpc);
            if (wb_head(&d,5,2)||wb_text(&d,"handler")||wb_text(&d,ap)||wb_text(&d,"pattern")||wb_text(&d,hpc)) { free(d.p); (void)emit_error(fd,rid,500,"internal_error"); return; }
            (void)emit_response(fd,rid,200,"system/handler/register-result",d.p,d.len,&empty,1); free(d.p); return;
        }
        if (!strcmp(op,"get")||!strcmp(op,"list")) { char path[640]; char tgt[600]=""; if(exec_target(buf,len,rdata_pos,tgt,sizeof tgt)) canon_path(tgt,path,sizeof path); else canon_path(uri,path,sizeof path); build_listing(fd,rid,path); return; }
        (void)emit_error(fd,rid,501,"unsupported_operation"); return;
    }

    /* system/validate (conformance scaffold, --validate) */
    if (!strcmp(rel,"system/validate") || !strncmp(rel,"system/validate/",16)) {
        if (!g_validate) { (void)emit_error(fd,rid,404,"not_found"); return; }
        if (!strcmp(op,"echo")) {
            const unsigned char *pd; size_t pl;
            if (exec_params_data(buf,len,rdata_pos,&pd,&pl)) { static const unsigned char empty=0xa0; (void)emit_response(fd,rid,200,"primitive/any",pd,pl,&empty,1); }
            else (void)emit_error(fd,rid,400,"invalid_params");
            return;
        }
        if (!strcmp(op,"dispatch")) { h_dispatch_outbound(fd,cs,rid,buf,len,rdata_pos); return; }
        (void)emit_error(fd,rid,501,"unsupported_operation"); return;
    }

    (void)emit_error(fd,rid,501,"no_handler_body");
}
