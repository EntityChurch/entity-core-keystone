/*
 * authority_test.c — the AUTHORITY-AS-QUERY harness: an oracle-driven interpreter of the
 * ACTUAL authored SQL artifact (the src/sql query files), the TurboWarp-#32 pattern applied to the
 * relational substrate. It loads schema.sql, registers the S2 crypto seam as app-defined
 * SQL functions, projects REAL Ed25519-signed capability facts into the tables, and runs the
 * VERBATIM authored queries (verify_ladder.sql / resolve.sql / k_of_n.sql) — no reimplementation
 * of the authority logic in C. The verdicts are the SQL's, exercised end-to-end with real crypto
 * flowing through ed25519_verify() INSIDE the query. This is a real in-container run (make
 * authority-check), the faithful low-risk verification of the interior — the live-oracle run
 * (S4 validate-peer) is the final confirmation caveat.
 *
 * Mandatory coverage: the ALLOW path + every §5.2a DENY surface a core peer reaches, the §4.10
 * chain-depth 400 pre-check, the §6.6 longest-prefix walk, and — non-negotiable per A-SQL-004 —
 * a GENUINE 2-of-3 multisig ACCEPT the rejection-only oracle category cannot cover.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ec_seam.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

/* ── file loader (the queries are the artifact; we run them verbatim) ── */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "read %s\n", path); exit(2); }
    b[n] = 0; fclose(f); return b;
}

static void must(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n---\n%s\n", err ? err : "?", sql);
        exit(2);
    }
}

/* hex-encode a blob into a X'..' SQL literal body */
static void hex(const unsigned char *b, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}

/* ── an identity: deterministic seed(label) → pubkey → hash(0x00||sha256(pub)) → peer_id ── */
typedef struct { unsigned char seed[32], pub[32], hash[33]; char peer_id[128]; char hhex[80]; } ident;
static void make_ident(const char *label, ident *id) {
    ec_seam_sha256((const unsigned char *)label, strlen(label), id->seed);
    if (ec_seam_ed25519_seed_to_pubkey(id->seed, id->pub) != 0) { fprintf(stderr, "seed2pub\n"); exit(2); }
    unsigned char dig[32]; ec_seam_sha256(id->pub, 32, dig);
    id->hash[0] = 0x00; memcpy(id->hash + 1, dig, 32);
    char *pid = NULL;
    if (ec_seam_peerid_format_alloc(1, 0, id->pub, 32, &pid) != 0) { fprintf(stderr, "peerid\n"); exit(2); }
    snprintf(id->peer_id, sizeof id->peer_id, "%s", pid); free(pid);
    hex(id->hash, 33, id->hhex);
}
/* a synthetic-but-stable 33-byte content id for a cap/exec (0x00||sha256(label)) */
static void make_hash(const char *label, unsigned char out33[33], char hhex[80]) {
    unsigned char dig[32]; ec_seam_sha256((const unsigned char *)label, strlen(label), dig);
    out33[0] = 0x00; memcpy(out33 + 1, dig, 32); hex(out33, 33, hhex);
}

/* ── fact binders (the host's §6.5 projection step, here driven by the harness) ── */
static void put_peer(sqlite3 *db, const ident *id) {
    char pk[80], sql[512];
    hex(id->pub, 32, pk);
    snprintf(sql, sizeof sql,
        "INSERT OR REPLACE INTO peer(hash,peer_id,public_key,key_type) "
        "VALUES(X'%s','%s',X'%s','ed25519');", id->hhex, id->peer_id, pk);
    must(db, sql);
}
static void put_cap(sqlite3 *db, const char *cap_hhex, const char *grantee_hhex,
                    const char *granter_hhex /*or NULL for multi*/, const char *parent_hhex /*or NULL*/,
                    long long created, const char *expires /*"NULL" or number*/, const char *not_before,
                    int is_multi, int threshold) {
    char sql[1024];
    snprintf(sql, sizeof sql,
        "INSERT INTO cap(hash,grantee,granter,parent,created_at,expires_at,not_before,is_multi,multi_threshold)"
        " VALUES(X'%s',X'%s',%s%s%s,%s%s%s,%lld,%s,%s,%d,%d);",
        cap_hhex, grantee_hhex,
        granter_hhex ? "X'" : "", granter_hhex ? granter_hhex : "NULL", granter_hhex ? "'" : "",
        parent_hhex ? "X'" : "", parent_hhex ? parent_hhex : "NULL", parent_hhex ? "'" : "",
        created, expires, not_before, is_multi, threshold);
    must(db, sql);
}
static void put_grant(sqlite3 *db, const char *cap_hhex, int gidx) {
    char sql[256];
    snprintf(sql, sizeof sql, "INSERT INTO cap_grant(cap_hash,grant_idx) VALUES(X'%s',%d);", cap_hhex, gidx);
    must(db, sql);
}
static void put_scope(sqlite3 *db, const char *cap_hhex, int gidx, const char *dim,
                      const char *kind, const char *pattern, const char *granter_peer_id) {
    char sql[512];
    snprintf(sql, sizeof sql,
        "INSERT INTO grant_scope(cap_hash,grant_idx,dim,kind,pattern,granter_peer_id)"
        " VALUES(X'%s',%d,'%s','%s','%s','%s');", cap_hhex, gidx, dim, kind, pattern, granter_peer_id);
    must(db, sql);
}
/* sign target33 with signer's seed and bind the signature row */
static void put_sig(sqlite3 *db, const ident *signer, const unsigned char target33[33], const char *target_hhex) {
    unsigned char sig[64]; char shex[160]; char sql[512];
    if (ec_seam_ed25519_sign(signer->seed, target33, 33, sig) != 0) { fprintf(stderr, "sign\n"); exit(2); }
    hex(sig, 64, shex);
    snprintf(sql, sizeof sql,
        "INSERT INTO signature(target,signer,algorithm,sig) VALUES(X'%s',X'%s','ed25519',X'%s');",
        target_hhex, signer->hhex, shex);
    must(db, sql);
}
static void put_handler(sqlite3 *db, const char *path) {
    char sql[256]; snprintf(sql, sizeof sql, "INSERT OR IGNORE INTO handler(path) VALUES('%s');", path);
    must(db, sql);
}
static void put_multi_signer(sqlite3 *db, const char *cap_hhex, const ident *s) {
    char sql[256];
    snprintf(sql, sizeof sql, "INSERT INTO multi_signer(cap_hash,signer) VALUES(X'%s',X'%s');", cap_hhex, s->hhex);
    must(db, sql);
}
static void set_request(sqlite3 *db, const char *ch_hhex, const char *wire_hhex, const char *author_hhex,
                        const char *cap_hhex, const char *uri, const char *op, long long now,
                        const char *local_peer_id) {
    char sql[1024];
    must(db, "DELETE FROM request; DELETE FROM request_resource;");
    snprintf(sql, sizeof sql,
        "INSERT INTO request(content_hash,wire_hash,author,capability,uri,operation,now_ms,local_peer_id,supports_revocation)"
        " VALUES(X'%s',X'%s',X'%s',X'%s','%s','%s',%lld,'%s',1);",
        ch_hhex, wire_hhex, author_hhex, cap_hhex, uri, op, now, local_peer_id);
    must(db, sql);
}
static void reset_data(sqlite3 *db) {
    must(db, "DELETE FROM peer;DELETE FROM cap;DELETE FROM multi_signer;DELETE FROM cap_grant;"
             "DELETE FROM grant_scope;DELETE FROM grant_kv;DELETE FROM signature;DELETE FROM handler;"
             "DELETE FROM revocation;DELETE FROM request;DELETE FROM request_resource;");
}

/* run verify_ladder.sql (self-contained: reads the request row + tables) → (status,code) */
static void run_verdict(sqlite3 *db, const char *ladder_sql, char *status, char *code) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, ladder_sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare ladder: %s\n", sqlite3_errmsg(db)); exit(2);
    }
    status[0] = code[0] = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *s = sqlite3_column_text(st, 0), *c = sqlite3_column_text(st, 1);
        if (s) snprintf(status, 8, "%s", s);
        if (c) snprintf(code, 64, "%s", c);
    }
    sqlite3_finalize(st);
}

static void check(const char *name, const char *got_s, const char *got_c,
                  const char *want_s, const char *want_c) {
    int ok = !strcmp(got_s, want_s) && !strcmp(got_c, want_c);
    printf("  [%s] %-42s got=(%s,%s) want=(%s,%s)\n", ok ? "PASS" : "FAIL", name,
           got_s[0]?got_s:"-", got_c[0]?got_c:"-", want_s, want_c);
    if (ok) g_pass++; else g_fail++;
}

int main(void) {
    printf("== SQL authority-as-query harness (verbatim src/sql/*.sql over real Ed25519 facts) ==\n");
    printf("   seam: %s\n", ec_seam_impl_info());

    char *schema = slurp("src/sql/schema.sql");
    char *ladder = slurp("src/sql/verify_ladder.sql");
    char *resolve = slurp("src/sql/resolve.sql");
    char *konf = slurp("src/sql/k_of_n.sql");

    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { fprintf(stderr, "open\n"); return 2; }
    if (ec_seam_register_sql_functions(db) != SQLITE_OK) { fprintf(stderr, "register fns\n"); return 2; }
    must(db, schema);

    ident P, alice, mallory;        /* P = this (local) peer / root granter; alice = a client */
    make_ident("local-peer-P", &P);
    make_ident("alice", &alice);
    make_ident("mallory", &mallory);

    unsigned char root_h[33], exec_h[33]; char root_hhex[80], exec_hhex[80];
    make_hash("root-cap-1", root_h, root_hhex);
    make_hash("exec-1", exec_h, exec_hhex);

    char status[8], code[64];

    /* handler path uses the REAL local peer_id */
    char htree[256];
    snprintf(htree, sizeof htree, "/%s/system/tree", P.peer_id);
    char uri_tree_get[256], uri_unreg[256];
    snprintf(uri_tree_get, sizeof uri_tree_get, "/%s/system/tree/instances/x", P.peer_id);
    snprintf(uri_unreg,    sizeof uri_unreg,    "/%s/local/nope/x", P.peer_id);

    /* 1. ALLOW — valid auth, handler resolves, grant covers op+handler+peer → 200 ok */
    reset_data(db); put_peer(db,&P); put_peer(db,&alice);
    put_cap(db, root_hhex, alice.hhex, P.hhex, NULL, 1000, "NULL", "NULL", 0, 0);
    put_grant(db, root_hhex, 0);
    put_scope(db, root_hhex, 0, "handlers","include","system/tree",P.peer_id);
    put_scope(db, root_hhex, 0, "resources","include","system/type/*",P.peer_id);
    put_scope(db, root_hhex, 0, "operations","include","get",P.peer_id);
    put_sig(db, &P, root_h, root_hhex);
    put_handler(db, htree);
    put_sig(db, &alice, exec_h, exec_hhex);   /* alice signs the EXECUTE */
    set_request(db, exec_hhex, exec_hhex, alice.hhex, root_hhex, uri_tree_get, "get", 5000, P.peer_id);
    run_verdict(db, ladder, status, code);
    check("allow_tree_get", status, code, "200", "ok");

    /* 2. 401 authentication_failed — EXECUTE signature absent */
    must(db, "DELETE FROM signature;");
    put_sig(db, &P, root_h, root_hhex);       /* keep cap sig, drop exec sig */
    run_verdict(db, ladder, status, code);
    check("auth_fail_no_exec_sig", status, code, "401", "authentication_failed");

    /* 3. 401 authentication_failed — EXECUTE signed by mallory, not the author (signer != author) */
    must(db, "DELETE FROM signature;"); put_sig(db, &P, root_h, root_hhex);
    put_peer(db,&mallory); put_sig(db, &mallory, exec_h, exec_hhex);
    run_verdict(db, ladder, status, code);
    check("auth_fail_wrong_signer", status, code, "401", "authentication_failed");

    /* 4. 403 capability_denied — grantee != author (cap granted to mallory, alice authors) */
    reset_data(db); put_peer(db,&P); put_peer(db,&alice); put_peer(db,&mallory);
    put_cap(db, root_hhex, mallory.hhex, P.hhex, NULL, 1000, "NULL", "NULL", 0, 0);
    put_grant(db, root_hhex, 0);
    put_scope(db, root_hhex, 0, "handlers","include","system/tree",P.peer_id);
    put_scope(db, root_hhex, 0, "operations","include","get",P.peer_id);
    put_sig(db, &P, root_h, root_hhex); put_sig(db, &alice, exec_h, exec_hhex);
    put_handler(db, htree);
    set_request(db, exec_hhex, exec_hhex, alice.hhex, root_hhex, uri_tree_get, "get", 5000, P.peer_id);
    run_verdict(db, ladder, status, code);
    check("authz_grantee_mismatch", status, code, "403", "capability_denied");

    /* 5. 401 unresolvable_grantee — an INTERIOR chain link's grantee is a ghost (not a present
          peer). The leaf grantee == author == alice (resolvable, so step-3 passes), but the root's
          grantee is a ghost identity, so the §5.5 per-link grantee-resolve fails → 401 (the authz
          carve-out). This arm sits ABOVE the per-link signature arm in the ladder, matching the
          spec's grantee-resolution rung. */
    { unsigned char child_h[33]; char child_hhex[80]; make_hash("child-unres", child_h, child_hhex);
      unsigned char ghost[33]; char ghex[80]; make_hash("ghost-id", ghost, ghex);
      reset_data(db); put_peer(db,&P); put_peer(db,&alice);
      put_cap(db, root_hhex, ghex, P.hhex, NULL, 1000, "NULL","NULL",0,0);         /* root.grantee = ghost (unresolvable) */
      put_cap(db, child_hhex, alice.hhex, ghex, root_hhex, 1000,"NULL","NULL",0,0);/* child.granter = ghost (== parent.grantee) */
      put_grant(db, child_hhex, 0);
      put_scope(db, child_hhex,0,"handlers","include","system/tree",P.peer_id);
      put_scope(db, child_hhex,0,"operations","include","get",P.peer_id);
      put_sig(db,&P,root_h,root_hhex);
      put_sig(db,&alice,exec_h,exec_hhex);
      put_handler(db,htree);
      set_request(db, exec_hhex, exec_hhex, alice.hhex, child_hhex, uri_tree_get, "get", 5000, P.peer_id);
      run_verdict(db, ladder, status, code);
      check("unresolvable_grantee", status, code, "401", "unresolvable_grantee");
    }

    /* 6. 403 capability_denied — scope deny: request op 'put' not in grant {get} */
    reset_data(db); put_peer(db,&P); put_peer(db,&alice);
    put_cap(db, root_hhex, alice.hhex, P.hhex, NULL, 1000,"NULL","NULL",0,0);
    put_grant(db, root_hhex, 0);
    put_scope(db, root_hhex,0,"handlers","include","system/tree",P.peer_id);
    put_scope(db, root_hhex,0,"operations","include","get",P.peer_id);
    put_sig(db,&P,root_h,root_hhex); put_sig(db,&alice,exec_h,exec_hhex); put_handler(db,htree);
    set_request(db, exec_hhex, exec_hhex, alice.hhex, root_hhex, uri_tree_get, "put", 5000, P.peer_id);
    run_verdict(db, ladder, status, code);
    check("authz_scope_deny_operation", status, code, "403", "capability_denied");

    /* 7. 404 not_found — valid auth (open grant) but no handler at the path */
    reset_data(db); put_peer(db,&P); put_peer(db,&alice);
    put_cap(db, root_hhex, alice.hhex, P.hhex, NULL, 1000,"NULL","NULL",0,0);
    put_grant(db, root_hhex, 0);
    put_scope(db, root_hhex,0,"handlers","include","*",P.peer_id);       /* open handler scope */
    put_scope(db, root_hhex,0,"operations","include","*",P.peer_id);
    put_scope(db, root_hhex,0,"resources","include","/*/*",P.peer_id);
    put_scope(db, root_hhex,0,"peers","include","*",P.peer_id);
    put_sig(db,&P,root_h,root_hhex); put_sig(db,&alice,exec_h,exec_hhex);
    put_handler(db, htree);                                              /* only system/tree registered */
    set_request(db, exec_hhex, exec_hhex, alice.hhex, root_hhex, uri_unreg, "get", 5000, P.peer_id);
    run_verdict(db, ladder, status, code);
    /* §3.3's 404 row (0.8.2.7) spells the RESOLUTION miss `handler_not_found`. `not_found`
     * is the neighbouring row -- a bound-path miss INSIDE a resolved handler -- and this
     * assertion carried it until the ladder was corrected. */
    check("not_found_unregistered_path", status, code, "404", "handler_not_found");

    /* 8. 403 capability_denied — expired capability (expires_at < now) */
    reset_data(db); put_peer(db,&P); put_peer(db,&alice);
    put_cap(db, root_hhex, alice.hhex, P.hhex, NULL, 1000, "2000", "NULL", 0, 0);  /* expires at 2000ms */
    put_grant(db, root_hhex, 0);
    put_scope(db, root_hhex,0,"handlers","include","system/tree",P.peer_id);
    put_scope(db, root_hhex,0,"operations","include","get",P.peer_id);
    put_sig(db,&P,root_h,root_hhex); put_sig(db,&alice,exec_h,exec_hhex); put_handler(db,htree);
    set_request(db, exec_hhex, exec_hhex, alice.hhex, root_hhex, uri_tree_get, "get", 5000, P.peer_id); /* now=5000 > 2000 */
    run_verdict(db, ladder, status, code);
    check("authz_expired", status, code, "403", "capability_denied");

    /* 9. 400 chain_depth_exceeded — a 66-link chain (> 64) → structural 400, BEFORE authz */
    {
      reset_data(db); put_peer(db,&P); put_peer(db,&alice);
      char prev[80]; char cur[80]; unsigned char curh[33];
      /* root at depth 0 */
      make_hash("deep-0", curh, cur); put_cap(db, cur, P.hhex, P.hhex, NULL, 1000,"NULL","NULL",0,0);
      put_sig(db,&P,curh,cur);
      snprintf(prev, sizeof prev, "%s", cur);
      for (int i = 1; i <= 66; i++) {
        char lbl[32]; snprintf(lbl, sizeof lbl, "deep-%d", i);
        make_hash(lbl, curh, cur);
        put_cap(db, cur, P.hhex, P.hhex, prev, 1000,"NULL","NULL",0,0);
        put_sig(db,&P,curh,cur);
        snprintf(prev, sizeof prev, "%s", cur);
      }
      put_grant(db, cur, 0);
      put_scope(db, cur,0,"handlers","include","system/tree",P.peer_id);
      put_scope(db, cur,0,"operations","include","get",P.peer_id);
      put_handler(db, htree);
      set_request(db, exec_hhex, exec_hhex, P.hhex, cur, uri_tree_get, "get", 5000, P.peer_id);
      put_sig(db,&P,exec_h,exec_hhex);
      run_verdict(db, ladder, status, code);
      check("chain_depth_exceeded_400", status, code, "400", "chain_depth_exceeded");
    }

    /* 10. §6.6 resolve.sql longest-prefix — /P/system and /P/system/tree registered; resolve
          /P/system/tree/x → picks /P/system/tree (the LONGER prefix). */
    {
      reset_data(db);
      char hsys[256]; snprintf(hsys, sizeof hsys, "/%s/system", P.peer_id);
      put_handler(db, hsys); put_handler(db, htree);
      sqlite3_stmt *st; sqlite3_prepare_v2(db, resolve, -1, &st, NULL);
      sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, ":uri"), uri_tree_get, -1, SQLITE_TRANSIENT);
      char got[256] = ""; if (sqlite3_step(st) == SQLITE_ROW) snprintf(got, sizeof got, "%s", sqlite3_column_text(st,0));
      sqlite3_finalize(st);
      int ok = !strcmp(got, htree);
      printf("  [%s] %-42s got=%s want=%s\n", ok?"PASS":"FAIL", "resolve_longest_prefix", got, htree);
      if (ok) g_pass++; else g_fail++;
    }

    /* 11. THE MANDATORY 2-of-3 MULTISIG ACCEPT (A-SQL-004) — the direction the rejection-only
          oracle category cannot cover. Three signers, threshold 2, TWO valid signatures. */
    {
      ident s1, s2, s3; make_ident("signer-1",&s1); make_ident("signer-2",&s2); make_ident("signer-3",&s3);
      unsigned char mroot_h[33]; char mroot_hhex[80]; make_hash("multi-root", mroot_h, mroot_hhex);
      reset_data(db);
      put_peer(db,&P); put_peer(db,&alice); put_peer(db,&s1); put_peer(db,&s2); put_peer(db,&s3);
      /* multi-sig root: granter NULL, is_multi=1, threshold=2, signers {s1,s2,s3}. Root-local
         requires the LOCAL peer to be in signers + signed (M6) — so make s1 the local peer. */
      char local_is_s1[128]; snprintf(local_is_s1, sizeof local_is_s1, "%s", s1.peer_id);
      put_cap(db, mroot_hhex, alice.hhex, NULL, NULL, 1000, "NULL","NULL", 1, 2);
      put_multi_signer(db, mroot_hhex, &s1); put_multi_signer(db, mroot_hhex, &s2); put_multi_signer(db, mroot_hhex, &s3);
      put_grant(db, mroot_hhex, 0);
      put_scope(db, mroot_hhex,0,"handlers","include","system/tree", s1.peer_id);
      put_scope(db, mroot_hhex,0,"operations","include","get", s1.peer_id);
      /* TWO of three sign the cap (s1, s2) — meets threshold 2 */
      put_sig(db,&s1,mroot_h,mroot_hhex); put_sig(db,&s2,mroot_h,mroot_hhex);
      put_sig(db,&alice,exec_h,exec_hhex);
      char uri_s1_tree[256]; snprintf(uri_s1_tree, sizeof uri_s1_tree, "/%s/system/tree/x", s1.peer_id);
      put_handler(db, /*handler under s1's namespace*/ (snprintf(htree,sizeof htree,"/%s/system/tree",s1.peer_id), htree));
      set_request(db, exec_hhex, exec_hhex, alice.hhex, mroot_hhex, uri_s1_tree, "get", 5000, local_is_s1);
      run_verdict(db, ladder, status, code);
      check("multisig_2of3_ACCEPT", status, code, "200", "ok");

      /* and k_of_n.sql standalone must report satisfied for this cap */
      { sqlite3_stmt *st; sqlite3_prepare_v2(db, konf, -1, &st, NULL);
        sqlite3_bind_blob(st, sqlite3_bind_parameter_index(st, ":cap_hash"), mroot_h, 33, SQLITE_TRANSIENT);
        int sat = 0; if (sqlite3_step(st)==SQLITE_ROW) sat = sqlite3_column_int(st, 3);
        sqlite3_finalize(st);
        printf("  [%s] %-42s satisfied=%d want=1\n", sat==1?"PASS":"FAIL", "k_of_n_having_accept", sat);
        if (sat==1) g_pass++; else g_fail++;
      }

      /* 12. multisig REJECT — only ONE valid signature (< threshold 2) → 403 capability_denied */
      must(db, "DELETE FROM signature;");
      put_sig(db,&s1,mroot_h,mroot_hhex);           /* only s1 signs */
      put_sig(db,&alice,exec_h,exec_hhex);
      run_verdict(db, ladder, status, code);
      check("multisig_1of3_REJECT", status, code, "403", "capability_denied");
    }

    printf("== authority-as-query: %d pass, %d fail ==\n", g_pass, g_fail);
    sqlite3_close(db);
    free(schema); free(ladder); free(resolve); free(konf);
    return g_fail ? 1 : 0;
}
