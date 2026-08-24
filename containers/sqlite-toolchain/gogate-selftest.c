/*
 * gogate-selftest.c — the S1 GO-gate for the SQL (authority-as-query) peer.
 *
 * Baked into the sqlite-toolchain image build (and runnable standalone). Proves,
 * headless, inside the capped container, the three things S1 must establish before
 * S2/S3 authoring can begin:
 *
 *   1. The query engine boots and runs a RECURSIVE CTE. This is the §5.5 delegation
 *      chain-walk primitive — if the recursive CTE works, the chain-walk is
 *      expressible in SQL. (Prints the fixpoint of a trivial 1..10 closure.)
 *
 *   2. The host seam reaches libentitycore_codec AND crypto is callable FROM SQL.
 *      We register `sha256(blob)` as a SQLite application-defined function backed by
 *      ec_sha256, then run an `ec_sha256` KAT *through a SQL query*
 *      (`SELECT hex(sha256(x'616263'))` == SHA-256("abc")). This proves both the FFI
 *      link and the tight-seam idea from the feasibility deep-dive: the verify
 *      sequencing can stay in SQL because the crypto primitive is a SQL function.
 *
 *   3. The host transport is 8-bit clean. A loopback TCP echo of a payload that
 *      includes 0x00 and 0xFF must round-trip byte-identical (framed binary CBOR
 *      carries embedded NULs and high bytes — a non-8-bit-clean transport would
 *      silently corrupt frames).
 *
 * Exit 0 iff all three pass; non-zero (and a FATAL line) on the first failure.
 * This is GO/NO-GO evidence, not decoration — the build fails if the gate fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sqlite3.h"
#include "entitycore_codec.h"

/* ── app-defined SQL function: sha256(blob) -> 32-byte blob, via ec_sha256 ── */
static void fn_sha256(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    if (argc != 1) { sqlite3_result_error(ctx, "sha256() takes 1 arg", -1); return; }
    const unsigned char *data = (const unsigned char *)sqlite3_value_blob(argv[0]);
    int n = sqlite3_value_bytes(argv[0]);
    unsigned char out[EC_SHA256_LEN];
    int rc = ec_sha256(data, (size_t)n, out);
    if (rc != EC_OK) { sqlite3_result_error(ctx, "ec_sha256 FFI call failed", -1); return; }
    sqlite3_result_blob(ctx, out, EC_SHA256_LEN, SQLITE_TRANSIENT);
}

/* ── Check 1 + 2: recursive CTE + crypto-callable-from-SQL KAT ── */
static int check_query_engine(void) {
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        fprintf(stderr, "FATAL: sqlite3_open failed: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    printf("  sqlite version: %s\n", sqlite3_libversion());

    /* Check 1: recursive CTE (the §5.5 chain-walk primitive). Expect sum(1..10)=55. */
    sqlite3_stmt *st = NULL;
    const char *cte =
        "WITH RECURSIVE c(n) AS ("
        "  SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n < 10"
        ") SELECT count(*), sum(n) FROM c;";
    if (sqlite3_prepare_v2(db, cte, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "FATAL: recursive CTE prepare failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db); return 1;
    }
    if (sqlite3_step(st) != SQLITE_ROW) {
        fprintf(stderr, "FATAL: recursive CTE produced no row\n");
        sqlite3_finalize(st); sqlite3_close(db); return 1;
    }
    long cnt = sqlite3_column_int64(st, 0), total = sqlite3_column_int64(st, 1);
    sqlite3_finalize(st);
    if (cnt != 10 || total != 55) {
        fprintf(stderr, "FATAL: recursive CTE wrong result: count=%ld sum=%ld (want 10/55)\n", cnt, total);
        sqlite3_close(db); return 1;
    }
    printf("  CHECK 1 OK: recursive CTE fixpoint count=%ld sum=%ld (§5.5 chain-walk expressible)\n", cnt, total);

    /* Register the crypto seam as a SQL function. */
    if (sqlite3_create_function(db, "sha256", 1,
                                SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                fn_sha256, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "FATAL: could not register sha256() app-defined function\n");
        sqlite3_close(db); return 1;
    }

    /* Check 2: ec_sha256 KAT, invoked FROM SQL. sha256("abc") known answer. */
    const char *KAT = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    if (sqlite3_prepare_v2(db, "SELECT hex(sha256(x'616263'));", -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "FATAL: KAT query prepare failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db); return 1;
    }
    if (sqlite3_step(st) != SQLITE_ROW) {
        fprintf(stderr, "FATAL: KAT query produced no row (ec_sha256 error?): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(st); sqlite3_close(db); return 1;
    }
    const char *got = (const char *)sqlite3_column_text(st, 0);
    int ok = got && strcmp(got, KAT) == 0;
    printf("  provenance: %s\n", ec_impl_info());
    printf("  CHECK 2 OK: SELECT hex(sha256(x'616263')) = %s\n", got ? got : "(null)");
    sqlite3_finalize(st);
    sqlite3_close(db);
    if (!ok) {
        fprintf(stderr, "FATAL: ec_sha256 KAT mismatch\n  want %s\n  got  %s\n", KAT, got ? got : "(null)");
        return 1;
    }
    return 0;
}

/* ── Check 3: 8-bit-clean loopback TCP echo (incl. 0x00 / 0xFF) ── */
static const unsigned char PAYLOAD[] = { 0x00, 0x01, 0xFF, 0x42, 0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x00 };
#define PAYLOAD_LEN (sizeof(PAYLOAD))

static void *echo_server(void *arg) {
    int lfd = *(int *)arg;
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) return NULL;
    unsigned char buf[PAYLOAD_LEN];
    size_t got = 0;
    while (got < PAYLOAD_LEN) {
        ssize_t r = recv(cfd, buf + got, PAYLOAD_LEN - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    size_t sent = 0;
    while (sent < got) {
        ssize_t w = send(cfd, buf + sent, got - sent, 0);
        if (w <= 0) break;
        sent += (size_t)w;
    }
    close(cfd);
    return NULL;
}

static int check_socket_byte_clean(void) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral */
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); close(lfd); return 1; }
    if (listen(lfd, 1) < 0) { perror("listen"); close(lfd); return 1; }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);

    pthread_t th;
    pthread_create(&th, NULL, echo_server, &lfd);

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(cfd); close(lfd); return 1;
    }
    send(cfd, PAYLOAD, PAYLOAD_LEN, 0);
    unsigned char back[PAYLOAD_LEN];
    size_t got = 0;
    while (got < PAYLOAD_LEN) {
        ssize_t r = recv(cfd, back + got, PAYLOAD_LEN - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(cfd);
    pthread_join(th, NULL);
    close(lfd);

    if (got != PAYLOAD_LEN || memcmp(PAYLOAD, back, PAYLOAD_LEN) != 0) {
        fprintf(stderr, "FATAL: socket echo not byte-clean (got %zu of %zu bytes)\n", got, PAYLOAD_LEN);
        return 1;
    }
    printf("  CHECK 3 OK: loopback TCP echo byte-clean over %zu bytes incl. 0x00/0xFF\n", PAYLOAD_LEN);
    return 0;
}

int main(void) {
    printf("SQL peer S1 GO-gate self-test (sqlite-toolchain)\n");
    if (check_query_engine())      { fprintf(stderr, "GO-GATE: NO-GO (query engine / crypto seam)\n"); return 1; }
    if (check_socket_byte_clean()) { fprintf(stderr, "GO-GATE: NO-GO (transport)\n"); return 1; }
    printf("GO-GATE OK: recursive-CTE + ec_sha256-callable-from-SQL + 8-bit-clean transport all proven\n");
    return 0;
}
