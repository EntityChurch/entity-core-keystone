/*
 * host.c — the standalone S4-ready peer host. Boots one peer on a localhost port and
 * serves until SIGINT/SIGTERM. Prints a `LISTENING <port>` line on stdout once bound
 * (so a runner can parse the chosen ephemeral port), then `PEER_ID <peer_id>`.
 *
 * Flags (mirror the cohort host + the Go entity-peer surface this peer is gated against):
 *   --port N            TCP listen port (0 = auto/ephemeral; default 0)
 *   --seed HEX          32-byte hex seed (default: 0x11 * 32)
 *   --validate          enable the §7a system/validate conformance handlers (OFF default)
 *   --debug-open-grants degenerate [default → *] seed policy (OFF by default)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "transport.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static bool parse_seed_hex(const char *hex, uint8_t out[32])
{
    if (strlen(hex) != 64) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char *end = NULL;
        long v = strtol(b, &end, 16);
        if (*end != 0) {
            return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

int main(int argc, char **argv)
{
    int port = 0;
    bool validate = false;
    bool open_grants = false;
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (!parse_seed_hex(argv[++i], seed)) {
                fprintf(stderr, "host: --seed must be 64 hex chars\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--validate") == 0) {
            validate = true;
        } else if (strcmp(argv[i], "--debug-open-grants") == 0) {
            open_grants = true;
        } else {
            fprintf(stderr, "host: unknown arg %s\n", argv[i]);
            return 2;
        }
    }

    ec_peer *peer = NULL;
    if (ec_peer_create(seed, open_grants, validate, &peer) != EC_OK) {
        fprintf(stderr, "host: peer create failed\n");
        return 1;
    }

    ec_listener *l = NULL;
    int bound = 0;
    if (ec_listener_start(peer, port, &l, &bound) != EC_OK) {
        fprintf(stderr, "host: listen failed\n");
        ec_peer_free(peer);
        return 1;
    }

    printf("LISTENING %d\n", bound);
    printf("PEER_ID %s\n", ec_peer_local(peer));
    fflush(stdout);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (!g_stop) {
        struct timespec ts = { 0, 50 * 1000 * 1000 };  /* 50ms poll */
        nanosleep(&ts, NULL);
    }

    ec_listener_stop(l);
    ec_peer_free(peer);
    return 0;
}
