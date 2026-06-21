// host.cpp — the S4 conformance host: a standalone entity-core-protocol-cpp peer the
// Go validate-peer oracle (and the §10.2 entity-peer reference) drive over loopback TCP.
//
// CLI (the cohort-standard surface):
//   --port N              bind 127.0.0.1:N (default 7777; 0 = auto)
//   --name NAME           load the Ed25519 identity from ~/.entity/peers/NAME/keypair
//                         (entity-core PEM = base64 of a 32-byte seed). Absent =>
//                         the conformance default seed 0x11×32 (peer_id 2KHoAk…).
//   --debug-open-grants   the degenerate default→* seed policy (grant-gated categories
//                         need it). §4.4 restricted default otherwise.
//   --validate            wire the §7a conformance handlers (system/validate/{echo,
//                         dispatch-outbound}). OFF by default (dispatch-outbound is a
//                         standing dialer — never live in production).
//
// On a successful bind it prints exactly one readiness line:
//   LISTENING 127.0.0.1:<port> <peer_id>
// then blocks forever (the harness reaps it). The Peer stays the library's; the host is
// pure scaffolding (no protocol logic) — the S4 twin of C#'s Host / TS's host.ts.
//
// SPDX-License-Identifier: Apache-2.0
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "entity_core/crypto.hpp"
#include "entity_core/peer.hpp"
#include "entity_core/transport.hpp"

using namespace entity_core;

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

// The conformance default seed (0x11 × 32) → peer_id 2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg.
std::vector<std::byte> default_seed() { return std::vector<std::byte>(32, std::byte{0x11}); }

// Read ~/.entity/peers/NAME/keypair, an entity-core PEM whose body is base64 of a 32-byte
// Ed25519 seed (header/base64/footer). Returns the raw 32-byte seed, or nullopt on any error.
std::optional<std::vector<std::byte>> load_named_seed(const std::string& name) {
    const char* home = std::getenv("HOME");
    std::string dir = std::string(home ? home : "/root") + "/.entity/peers/" + name;
    std::string path = dir + "/keypair";
    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "host: cannot open identity %s\n", path.c_str());
        return std::nullopt;
    }
    // Concatenate the base64 body (every non-delimiter line).
    std::string b64, line;
    while (std::getline(in, line)) {
        if (line.rfind("-----", 0) == 0) continue;  // PEM delimiter
        // strip trailing CR / whitespace
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                                 line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        b64 += line;
    }
    std::vector<unsigned char> bin(b64.size());  // base64 decodes shorter than its input
    size_t bin_len = 0;
    if (sodium_base642bin(bin.data(), bin.size(), b64.c_str(), b64.size(), nullptr, &bin_len,
                          nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::fprintf(stderr, "host: identity %s is not valid base64\n", path.c_str());
        return std::nullopt;
    }
    if (bin_len != crypto::kEd25519SeedLen) {
        std::fprintf(stderr, "host: identity %s decodes to %zu bytes, expected 32\n", path.c_str(),
                     bin_len);
        return std::nullopt;
    }
    std::vector<std::byte> seed(bin_len);
    std::memcpy(seed.data(), bin.data(), bin_len);
    return seed;
}

}  // namespace

int main(int argc, char** argv) {
    int port = 7777;
    bool open_grants = false;
    bool conformance = false;
    std::string name;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if (a == "--name" && i + 1 < argc) {
            name = argv[++i];
        } else if (a == "--debug-open-grants") {
            open_grants = true;
        } else if (a == "--validate") {
            conformance = true;
        } else {
            std::fprintf(stderr, "host: unknown argument '%s'\n", a.c_str());
            std::fprintf(stderr,
                         "usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]\n");
            return 2;
        }
    }

    if (auto i = crypto::init(); !i) {
        std::fprintf(stderr, "host: crypto init failed\n");
        return 1;
    }

    std::vector<std::byte> seed;
    if (!name.empty()) {
        auto s = load_named_seed(name);
        if (!s) return 1;
        seed = std::move(*s);
    } else {
        seed = default_seed();
    }

    auto peer = Peer::create(std::span<const std::byte>(seed), open_grants, conformance);
    if (!peer) {
        std::fprintf(stderr, "host: peer create failed\n");
        return 1;
    }

    auto listener = Listener::start(**peer, port);
    if (!listener) {
        std::fprintf(stderr, "host: listen on port %d failed\n", port);
        return 1;
    }
    int bound = (*listener)->port();

    // The single readiness line the harness greps for. Flush immediately.
    std::printf("LISTENING 127.0.0.1:%d %s\n", bound, (*peer)->local().c_str());
    std::fflush(stdout);

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    // Block until signalled; the Listener's accept loop + per-connection reader threads run
    // in the background (RAII tears them down on Listener destruction).
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
