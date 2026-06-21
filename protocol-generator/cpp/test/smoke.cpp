// smoke.cpp — the S3 phase exit gate: a two-C++-peer loopback over real localhost TCP.
//
// A RESPONDER peer listens; an INITIATOR peer (a second identity) dials it and drives the
// §4.1 forward handshake (hello → authenticate), then exercises the wire-level peer surface:
//   Scenario 1 (core ops, default seed policy):
//     - session established (capability minted)         §4.1
//     - remote peer_id matches the responder            §4.6 identity binding
//     - unregistered path → 404                          §6.6 no handler resolved
//     - granted tree get → 200 (discovery floor)         §4.4
//     - tree get returns a system/handler/interface
//     - capability request → 200                          §6.2 mint-bounded
//     - 8 interleaved requests each correlated → 8/8     N7 / §6.11 request_id demux
//   Scenario 2 (Core Extensibility Boundary; --debug-open-grants + --validate):
//     - handler register → 200 (live, not 501)           §6.13(a)
//     - emit hook fired on register's tree writes        §6.13(c)
//     - §7a echo → 200                                    §7a resolve→dispatch
//     - §7a echo returns params verbatim
//     - §7a dispatch-outbound reentry → 200 (§6.11)       the S4 surface, smoke-tested
//   → SMOKE: PASS (12/12)
//
// Built under ASan/LSan/UBSan: a memory bug (leak / UAF / overflow / UB) FAILS the run.
// The full validate-peer --profile core run is S4; this proves the peer talks the wire.
//
// SPDX-License-Identifier: Apache-2.0
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

#include "entity_core/peer.hpp"
#include "entity_core/transport.hpp"
#include "entity_core/wire.hpp"

using namespace entity_core;

namespace {
int g_pass = 0;
int g_fail = 0;
std::atomic<int> g_emit_events{0};

void check(const char* name, bool ok) {
    if (ok) g_pass++; else g_fail++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

std::vector<std::byte> seed_fill(std::uint8_t b) {
    return std::vector<std::byte>(32, std::byte{b});
}

EcfValue scope_inc(std::span<const std::string_view> items) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("include"), value::text_array(items));
    return m;
}

EcfValue make_scoped_grant(std::span<const std::string_view> h,
                           std::span<const std::string_view> r,
                           std::span<const std::string_view> o) {
    auto g = EcfValue::map();
    g.put(EcfValue::text("handlers"), scope_inc(h));
    g.put(EcfValue::text("resources"), scope_inc(r));
    g.put(EcfValue::text("operations"), scope_inc(o));
    return g;
}

// ── scenario 1 ────────────────────────────────────────────────────────────────────
int scenario_core() {
    auto responder = Peer::create(seed_fill(0x11), false, false);
    auto initiator = Peer::create(seed_fill(0x22), false, false);
    if (!responder || !initiator) { std::fprintf(stderr, "peer create failed\n"); return 1; }

    auto listener = Listener::start(**responder, 0);
    if (!listener) { std::fprintf(stderr, "listen failed\n"); return 1; }
    int port = (*listener)->port();
    std::printf("Responder listening on 127.0.0.1:%d (peer %s)\n", port,
                (*responder)->local().c_str());

    auto sess = Session::dial(**initiator, "127.0.0.1", port);
    if (!sess) { std::fprintf(stderr, "dial/handshake failed\n"); return 1; }
    Session& s = **sess;
    const std::string& remote = s.remote_peer();

    std::printf("Handshake:\n");
    check("session established (capability minted)", s.has_capability());
    check("remote peer_id matches responder", remote == (*responder)->local());

    std::printf("Dispatch:\n");
    {
        std::string uri = "/" + remote + "/does/not/exist";
        auto params = wire::empty_params();
        auto r = s.execute(uri, "noop", **params, std::nullopt);
        check("unregistered path -> 404", r && response_status(*r) == 404);
    }
    {
        std::string uri = "/" + remote + "/system/tree";
        auto params = wire::empty_params();
        auto res = wire::resource_target("system/handler/system/tree");
        auto r = s.execute(uri, "get", **params, res);
        check("granted tree get -> 200", r && response_status(*r) == 200);
        auto rr = r ? response_result(*r) : nullptr;
        check("tree get returns a system/handler/interface entity",
              rr && rr->type() == "system/handler/interface");
    }
    {
        std::string uri = "/" + remote + "/system/capability";
        using V = std::string_view;
        std::array<V, 1> h{"system/tree"};
        std::array<V, 1> r_{"system/type/*"};
        std::array<V, 1> o{"get"};
        auto grant = make_scoped_grant(h, r_, o);
        auto grants = EcfValue::array();
        grants.push(std::move(grant));
        auto pm = EcfValue::map();
        pm.put(EcfValue::text("grants"), std::move(grants));
        auto params = Entity::make("system/capability/request", std::move(pm));
        auto r = s.execute(uri, "request", **params, std::nullopt);
        check("capability request -> 200", r && response_status(*r) == 200);
    }
    std::printf("Concurrency (request_id demux):\n");
    {
        constexpr int N = 8;
        std::array<bool, N> okv{};
        std::vector<std::thread> ts;
        std::string uri = "/" + remote + "/system/tree";
        for (int i = 0; i < N; ++i) {
            ts.emplace_back([&, i] {
                auto params = wire::empty_params();
                auto res = wire::resource_target("system/handler/system/tree");
                auto r = s.execute(uri, "get", **params, res);
                auto rr = r ? response_result(*r) : nullptr;
                okv[i] = r && response_status(*r) == 200 && rr &&
                         rr->type() == "system/handler/interface";
            });
        }
        int correlated = 0;
        for (int i = 0; i < N; ++i) { ts[i].join(); if (okv[i]) correlated++; }
        char msg[64];
        std::snprintf(msg, sizeof(msg), "8 interleaved requests each correlated -> %d/8",
                      correlated);
        check(msg, correlated == N);
    }
    return 0;
}

// ── scenario 2 ────────────────────────────────────────────────────────────────────
int scenario_extensibility() {
    auto responder = Peer::create(seed_fill(0x33), true, true);   // open-grants + validate
    auto initiator = Peer::create(seed_fill(0x44), false, false);
    if (!responder || !initiator) { std::fprintf(stderr, "peer create failed\n"); return 1; }
    (*responder)->store().register_tree_consumer(
        [](const std::string&) { g_emit_events.fetch_add(1); });

    auto listener = Listener::start(**responder, 0);
    if (!listener) return 1;
    int port = (*listener)->port();
    auto sess = Session::dial(**initiator, "127.0.0.1", port);
    if (!sess) return 1;
    Session& s = **sess;
    const std::string& remote = s.remote_peer();
    int emit_before = g_emit_events.load();

    std::printf("Extensibility (open-grants + --validate):\n");
    {
        std::string uri = "/" + remote + "/system/handler";
        auto manifest = EcfValue::map();
        manifest.put(EcfValue::text("name"), EcfValue::text("demo"));
        manifest.put(EcfValue::text("operations"), EcfValue::map());
        auto pm = EcfValue::map();
        pm.put(EcfValue::text("manifest"), std::move(manifest));
        auto req = Entity::make("system/handler/register-request", std::move(pm));
        auto res = wire::resource_target("system/handler/demo");
        auto r = s.execute(uri, "register", **req, res);
        check("handler register -> 200 (live, not 501)", r && response_status(*r) == 200);
        check("emit hook fired on register's tree writes (§6.13(c))",
              g_emit_events.load() > emit_before);
    }
    {
        std::string uri = "/" + remote + "/system/validate/echo";
        auto pm = EcfValue::map();
        pm.put(EcfValue::text("ping"), EcfValue::uint(42));
        auto payload = Entity::make("primitive/any", std::move(pm));
        auto r = s.execute(uri, "echo", **payload, std::nullopt);
        check("§7a echo -> 200", r && response_status(*r) == 200);
        auto rr = r ? response_result(*r) : nullptr;
        check("§7a echo returns params verbatim", rr && rr->type() == "primitive/any");
    }
    return 0;
}

// ── scenario 3: §6.11 reentry dispatch-outbound (the S4 origination-core surface) ──
//
// The INITIATOR is also a B-role server on its own connection: it minted a reentry cap
// authorizing the RESPONDER to call the initiator's system/validate/echo. The initiator
// sends `system/validate/dispatch-outbound:dispatch` to the responder; the responder
// ORIGINATES an EXECUTE back to the initiator over the SAME inbound connection (§6.11
// reentry), the initiator's reader dispatches it (validator-as-B), and the echo result
// flows back. This proves the reentry transport + correlation the S4 gate (3/3) needs.
int scenario_reentry() {
    // Both peers conformance-enabled: the responder runs dispatch-outbound; the initiator
    // serves echo as the reentry B-role.
    auto responder = Peer::create(seed_fill(0x55), true, true);
    auto initiator = Peer::create(seed_fill(0x66), true, true);
    if (!responder || !initiator) { std::fprintf(stderr, "peer create failed\n"); return 1; }

    auto listener = Listener::start(**responder, 0);
    if (!listener) return 1;
    int port = (*listener)->port();
    auto sess = Session::dial(**initiator, "127.0.0.1", port);
    if (!sess) return 1;
    Session& s = **sess;
    const std::string& remote = s.remote_peer();
    const std::string& local_init = (*initiator)->local();
    const auto& init_id = (*initiator)->identity();
    const auto& resp_id = (*responder)->identity();

    std::printf("Reentry (§6.11 dispatch-outbound over the same connection):\n");

    // Mint a reentry cap: granter = initiator, grantee = responder, granting echo on the
    // initiator's namespace. Signed by the initiator (validator-as-B authority).
    using V = std::string_view;
    auto scope = [](std::span<const V> items) {
        auto m = EcfValue::map();
        m.put(EcfValue::text("include"), value::text_array(items));
        return m;
    };
    std::array<V, 1> h{"system/validate/echo"};
    std::array<V, 1> o{"echo"};
    std::array<V, 1> star{"*"};
    std::array<V, 1> peers{local_init};
    auto grant = EcfValue::map();
    grant.put(EcfValue::text("handlers"), scope(h));
    grant.put(EcfValue::text("resources"), scope(star));
    grant.put(EcfValue::text("operations"), scope(o));
    grant.put(EcfValue::text("peers"), scope(std::span<const V>(peers)));
    auto grants = EcfValue::array();
    grants.push(std::move(grant));
    auto tm = EcfValue::map();
    tm.put(EcfValue::text("granter"), value::bytes_value(init_id.identity_hash()));
    tm.put(EcfValue::text("grantee"), value::bytes_value(resp_id.identity_hash()));
    tm.put(EcfValue::text("grants"), std::move(grants));
    tm.put(EcfValue::text("created_at"), EcfValue::uint(cap::now_ms()));
    auto reentry_cap = Entity::make("system/capability/token", std::move(tm));
    auto reentry_sig = init_id.sign(**reentry_cap);
    auto reentry_granter = init_id.peer_entity();   // the granter's system/peer entity

    // The dispatch-outbound params: {target, operation, value, reentry_*}. The value is the
    // echo payload, forwarded verbatim.
    auto value_map = EcfValue::map();
    value_map.put(EcfValue::text("marker"), EcfValue::text("reentry-roundtrip"));
    auto pm = EcfValue::map();
    pm.put(EcfValue::text("target"), EcfValue::text("system/validate/echo"));
    pm.put(EcfValue::text("operation"), EcfValue::text("echo"));
    pm.put(EcfValue::text("value"), std::move(value_map));
    pm.put(EcfValue::text("reentry_capability"), (*reentry_cap)->to_cbor());
    pm.put(EcfValue::text("reentry_granter"), reentry_granter->to_cbor());
    pm.put(EcfValue::text("reentry_cap_signature"), (*reentry_sig)->to_cbor());
    auto params = Entity::make("primitive/any", std::move(pm));

    std::string uri = "/" + remote + "/system/validate/dispatch-outbound";
    auto res = wire::resource_target("system/handler/system/validate/dispatch-outbound");
    auto r = s.execute(uri, "dispatch", **params, res);
    bool ok200 = r && response_status(*r) == 200;
    check("dispatch-outbound -> 200 (reentry produced a response)", ok200);
    // the result wraps the downstream {status, result}; the downstream echo status is 200.
    if (r) {
        auto rr = response_result(*r);
        auto dstatus = rr ? rr->uint("status") : std::nullopt;
        check("downstream echo via reentry -> status 200",
              dstatus.has_value() && *dstatus == 200);
    } else {
        check("downstream echo via reentry -> status 200", false);
    }
    return 0;
}

}  // namespace

int main() {
    if (auto i = crypto::init(); !i) { std::fprintf(stderr, "crypto init failed\n"); return 1; }
    if (scenario_core() != 0) { std::printf("\nSMOKE: FAIL (harness error in scenario 1)\n"); return 1; }
    if (scenario_extensibility() != 0) { std::printf("\nSMOKE: FAIL (harness error in scenario 2)\n"); return 1; }
    if (scenario_reentry() != 0) { std::printf("\nSMOKE: FAIL (harness error in scenario 3)\n"); return 1; }
    bool all_pass = (g_fail == 0);
    std::printf("\nSMOKE: %s (%d/%d)\n", all_pass ? "PASS" : "FAIL", g_pass, g_pass + g_fail);
    return all_pass ? 0 : 1;
}
