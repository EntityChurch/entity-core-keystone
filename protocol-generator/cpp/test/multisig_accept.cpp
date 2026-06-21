// multisig_accept.cpp — the ACCEPT-PATH unit test for genuine §3.6 K-of-N multi-sig, the
// direction the rejection-only validate-peer `multisig` category cannot cover. Builds a real
// 2-of-3 quorum root capability (the local peer is one of the signers), an authenticated
// EXECUTE authored by the grantee, runs it through cap::verify_request, and asserts:
//   - valid 2-of-3 (incl. local) → ALLOW                       (§3.6 M3 + §5.5 M4/M6)
//   - M3 deny flips: n<2 ; threshold>n ; threshold<2 ; duplicate signers ; has a parent
//   - M4 deny flip: only 1 of 2 required sigs present          (k-of-n replay defense)
//   - M6 deny flip: local NOT among the signers
//   - single-sig superset: a plain single-sig root still ALLOWs (multi-sig is a subset)
//
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <vector>

#include "entity_core/capability.hpp"
#include "entity_core/entity.hpp"
#include "entity_core/peer_identity.hpp"
#include "entity_core/store.hpp"
#include "entity_core/wire.hpp"

using namespace entity_core;

namespace {
int g_pass = 0, g_fail = 0;
void check(const char* name, bool ok) {
    if (ok) g_pass++; else g_fail++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

std::vector<std::byte> seed(std::uint8_t b) { return std::vector<std::byte>(32, std::byte{b}); }

EcfValue full_grants(const std::string& local) {
    // a single wide grant {handlers:*, resources:*, operations:*, peers:[local]}
    using V = std::string_view;
    std::array<V, 1> star{"*"};
    std::array<V, 1> peers{local};
    auto scope = [](std::span<const V> items) {
        auto m = EcfValue::map();
        m.put(EcfValue::text("include"), value::text_array(items));
        return m;
    };
    auto g = EcfValue::map();
    g.put(EcfValue::text("handlers"), scope(star));
    g.put(EcfValue::text("resources"), scope(star));
    g.put(EcfValue::text("operations"), scope(star));
    g.put(EcfValue::text("peers"), scope(std::span<const V>(peers)));
    auto arr = EcfValue::array();
    arr.push(std::move(g));
    return arr;
}

// Build a multi-granter root token {grants, granter:{signers,threshold}, grantee, created_at}.
EntityPtr make_multi_token(const std::vector<EntityPtr>& signer_peers, std::uint64_t threshold,
                           const std::string& local, std::span<const std::byte> grantee,
                           bool with_parent) {
    auto signers = EcfValue::array();
    for (const auto& sp : signer_peers) signers.push(value::bytes_value(sp->hash()));
    auto granter = EcfValue::map();
    granter.put(EcfValue::text("signers"), std::move(signers));
    granter.put(EcfValue::text("threshold"), EcfValue::uint(threshold));
    auto m = EcfValue::map();
    m.put(EcfValue::text("granter"), std::move(granter));
    m.put(EcfValue::text("grantee"), value::bytes_value(grantee));
    m.put(EcfValue::text("grants"), full_grants(local));
    m.put(EcfValue::text("created_at"), EcfValue::uint(cap::now_ms()));
    if (with_parent) {
        std::array<std::byte, kHashLen> p{};
        for (auto& b : p) b = std::byte{0x07};
        m.put(EcfValue::text("parent"), value::bytes_value(p));
    }
    return *Entity::make("system/capability/token", std::move(m));
}

// Build an authenticated EXECUTE envelope authored by `author` carrying `cap` + all the
// supporting entities (peer entities, cap signatures) needed to verify the quorum.
Envelope make_request(const PeerIdentity& author, const EntityPtr& cap, const std::string& uri,
                      const std::vector<EntityPtr>& support) {
    auto params = wire::empty_params();
    auto resource = wire::resource_target("system/handler/system/tree");
    auto exec = wire::make_execute("req-1", uri, "get", **params,
                                   std::span<const std::byte>(author.identity_hash()),
                                   std::span<const std::byte>(cap->hash()), resource);
    auto exec_sig = author.sign(**exec);
    Envelope env(*exec);
    env.add(cap);
    env.add(author.peer_entity());
    env.add(*exec_sig);
    for (const auto& s : support) env.add(s);
    return env;
}

}  // namespace

int main() {
    if (auto i = crypto::init(); !i) { std::fprintf(stderr, "crypto init failed\n"); return 1; }

    // local peer (the responder) + two co-signers + a grantee (the caller).
    auto local_id = *PeerIdentity::from_seed(seed(0x11));
    auto co1 = *PeerIdentity::from_seed(seed(0x22));
    auto co2 = *PeerIdentity::from_seed(seed(0x33));
    auto grantee = *PeerIdentity::from_seed(seed(0x44));
    const std::string local = local_id.peer_id();
    std::string uri = "/" + local + "/system/tree";

    Store store;
    std::vector<EntityPtr> signer_peers = {local_id.peer_entity(), co1.peer_entity(),
                                           co2.peer_entity()};

    auto run = [&](const EntityPtr& cap, const std::vector<EntityPtr>& extra_support) {
        // signatures over the cap by the quorum members in extra_support are added there.
        Envelope env = make_request(grantee, cap, uri, [&] {
            std::vector<EntityPtr> sup = signer_peers;
            sup.push_back(grantee.peer_entity());
            for (const auto& s : extra_support) sup.push_back(s);
            return sup;
        }());
        return cap::verify_request(local, store, env);
    };
    auto sig_over = [&](const PeerIdentity& who, const EntityPtr& cap) { return *who.sign(*cap); };

    std::printf("Multi-sig K-of-N accept-path:\n");

    // valid 2-of-3 (local + co1 sign): ALLOW
    {
        auto cap = make_multi_token(signer_peers, 2, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap), sig_over(co1, cap)});
        check("valid 2-of-3 (incl. local) -> ALLOW", v == cap::ReqVerdict::Allow);
    }
    // M4: only 1 valid sig (< threshold 2): DENY
    {
        auto cap = make_multi_token(signer_peers, 2, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap)});
        check("M4 flip: 1-of-2 sigs -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M6: local not among signers (use co1+co2+grantee as signers, sign with co1+co2): DENY
    {
        std::vector<EntityPtr> no_local = {co1.peer_entity(), co2.peer_entity(),
                                           grantee.peer_entity()};
        auto cap = make_multi_token(no_local, 2, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(co1, cap), sig_over(co2, cap)});
        check("M6 flip: local not in signers -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M3: n < 2 (single signer in a multi-granter shape): DENY
    {
        std::vector<EntityPtr> one = {local_id.peer_entity()};
        auto cap = make_multi_token(one, 2, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap)});
        check("M3 flip: n<2 -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M3: threshold > n: DENY
    {
        auto cap = make_multi_token(signer_peers, 4, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap), sig_over(co1, cap), sig_over(co2, cap)});
        check("M3 flip: threshold>n -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M3: threshold < 2 (degenerate single): DENY
    {
        auto cap = make_multi_token(signer_peers, 1, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap), sig_over(co1, cap)});
        check("M3 flip: threshold<2 -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M3: duplicate signers: DENY
    {
        std::vector<EntityPtr> dup = {local_id.peer_entity(), co1.peer_entity(),
                                      co1.peer_entity()};
        auto cap = make_multi_token(dup, 2, local, grantee.identity_hash(), false);
        auto v = run(cap, {sig_over(local_id, cap), sig_over(co1, cap)});
        check("M3 flip: duplicate signers -> AuthzDeny (403)", v == cap::ReqVerdict::AuthzDeny);
    }
    // M3: multi-sig with a parent (not root-only): DENY
    {
        auto cap = make_multi_token(signer_peers, 2, local, grantee.identity_hash(), true);
        auto v = run(cap, {sig_over(local_id, cap), sig_over(co1, cap)});
        check("M3 flip: multi-sig has parent (not root) -> AuthzDeny (403)",
              v == cap::ReqVerdict::AuthzDeny);
    }
    // single-sig superset: a plain single-sig root (granter = local identity hash) → ALLOW.
    {
        auto m = EcfValue::map();
        m.put(EcfValue::text("granter"), value::bytes_value(local_id.identity_hash()));
        m.put(EcfValue::text("grantee"), value::bytes_value(grantee.identity_hash()));
        m.put(EcfValue::text("grants"), full_grants(local));
        m.put(EcfValue::text("created_at"), EcfValue::uint(cap::now_ms()));
        auto cap = *Entity::make("system/capability/token", std::move(m));
        // the single-sig root is signed by the local granter.
        Envelope env = make_request(grantee, cap, uri, {
            local_id.peer_entity(), grantee.peer_entity(), *local_id.sign(*cap)});
        auto v = cap::verify_request(local, store, env);
        check("single-sig superset: plain single-sig root -> ALLOW", v == cap::ReqVerdict::Allow);
    }

    bool all = g_fail == 0;
    std::printf("\nMULTISIG-ACCEPT: %s (%d/%d)\n", all ? "PASS" : "FAIL", g_pass, g_pass + g_fail);
    return all ? 0 : 1;
}
