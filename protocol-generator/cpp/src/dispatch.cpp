// dispatch.cpp — the peer protocol brain (L1–L4 + foundation). Idiomatic C++ port of the
// cohort dispatch contract: bootstrap (§6.9/§6.9a), the four MUST handlers (§6.2 connect/
// tree/handler/capability) + the §9.5 type handler, the §6.5 dispatch chain, §6.6 backward
// handler resolution, §6.9a seed-policy derivation, the §7a conformance handlers (behind a
// flag), and the §6.13(b) reentry outbound seam.
//
// Idiom: handlers are member functions bound into std::function; an Outcome is a value
// (status + result + included). Errors are values — no exceptions on the dispatch path; the
// §5.2 trichotomy (401 authn / 403 authz / 401 unresolvable / 400 chain-depth) is a verdict
// mapped to a wire status. std::string path-building (no manual snprintf/malloc).
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/peer.hpp"

#include <array>
#include <random>
#include <set>

#include "entity_core/core_typedefs.hpp"
#include "entity_core/wire.hpp"

namespace entity_core {

using ecf::EcfValue;

namespace {

void ok(Outcome& o, EntityPtr result) {
    o.status = 200;
    o.result = std::move(result);
}

void err(Outcome& o, std::uint64_t status, const std::string& code,
         std::optional<std::string> msg = std::nullopt) {
    auto e = wire::error_result(code, std::move(msg));
    if (e) {
        o.status = status;
        o.result = *e;
    } else {
        o.status = 500;
        o.result = nullptr;
    }
}

bool is_zero_hash(std::span<const std::byte> h) {
    for (auto b : h) {
        if (b != std::byte{0}) return false;
    }
    return !h.empty();
}

// scope map {include:[...]}.
EcfValue scope_cbor(std::span<const std::string_view> incl) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("include"), value::text_array(incl));
    return m;
}

// a grant map {handlers,resources,operations[,peers]}.
EcfValue grant_cbor(std::span<const std::string_view> h, std::span<const std::string_view> r,
                    std::span<const std::string_view> o,
                    std::optional<std::span<const std::string_view>> pe) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("handlers"), scope_cbor(h));
    m.put(EcfValue::text("resources"), scope_cbor(r));
    m.put(EcfValue::text("operations"), scope_cbor(o));
    if (pe) m.put(EcfValue::text("peers"), scope_cbor(*pe));
    return m;
}

// the §4.4 discovery floor (two grants).
EcfValue discovery_floor() {
    using V = std::string_view;
    std::array<V, 1> h1{"system/tree"};
    std::array<V, 2> r1{"system/type/*", "system/handler/*"};
    std::array<V, 1> o1{"get"};
    std::array<V, 1> h2{"system/capability"};
    std::array<V, 1> o2{"request"};
    auto arr = EcfValue::array();
    arr.push(grant_cbor(h1, r1, o1, std::nullopt));
    arr.push(grant_cbor(h2, {}, o2, std::nullopt));
    return arr;
}

// wide-open admin scope (= --debug-open-grants).
EcfValue open_grants_scope() {
    using V = std::string_view;
    std::array<V, 1> star{"*"};
    std::array<V, 2> res{"*", "/*/*"};
    auto arr = EcfValue::array();
    arr.push(grant_cbor(star, res, star, std::span<const V>(star)));
    return arr;
}

// full owner authority over the local namespace (§6.9a).
EcfValue owner_grants(const std::string& local) {
    using V = std::string_view;
    std::array<V, 1> star{"*"};
    std::array<V, 1> peers{local};
    auto arr = EcfValue::array();
    arr.push(grant_cbor(star, star, star, std::span<const V>(peers)));
    return arr;
}

// §4.5 negotiation: does the advertised text-array `key` overlap with `want`? Absent/empty =
// no constraint (accept). Non-empty + no overlap = disjoint → reject.
bool advertised_excludes(const Entity* params, std::string_view key, std::string_view want) {
    if (!params) return false;
    const auto* arr = params->field(key);
    if (!arr || !arr->is<ecf::Array>()) return false;
    const auto& a = std::get<ecf::Array>(arr->as_variant());
    if (a.empty()) return false;
    for (const auto& box : a) {
        const auto* t = std::get_if<ecf::Text>(&box->as_variant());
        if (t) {
            std::string s(reinterpret_cast<const char*>(t->data()), t->size());
            if (s == want) return false;  // overlap
        }
    }
    return true;
}

// the single resource target string off an EXECUTE (and its raw byte length).
std::optional<std::string> exec_resource_target(const Entity& exec, std::size_t* raw_len) {
    if (raw_len) *raw_len = 0;
    const auto* r = exec.map_field("resource");
    if (!r) return std::nullopt;
    const auto* targets = value::get(*r, "targets");
    if (targets && targets->is<ecf::Array>()) {
        const auto& a = std::get<ecf::Array>(targets->as_variant());
        if (!a.empty()) {
            const auto* t = std::get_if<ecf::Text>(&a[0]->as_variant());
            if (t) {
                if (raw_len) *raw_len = t->size();
                return std::string(reinterpret_cast<const char*>(t->data()), t->size());
            }
        }
    }
    return std::nullopt;
}

// §1.4 R1 path flex check (control-byte / embedded NUL / empty segment / . / .. rejection).
bool path_flex_ok(const std::string& target, std::size_t raw_len) {
    (void)raw_len;  // the wire target is length-prefixed text; embedded NUL survives into
                    // std::string, so scan the bytes directly rather than comparing lengths.
    // §1.4 R1: control bytes (incl. NUL) are not valid in any path segment.
    for (unsigned char ch : target)
        if (ch < 0x20 || ch == 0x7f) return false;
    if (target.find("//") != std::string::npos) return false;    // empty segment
    if (target == "/") return false;
    std::string body = target;
    if (!body.empty() && body.front() == '/') {
        auto second = body.find('/', 1);
        std::string seg1 = (second == std::string::npos) ? body.substr(1)
                                                          : body.substr(1, second - 1);
        if (!cap::is_peer_id(seg1)) return false;
        body = (second == std::string::npos) ? std::string() : body.substr(second + 1);
    }
    if (!body.empty() && body.back() == '/') body.pop_back();  // strip one trailing slash
    std::size_t start = 0;
    while (start <= body.size()) {
        auto slash = body.find('/', start);
        std::string seg = (slash == std::string::npos) ? body.substr(start)
                                                        : body.substr(start, slash - start);
        if (slash == std::string::npos) {
            if (seg.empty() && start < body.size()) return false;
            if (seg == "." || seg == "..") return false;
            break;
        }
        if (seg.empty() || seg == "." || seg == "..") return false;
        start = slash + 1;
    }
    return true;
}

// operations map: op-name → empty spec (the §6 operations-match gate needs only the keys).
EcfValue operations_map(std::span<const std::string_view> ops) {
    auto m = EcfValue::map();
    for (auto o : ops) m.put(EcfValue::text(o), EcfValue::map());
    return m;
}

EcfValue clone_grants_array(const EcfValue* requested) {
    auto grants = EcfValue::array();
    if (requested && requested->is<ecf::Array>()) {
        for (const auto& box : std::get<ecf::Array>(requested->as_variant())) {
            grants.push(*box);  // value copy
        }
    }
    return grants;
}

}  // namespace

// ── helpers ──────────────────────────────────────────────────────────────────────
std::string Peer::abs_path(std::string_view rel) const {
    return "/" + local_ + "/" + std::string(rel);
}

Result<std::pair<EntityPtr, EntityPtr>> Peer::mint_token(
    std::span<const std::byte> grantee, EcfValue grants,
    std::optional<std::span<const std::byte>> parent) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("granter"), value::bytes_value(identity_.identity_hash()));
    m.put(EcfValue::text("grantee"), EcfValue::bytes(grantee));
    m.put(EcfValue::text("grants"), std::move(grants));
    m.put(EcfValue::text("created_at"), EcfValue::uint(cap::now_ms()));
    if (parent) m.put(EcfValue::text("parent"), EcfValue::bytes(*parent));
    auto tok = Entity::make("system/capability/token", std::move(m));
    if (!tok) return std::unexpected(tok.error());
    auto sig = identity_.sign(**tok);
    if (!sig) return std::unexpected(sig.error());
    return std::make_pair(*tok, *sig);
}

void Peer::attach_cap(Outcome& o, const EntityPtr& token, const EntityPtr& sig) {
    o.included.push_back(token);
    o.included.push_back(identity_.peer_entity());
    o.included.push_back(sig);
}

// §6.9a seed-policy: append the grants from a policy entry (a verified cap token, or a
// policy-entry) into out_arr.
namespace {
void append_entry_grants(Peer& peer, const Entity& entry, EcfValue& out_arr) {
    const EcfValue* grants = nullptr;
    if (entry.type() == "system/capability/token") {
        std::string path = "/" + peer.local() + "/system/signature/" + entry.hash_hex();
        auto sgn = peer.store().get_at(path);
        if (sgn && verify_signature(*sgn, *peer.identity().peer_entity())) {
            grants = entry.field("grants");
        }
    } else if (entry.type() == "system/capability/policy-entry") {
        grants = entry.field("grants");
    }
    if (grants && grants->is<ecf::Array>()) {
        for (const auto& box : std::get<ecf::Array>(grants->as_variant())) {
            out_arr.push(*box);
        }
    }
}
}  // namespace

EcfValue Peer::derive_seed_grants(const Entity& remote_peer, const std::string& remote_peer_id) {
    auto floor = discovery_floor();
    EntityPtr entry;
    std::string hexpath = "/" + local_ + "/system/capability/policy/" + remote_peer.hash_hex();
    entry = store_.get_at(hexpath);
    if (!entry && !remote_peer_id.empty()) {
        entry = store_.get_at("/" + local_ + "/system/capability/policy/" + remote_peer_id);
    }
    if (!entry) {
        entry = store_.get_at(abs_path("system/capability/policy/default"));
    }
    if (entry) append_entry_grants(*this, *entry, floor);
    return floor;
}

void Peer::ingest_signatures(const Envelope& env) {
    for (const auto& e : env.included()) {
        if (e->type() != "system/signature") continue;
        store_.put(e);
        auto signer_h = e->bytes("signer");
        if (!signer_h || signer_h->size() != kHashLen) continue;
        auto signer_peer = env.find(*signer_h);
        if (!signer_peer) continue;
        store_.put(signer_peer);
        auto target = e->bytes("target");
        auto pk = signer_peer->bytes("public_key");
        if (target && target->size() == kHashLen && pk && pk->size() == 32) {
            if (auto pid = peer_id_of_pubkey(*pk)) {
                std::string path = "/" + *pid + "/system/signature/" +
                                   identity::hex_lower(*target);
                store_.bind(path, e);
            }
        }
    }
}

std::optional<std::string> Peer::resolve_handler_path(const std::string& path) const {
    std::string work = path;
    for (;;) {
        auto e = store_.get_at(work);
        if (e && e->type() == "system/handler") return work;
        auto slash = work.rfind('/');
        if (slash == std::string::npos || slash == 0) break;
        work.resize(slash);
    }
    return std::nullopt;
}

// ── connect handler (§4.1/§4.6) ───────────────────────────────────────────────────
void Peer::h_connect(Connection& conn, const Envelope& env, const Entity& exec,
                     const Entity* /*caller_cap*/, const std::string& op, Outcome& o) {
    if (op == "hello") {
        if (conn.established) { err(o, 409, "connection_already_established"); return; }
        auto params = exec.entity_field("params");
        const Entity* p = params.get();
        std::optional<std::string> initiator = p ? p->text("peer_id") : std::nullopt;
        if (advertised_excludes(p, "hash_formats", "ecfv1-sha256")) {
            err(o, 400, "incompatible_hash_format"); return;
        }
        if (advertised_excludes(p, "key_types", "ed25519")) {
            err(o, 400, "unsupported_key_type"); return;
        }
        // fresh CSPRNG nonce bound to THIS connection (F12: per-connection unique nonce
        // defeats the §4.6 cross-connection authenticate replay).
        std::array<std::byte, 32> nonce{};
        std::random_device rd;
        for (auto& b : nonce) b = std::byte(static_cast<std::uint8_t>(rd()));
        conn.issued_nonce = nonce;
        conn.have_nonce = true;
        conn.hello_peer_id = initiator;

        using V = std::string_view;
        std::array<V, 1> protos{"entity-core/1.0"};
        std::array<V, 1> hf{"ecfv1-sha256"};
        std::array<V, 1> kt{"ed25519"};
        auto m = EcfValue::map();
        m.put(EcfValue::text("peer_id"), EcfValue::text(local_));
        m.put(EcfValue::text("nonce"), EcfValue::bytes(nonce));
        m.put(EcfValue::text("protocols"), value::text_array(protos));
        m.put(EcfValue::text("timestamp"), EcfValue::uint(cap::now_ms()));
        m.put(EcfValue::text("hash_formats"), value::text_array(hf));
        m.put(EcfValue::text("key_types"), value::text_array(kt));
        auto result = Entity::make("system/protocol/connect/hello", std::move(m));
        if (result) ok(o, *result); else err(o, 500, "internal_error");
        return;
    }
    if (op == "authenticate") {
        if (conn.established) { err(o, 409, "connection_already_established"); return; }
        if (!conn.have_nonce) { err(o, 401, "invalid_nonce"); return; }
        auto auth = exec.entity_field("params");
        if (!auth) { err(o, 401, "authentication_failed"); return; }

        if (auto ktf = auth->text("key_type"); ktf && *ktf != "ed25519") {
            err(o, 400, "unsupported_key_type"); return;
        }
        auto pub = auth->bytes("public_key");
        if (pub && pub->size() != 32) { err(o, 400, "unsupported_key_type"); return; }
        if (auto claimed = auth->text("peer_id")) {
            if (auto parts = identity::peer_id_parse(*claimed)) {
                if (parts->key_type != identity::kKeyTypeEd25519) {
                    err(o, 400, "unsupported_key_type"); return;
                }
            }
        }
        auto echoed = auth->bytes("nonce");
        if (!(echoed && echoed->size() == 32 &&
              std::equal(echoed->begin(), echoed->end(), conn.issued_nonce.begin()))) {
            err(o, 401, "invalid_nonce"); return;
        }
        if (!pub) { err(o, 401, "authentication_failed"); return; }
        // step 2: proof of possession — find sig over auth, verify against pub.
        bool sig_ok = false;
        for (const auto& sg : env.included()) {
            if (sg->type() != "system/signature") continue;
            auto tg = sg->bytes("target");
            if (tg && tg->size() == kHashLen &&
                std::equal(tg->begin(), tg->end(), auth->hash().begin())) {
                auto sb = sg->bytes("signature");
                if (sb && sb->size() == crypto::kEd25519SigLen &&
                    crypto::ed25519_verify(*pub, *sb, auth->hash()).has_value()) {
                    sig_ok = true;
                }
                break;
            }
        }
        if (!sig_ok) { err(o, 401, "authentication_failed"); return; }
        // step 3: identity binding.
        auto claimed = auth->text("peer_id");
        auto derived = peer_id_of_pubkey(*pub);
        bool bound = derived && claimed && *derived == *claimed;
        if (bound && conn.hello_peer_id && *conn.hello_peer_id != *claimed) bound = false;
        if (!bound) { err(o, 401, "identity_mismatch"); return; }

        auto remote_peer = peer_entity_of_pubkey(*pub);
        if (!remote_peer) { err(o, 500, "internal_error"); return; }
        auto grants = derive_seed_grants(**remote_peer, claimed.value_or(""));
        auto minted = mint_token((*remote_peer)->hash(), std::move(grants), std::nullopt);
        if (!minted) { err(o, 500, "internal_error"); return; }
        auto [token, sig] = *minted;
        conn.established = true;

        auto gm = EcfValue::map();
        gm.put(EcfValue::text("token"), value::bytes_value(token->hash()));
        auto grant_ent = Entity::make("system/capability/grant", std::move(gm));
        if (grant_ent) {
            ok(o, *grant_ent);
            attach_cap(o, token, sig);
        } else {
            err(o, 500, "internal_error");
        }
        return;
    }
    err(o, 501, "unsupported_operation", op);
}

// ── tree handler (§6.3) ────────────────────────────────────────────────────────────
void Peer::build_listing(const std::string& path, Outcome& o) {
    auto rows = store_.listing(path);
    auto entries = EcfValue::map();
    std::size_t count = 0;
    auto is_deletion_marker = [&](const Hash& h) {
        auto e = store_.get_by_hash(h);
        return e && e->type() == "system/deletion-marker";
    };
    for (const auto& row : rows) {
        if (row.hash && !row.has_children && is_deletion_marker(*row.hash)) continue;
        auto data = EcfValue::map();
        data.put(EcfValue::text("has_children"), EcfValue::boolean(row.has_children));
        if (row.hash) data.put(EcfValue::text("hash"), value::bytes_value(*row.hash));
        auto le = Entity::make("system/tree/listing-entry", std::move(data));
        if (le) {
            entries.put(EcfValue::text(row.segment), (*le)->to_cbor());
            count++;
        }
    }
    auto m = EcfValue::map();
    m.put(EcfValue::text("path"), EcfValue::text(path));
    m.put(EcfValue::text("entries"), std::move(entries));
    m.put(EcfValue::text("count"), EcfValue::uint(count));
    m.put(EcfValue::text("offset"), EcfValue::uint(0));
    auto r = Entity::make("system/tree/listing", std::move(m));
    if (r) ok(o, *r); else err(o, 500, "internal_error");
}

void Peer::h_tree(const Envelope& /*env*/, const Entity& exec, const std::string& op,
                  Outcome& o) {
    if (op == "get") {
        std::size_t raw = 0;
        auto target = exec_resource_target(exec, &raw);
        if (target && !path_flex_ok(*target, raw)) { err(o, 400, "invalid_path", *target); return; }
        if (!target) { build_listing(abs_path(""), o); return; }
        if (target->empty() || target->back() == '/') {
            auto path = cap::canonicalize(local_, *target);
            if (!path) { err(o, 400, "invalid_path", *target); return; }
            build_listing(*path, o);
            return;
        }
        auto path = cap::canonicalize(local_, *target);
        if (!path) { err(o, 400, "invalid_path", *target); return; }
        auto e = store_.get_at(*path);
        if (!e) { err(o, 404, "not_found", *target); return; }
        auto params = exec.entity_field("params");
        auto mode = params ? params->text("mode") : std::nullopt;
        if (mode && *mode == "hash") {
            auto m = EcfValue::map();
            m.put(EcfValue::text("hash"), value::bytes_value(e->hash()));
            auto r = Entity::make("system/hash", std::move(m));
            if (r) ok(o, *r); else err(o, 500, "internal_error");
        } else {
            ok(o, e);
        }
        return;
    }
    if (op == "put") {
        std::size_t raw = 0;
        auto target = exec_resource_target(exec, &raw);
        if (!target) { err(o, 400, "ambiguous_resource", "tree: missing resource target"); return; }
        if (!path_flex_ok(*target, raw)) { err(o, 400, "invalid_path", *target); return; }
        auto path = cap::canonicalize(local_, *target);
        if (!path) { err(o, 400, "invalid_path", *target); return; }
        auto params = exec.entity_field("params");
        auto entity = params ? params->entity_field("entity") : nullptr;
        auto expected = params ? params->bytes("expected_hash") : std::nullopt;
        auto current = store_.hash_hex_at(*path);
        bool cas_ok;
        if (!expected) {
            cas_ok = true;
        } else if (expected->size() == kHashLen && is_zero_hash(*expected)) {
            cas_ok = !current.has_value();
        } else {
            cas_ok = current && *current == identity::hex_lower(*expected);
        }
        if (!cas_ok) { err(o, 409, "hash_mismatch", *target); return; }
        if (!entity) { err(o, 400, "unexpected_params", "put: missing entity"); return; }
        store_.bind(*path, entity);
        auto m = EcfValue::map();
        m.put(EcfValue::text("hash"), value::bytes_value(entity->hash()));
        auto r = Entity::make("system/hash", std::move(m));
        if (r) ok(o, *r); else err(o, 500, "internal_error");
        return;
    }
    err(o, 501, "unsupported_operation", op);
}

// ── capability handler (§6.2) ───────────────────────────────────────────────────────
void Peer::mint_bounded(const Entity* caller_cap, const EcfValue* requested,
                        std::span<const std::byte> grantee,
                        std::optional<std::span<const std::byte>> parent, Outcome& o) {
    bool bounded = false;
    if (caller_cap) {
        const auto* pg = caller_cap->field("grants");
        const EcfValue* parent_grants = (pg && pg->is<ecf::Array>()) ? pg : nullptr;
        bounded = true;
        if (requested && requested->is<ecf::Array>()) {
            for (const auto& rbox : std::get<ecf::Array>(requested->as_variant())) {
                bool some = false;
                if (parent_grants) {
                    for (const auto& pbox : std::get<ecf::Array>(parent_grants->as_variant())) {
                        if (cap::grant_subset(local_, local_, local_, *rbox, *pbox)) {
                            some = true;
                            break;
                        }
                    }
                }
                if (!some) { bounded = false; break; }
            }
        }
    }
    if (!bounded) { err(o, 403, "scope_exceeds_authority"); return; }
    auto grants = clone_grants_array(requested);
    auto minted = mint_token(grantee, std::move(grants), parent);
    if (!minted) { err(o, 500, "internal_error"); return; }
    auto [token, sig] = *minted;
    auto gm = EcfValue::map();
    gm.put(EcfValue::text("token"), value::bytes_value(token->hash()));
    auto grant_ent = Entity::make("system/capability/grant", std::move(gm));
    if (grant_ent) {
        ok(o, *grant_ent);
        attach_cap(o, token, sig);
    } else {
        err(o, 500, "internal_error");
    }
}

void Peer::h_capability(const Entity& exec, const Entity* caller_cap, const std::string& op,
                        Outcome& o) {
    auto params = exec.entity_field("params");
    if (op == "request") {
        auto author = exec.bytes("author");
        if (!author || author->size() != kHashLen) { err(o, 403, "capability_denied"); return; }
        const EcfValue* req = params ? params->field("grants") : nullptr;
        if (req && !req->is<ecf::Array>()) req = nullptr;
        mint_bounded(caller_cap, req, *author, std::nullopt, o);
        return;
    }
    if (op == "delegate") {
        auto author = exec.bytes("author");
        // §2.6 F1: delegate is SAME-PEER-ONLY in v1 — a remote caller → 501 (before params).
        if (!(author && author->size() == kHashLen &&
              std::equal(author->begin(), author->end(), identity_.identity_hash().begin()))) {
            err(o, 501, "unsupported_operation", "delegate: same-peer-only in v1"); return;
        }
        auto ph = params ? params->bytes("parent") : std::nullopt;
        if (!ph || ph->size() != kHashLen) {
            err(o, 400, "unexpected_params", "delegate: parent required"); return;
        }
        if (is_zero_hash(*ph)) { err(o, 400, "unexpected_params", "delegate: zero parent"); return; }
        const EcfValue* req = params ? params->field("grants") : nullptr;
        if (req && !req->is<ecf::Array>()) req = nullptr;
        mint_bounded(caller_cap, req, *author, std::span<const std::byte>(*ph), o);
        return;
    }
    if (op == "revoke") {
        auto tok = params ? params->bytes("token") : std::nullopt;
        if (!tok || tok->size() != kHashLen) {
            err(o, 400, "unexpected_params", "revoke: missing token"); return;
        }
        if (is_zero_hash(*tok)) { err(o, 400, "unexpected_params", "revoke: zero token"); return; }
        auto m = EcfValue::map();
        m.put(EcfValue::text("token"), EcfValue::bytes(*tok));
        m.put(EcfValue::text("revoked_at"), EcfValue::uint(cap::now_ms()));
        auto marker = Entity::make("system/capability/revocation", std::move(m));
        if (marker) {
            std::string path = "/" + local_ + "/system/capability/revocations/" +
                               identity::hex_lower(*tok);
            store_.bind(path, *marker);
            auto ep = wire::empty_params();
            if (ep) ok(o, *ep); else err(o, 500, "internal_error");
        } else {
            err(o, 500, "internal_error");
        }
        return;
    }
    if (op == "configure") {
        auto pp = params ? params->text("peer_pattern") : std::nullopt;
        if (!pp) { err(o, 400, "unexpected_params", "configure: missing peer_pattern"); return; }
        bool is_hex = pp->size() == 66;
        if (is_hex) {
            for (char c : *pp) {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { is_hex = false; break; }
            }
        }
        if (!(*pp == "default" || is_hex || cap::is_peer_id(*pp))) {
            err(o, 400, "invalid_peer_pattern", *pp); return;
        }
        if (params) {
            store_.bind("/" + local_ + "/system/capability/policy/" + *pp, params);
        }
        auto ep = wire::empty_params();
        if (ep) ok(o, *ep); else err(o, 500, "internal_error");
        return;
    }
    err(o, 501, "unsupported_operation", op);
}

// ── handlers handler (§6.2 / §6.13(a) register/unregister) ──────────────────────────
namespace {
std::optional<std::string> register_pattern(const Entity& exec) {
    std::size_t raw = 0;
    auto target = exec_resource_target(exec, &raw);
    if (!target) return std::nullopt;
    const std::string prefix = "system/handler/";
    if (!cap::starts_with(prefix, *target) || target->size() == prefix.size()) return std::nullopt;
    return target->substr(prefix.size());
}
}  // namespace

void Peer::h_handlers(const Entity& exec, const std::string& op, Outcome& o) {
    bool is_register = op == "register";
    bool is_unregister = op == "unregister";
    if (!is_register && !is_unregister) { err(o, 501, "unsupported_operation", op); return; }
    auto pattern = register_pattern(exec);
    if (!pattern) {
        std::size_t raw = 0;
        if (!exec_resource_target(exec, &raw)) {
            err(o, 400, "ambiguous_resource",
                "register/unregister require exactly one resource target");
        } else {
            err(o, 400, "invalid_resource",
                "resource target MUST be system/handler/{pattern}");
        }
        return;
    }

    if (is_unregister) {
        std::string grants_path = "/" + local_ + "/system/capability/grants/" + *pattern;
        if (auto g = store_.get_at(grants_path)) {
            store_.unbind("/" + local_ + "/system/signature/" + g->hash_hex());
            store_.unbind(grants_path);
        }
        store_.unbind(abs_path(*pattern));
        store_.unbind("/" + local_ + "/system/handler/" + *pattern);
        auto ep = wire::empty_params();
        if (ep) ok(o, *ep); else err(o, 500, "internal_error");
        return;
    }

    // register
    auto req = exec.entity_field("params");
    if (!req) { err(o, 400, "unexpected_params", "register: missing params"); return; }
    if (req->type() != "system/handler/register-request") {
        err(o, 400, "unexpected_params", "register expects register-request"); return;
    }
    const auto* manifest = req->map_field("manifest");
    std::string name = (manifest ? value::text(*manifest, "name") : std::nullopt).value_or(*pattern);
    const EcfValue* operations = manifest ? value::get(*manifest, "operations") : nullptr;
    if (operations && !operations->is<ecf::Map>()) operations = nullptr;

    // (1) handler manifest at the pattern path
    {
        auto hm = EcfValue::map();
        hm.put(EcfValue::text("interface"), EcfValue::text("system/handler/" + *pattern));
        if (auto he = Entity::make("system/handler", std::move(hm))) {
            store_.bind(abs_path(*pattern), *he);
        }
    }
    // (3)+(4) self-issued signed grant + grant signature at §3.5
    {
        const EcfValue* scope = req->field("requested_scope");
        EcfValue grants = (scope && scope->is<ecf::Array>())
                              ? clone_grants_array(scope) : EcfValue::array();
        if (auto minted = mint_token(identity_.identity_hash(), std::move(grants), std::nullopt)) {
            auto [token, sig] = *minted;
            store_.bind("/" + local_ + "/system/capability/grants/" + *pattern, token);
            store_.bind("/" + local_ + "/system/signature/" + token->hash_hex(), sig);
        }
    }
    // (5) handler interface entity (discovery index)
    {
        auto im = EcfValue::map();
        im.put(EcfValue::text("pattern"), EcfValue::text(*pattern));
        im.put(EcfValue::text("name"), EcfValue::text(name));
        im.put(EcfValue::text("operations"), operations ? *operations : EcfValue::map());
        if (auto ie = Entity::make("system/handler/interface", std::move(im))) {
            store_.bind("/" + local_ + "/system/handler/" + *pattern, *ie);
        }
    }
    // result
    auto m = EcfValue::map();
    m.put(EcfValue::text("pattern"), EcfValue::text(*pattern));
    auto r = Entity::make("system/handler/register-result", std::move(m));
    if (r) ok(o, *r); else err(o, 500, "internal_error");
}

// ── §9.5 type registry handler ──────────────────────────────────────────────────────
void Peer::h_type(const Entity& exec, const std::string& op, Outcome& o) {
    if (op != "validate") { err(o, 501, "unsupported_operation", op); return; }
    auto req = exec.entity_field("params");
    if (!req) { err(o, 400, "invalid_params", "validate requires a params entity"); return; }
    auto subject = req->entity_field("entity");
    if (!subject) { err(o, 400, "unexpected_params", "validate-request missing entity"); return; }
    std::string type_name = req->text("type_path").value_or(subject->type());

    auto typedef_e = store_.get_at("/" + local_ + "/system/type/" + type_name);
    auto make_result = [&](EcfValue m) {
        auto r = Entity::make("system/type/validate-result", std::move(m));
        if (r) ok(o, *r); else err(o, 500, "internal_error");
    };
    if (!typedef_e) {
        auto v = EcfValue::map();
        v.put(EcfValue::text("kind"), EcfValue::text("unknown_type"));
        v.put(EcfValue::text("field"), EcfValue::text(type_name));
        v.put(EcfValue::text("message"), EcfValue::text("no registered type definition"));
        auto vs = EcfValue::array();
        vs.push(std::move(v));
        auto m = EcfValue::map();
        m.put(EcfValue::text("valid"), EcfValue::boolean(false));
        m.put(EcfValue::text("violations"), std::move(vs));
        make_result(std::move(m));
        return;
    }
    const auto* fields = typedef_e->map_field("fields");
    const EcfValue* subj_data = subject->data().is<ecf::Map>() ? &subject->data() : nullptr;

    auto violations = EcfValue::array();
    auto unevaluated = EcfValue::array();
    std::size_t nviol = 0;
    if (fields && fields->is<ecf::Map>()) {
        for (const auto& kv : std::get<ecf::Map>(fields->as_variant())) {
            const auto* fk = std::get_if<ecf::Text>(&kv.key->as_variant());
            if (!fk) continue;
            std::string fname(reinterpret_cast<const char*>(fk->data()), fk->size());
            bool optional = false;
            if (kv.value->is<ecf::Map>()) {
                optional = value::is_true(value::get(*kv.value, "optional"));
            }
            bool present = subj_data && value::get(*subj_data, fname) != nullptr;
            if (!optional && !present) {
                auto viol = EcfValue::map();
                viol.put(EcfValue::text("kind"), EcfValue::text("missing_required_field"));
                viol.put(EcfValue::text("field"), EcfValue::text(fname));
                viol.put(EcfValue::text("message"), EcfValue::text("required field absent"));
                violations.push(std::move(viol));
                nviol++;
            }
        }
    }
    std::size_t nunev = 0;
    if (subj_data) {
        for (const auto& kv : std::get<ecf::Map>(subj_data->as_variant())) {
            const auto* sk = std::get_if<ecf::Text>(&kv.key->as_variant());
            if (!sk) continue;
            std::string sname(reinterpret_cast<const char*>(sk->data()), sk->size());
            bool declared = fields && fields->is<ecf::Map>() && value::get(*fields, sname);
            if (!declared) { unevaluated.push(EcfValue::text(sname)); nunev++; }
        }
    }
    auto m = EcfValue::map();
    m.put(EcfValue::text("valid"), EcfValue::boolean(nviol == 0));
    if (nviol > 0) m.put(EcfValue::text("violations"), std::move(violations));
    if (nunev > 0) m.put(EcfValue::text("unevaluated_fields"), std::move(unevaluated));
    make_result(std::move(m));
}

// ── §7a conformance handlers ────────────────────────────────────────────────────────
void Peer::h_validate_echo(const Entity& exec, const std::string& op, Outcome& o) {
    if (op != "echo") { err(o, 501, "unsupported_operation", op); return; }
    auto params = exec.entity_field("params");
    if (params) ok(o, params); else err(o, 400, "invalid_params", "echo requires a params entity");
}

// §6.13(b)/§6.11 dispatch-outbound: originate an EXECUTE back to the caller over the inbound
// connection (the reentry seam) and await the response. The reentry cap/granter/cap-sig
// travel in `included` exactly as a session EXECUTE carries its §5.8 authority chain.
void Peer::h_validate_dispatch_outbound(Connection& conn, const Entity& exec,
                                        const std::string& op, Outcome& o) {
    if (op != "dispatch") { err(o, 501, "unsupported_operation", op); return; }
    auto params = exec.entity_field("params");
    if (!params) { err(o, 400, "invalid_params", "dispatch-outbound requires a params entity"); return; }
    auto target = params->text("target").value_or("");
    auto operation = params->text("operation").value_or("");
    const EcfValue* value_v = params->field("value");
    auto capability = params->entity_field("reentry_capability");
    auto granter = params->entity_field("reentry_granter");
    auto cap_sig = params->entity_field("reentry_cap_signature");
    if (!value_v || !capability || !granter || !cap_sig) {
        err(o, 400, "invalid_params",
            "dispatch-outbound requires value + reentry authority");
        return;
    }
    if (!conn.seam) {
        err(o, 503, "no_outbound_seam", "no live §6.11 reentry connection"); return;
    }
    // generic relay: forward `value` verbatim as the downstream EXECUTE's params data.
    auto inner = Entity::make("primitive/any", *value_v);
    if (!inner) { err(o, 500, "internal_error"); return; }

    EcfValue resource = wire::resource_target("system/handler/" + target);
    int n = ++conn.out_counter;
    std::string rid = "out-" + std::to_string(n);
    auto exec_out = wire::make_execute(rid, target, operation, **inner,
                                       identity_.identity_hash(),
                                       std::span<const std::byte>(capability->hash()),
                                       std::move(resource));
    if (!exec_out) { err(o, 500, "internal_error"); return; }
    auto exec_sig = identity_.sign(**exec_out);
    if (!exec_sig) { err(o, 500, "internal_error"); return; }
    Envelope req(*exec_out);
    req.add(capability);
    req.add(granter);
    req.add(identity_.peer_entity());
    req.add(cap_sig);
    req.add(*exec_sig);

    auto resp = conn.seam->outbound(req);
    if (!resp) { err(o, 503, "no_outbound_seam", "reentry dispatch produced no response"); return; }

    std::uint64_t dstatus = resp->root()->uint("status").value_or(0);
    const EcfValue* dresult = resp->root()->field("result");
    auto m = EcfValue::map();
    m.put(EcfValue::text("status"), EcfValue::uint(dstatus));
    m.put(EcfValue::text("result"), dresult ? *dresult : EcfValue::map());
    auto r = Entity::make("primitive/any", std::move(m));
    if (r) ok(o, *r); else err(o, 500, "internal_error");
}

// ── §6.5 dispatch chain ─────────────────────────────────────────────────────────────
std::optional<Envelope> Peer::dispatch(Connection& conn, const Envelope& env) {
    const Entity& exec = *env.root();
    if (exec.type() != "system/protocol/execute") return std::nullopt;  // §3.3 ignore non-EXECUTE

    std::string request_id = exec.text("request_id").value_or("");
    std::string uri = exec.text("uri").value_or("");
    std::string operation = exec.text("operation").value_or("");

    Outcome o;

    auto respond = [&]() -> std::optional<Envelope> {
        EntityPtr result = o.result;
        if (!result) {
            auto ep = wire::empty_params();
            if (!ep) return std::nullopt;
            result = *ep;
        }
        auto resp = wire::make_response(request_id, o.status, *result);
        if (!resp) return std::nullopt;
        Envelope renv(*resp);
        for (const auto& inc : o.included) renv.add(inc);
        return renv;
    };

    // connect path: unauthenticated
    if (uri == "system/protocol/connect") {
        if (const auto* fn = lookup_handler("system/protocol/connect")) {
            (*fn)(*this, conn, env, exec, nullptr, operation, o);
        } else {
            err(o, 500, "internal_error");
        }
        return respond();
    }

    // §6.5 signature ingestion + §5.2 verify
    ingest_signatures(env);
    switch (cap::verify_request(local_, store_, env)) {
        case cap::ReqVerdict::AuthnFail:    err(o, 401, "authentication_failed"); return respond();
        case cap::ReqVerdict::AuthzDeny:    err(o, 403, "capability_denied"); return respond();
        case cap::ReqVerdict::ChainTooDeep: err(o, 400, "chain_depth_exceeded"); return respond();
        case cap::ReqVerdict::Unresolvable: err(o, 401, "unresolvable_grantee"); return respond();
        case cap::ReqVerdict::Allow: break;
    }

    // §1.4 path resolution + local-peer gate
    std::string norm = cap::normalize_uri(uri);
    auto path = cap::canonicalize(local_, norm);
    if (!path) { err(o, 400, "invalid_path", uri); return respond(); }
    if (cap::extract_peer(local_, *path) != local_) {
        err(o, 404, "handler_not_found", "not local peer"); return respond();
    }
    auto pattern = resolve_handler_path(*path);
    if (!pattern) { err(o, 404, "handler_not_found", uri); return respond(); }

    // resolve the caller cap from the envelope
    auto cap_h = exec.bytes("capability");
    EntityPtr caller_cap = (cap_h && cap_h->size() == kHashLen) ? env.find(*cap_h) : nullptr;
    if (!caller_cap) { err(o, 403, "capability_denied"); return respond(); }

    // §PR-8 granter frame
    std::string gframe = cap::resolve_granter_peer(env, store_, *caller_cap).value_or(local_);

    if (cap::check_permission(local_, gframe, exec, *caller_cap, *pattern) == cap::Verdict::Deny) {
        err(o, 403, "capability_denied"); return respond();
    }

    // strip the /{local}/ prefix → the registration key
    std::string stripped = *pattern;
    std::string lprefix = "/" + local_ + "/";
    if (cap::starts_with(lprefix, stripped)) stripped = stripped.substr(lprefix.size());

    if (const auto* fn = lookup_handler(stripped)) {
        (*fn)(*this, conn, env, exec, caller_cap.get(), operation, o);
    } else {
        err(o, 501, "no_handler_body", *pattern);
    }
    return respond();
}

// ── bootstrap (§6.9 / §6.9a) + create ───────────────────────────────────────────────
void Peer::register_handler(const std::string& pattern, Handler fn) {
    handlers_.emplace_back(pattern, std::move(fn));
}

const Peer::Handler* Peer::lookup_handler(const std::string& pattern) const {
    for (const auto& [p, fn] : handlers_) {
        if (p == pattern) return &fn;
    }
    return nullptr;
}

Result<void> Peer::bootstrap_handler_entities(const std::string& pattern, const std::string& name,
                                              std::span<const std::string_view> ops) {
    // manifest at /{local}/{pattern}
    {
        auto hm = EcfValue::map();
        hm.put(EcfValue::text("interface"), EcfValue::text("system/handler/" + pattern));
        auto he = Entity::make("system/handler", std::move(hm));
        if (!he) return std::unexpected(he.error());
        store_.bind(abs_path(pattern), *he);
    }
    // interface entity at /{local}/system/handler/{pattern}
    {
        auto im = EcfValue::map();
        im.put(EcfValue::text("pattern"), EcfValue::text(pattern));
        im.put(EcfValue::text("name"), EcfValue::text(name));
        im.put(EcfValue::text("operations"), operations_map(ops));
        auto ie = Entity::make("system/handler/interface", std::move(im));
        if (!ie) return std::unexpected(ie.error());
        store_.bind("/" + local_ + "/system/handler/" + pattern, *ie);
    }
    // empty self-grant
    if (auto minted = mint_token(identity_.identity_hash(), EcfValue::array(), std::nullopt)) {
        store_.bind("/" + local_ + "/system/capability/grants/" + pattern, minted->first);
    }
    return {};
}

Result<void> Peer::publish_core_types() {
    for (const auto& td : types::core_typedefs()) {
        auto e = Entity::make("system/type", td.build());
        if (!e) return std::unexpected(e.error());
        store_.bind("/" + local_ + "/system/type/" + td.name, *e);
    }
    return {};
}

void Peer::bootstrap_authority(bool open_grants) {
    // §6.9a self-owner cap + its signature, stored under the identity-keyed policy path.
    if (auto minted = mint_token(identity_.identity_hash(), owner_grants(local_), std::nullopt)) {
        auto [token, sig] = *minted;
        store_.bind("/" + local_ + "/system/capability/policy/" +
                        identity::hex_lower(identity_.identity_hash()),
                    token);
        store_.bind("/" + local_ + "/system/signature/" + token->hash_hex(), sig);
    }
    // default policy entry
    EcfValue def_grants = open_grants ? open_grants_scope() : discovery_floor();
    auto dm = EcfValue::map();
    dm.put(EcfValue::text("peer_pattern"), EcfValue::text("default"));
    dm.put(EcfValue::text("grants"), std::move(def_grants));
    if (auto de = Entity::make("system/capability/policy-entry", std::move(dm))) {
        store_.bind(abs_path("system/capability/policy/default"), *de);
    }
}

Result<void> Peer::init(bool open_grants, bool conformance) {
    open_grants_ = open_grants;
    conformance_ = conformance;
    local_ = identity_.peer_id();

    // local identity entity in the store (root-granter resolution).
    store_.put(identity_.peer_entity());

    using V = std::string_view;
    static const std::array<V, 2> ops_tree{"get", "put"};
    static const std::array<V, 2> ops_handler{"register", "unregister"};
    static const std::array<V, 4> ops_cap{"request", "revoke", "configure", "delegate"};
    static const std::array<V, 2> ops_connect{"hello", "authenticate"};
    static const std::array<V, 1> ops_type{"validate"};

    register_handler("system/tree",
        [](Peer& p, Connection&, const Envelope& e, const Entity& x, const Entity*,
           const std::string& op, Outcome& o) { p.h_tree(e, x, op, o); });
    register_handler("system/handler",
        [](Peer& p, Connection&, const Envelope&, const Entity& x, const Entity*,
           const std::string& op, Outcome& o) { p.h_handlers(x, op, o); });
    register_handler("system/capability",
        [](Peer& p, Connection&, const Envelope&, const Entity& x, const Entity* cc,
           const std::string& op, Outcome& o) { p.h_capability(x, cc, op, o); });
    register_handler("system/protocol/connect",
        [](Peer& p, Connection& c, const Envelope& e, const Entity& x, const Entity* cc,
           const std::string& op, Outcome& o) { p.h_connect(c, e, x, cc, op, o); });
    register_handler("system/type",
        [](Peer& p, Connection&, const Envelope&, const Entity& x, const Entity*,
           const std::string& op, Outcome& o) { p.h_type(x, op, o); });

    struct Must { const char* pattern; const char* name; std::span<const V> ops; };
    const std::array<Must, 5> must{{
        {"system/tree", "Tree", ops_tree},
        {"system/handler", "Handlers", ops_handler},
        {"system/capability", "Capability", ops_cap},
        {"system/protocol/connect", "Connect", ops_connect},
        {"system/type", "Type", ops_type},
    }};
    for (const auto& m : must) {
        if (auto r = bootstrap_handler_entities(m.pattern, m.name, m.ops); !r) return r;
    }

    bootstrap_authority(open_grants);

    if (auto r = publish_core_types(); !r) return r;

    if (conformance) {
        static const std::array<V, 1> ops_echo{"echo"};
        static const std::array<V, 1> ops_dispatch{"dispatch"};
        register_handler("system/validate/echo",
            [](Peer& p, Connection&, const Envelope&, const Entity& x, const Entity*,
               const std::string& op, Outcome& o) { p.h_validate_echo(x, op, o); });
        register_handler("system/validate/dispatch-outbound",
            [](Peer& p, Connection& c, const Envelope&, const Entity& x, const Entity*,
               const std::string& op, Outcome& o) {
                p.h_validate_dispatch_outbound(c, x, op, o);
            });
        struct Conf { const char* pattern; const char* name; std::span<const V> ops; };
        const std::array<Conf, 2> conf{{
            {"system/validate/echo", "validate-echo", ops_echo},
            {"system/validate/dispatch-outbound", "validate-dispatch-outbound", ops_dispatch},
        }};
        for (const auto& c : conf) {
            if (auto r = bootstrap_handler_entities(c.pattern, c.name, c.ops); !r) return r;
        }
    }
    return {};
}

Result<std::unique_ptr<Peer>> Peer::create(std::span<const std::byte> seed, bool open_grants,
                                           bool conformance) {
    auto id = PeerIdentity::from_seed(seed);
    if (!id) return std::unexpected(id.error());
    std::unique_ptr<Peer> p(new Peer());
    p->identity_ = std::move(*id);
    if (auto r = p->init(open_grants, conformance); !r) return std::unexpected(r.error());
    return p;
}

}  // namespace entity_core
