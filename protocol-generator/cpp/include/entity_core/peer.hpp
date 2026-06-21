// entity_core/peer.hpp — the protocol brain (L1–L4 + foundation): the four MUST system
// handlers (§6.2 connect/tree/handler/capability), the §9.5 type-registry handler, the §6.5
// dispatch chain, §6.6 backward handler resolution, §6.9a peer-authority bootstrap + seed
// policy, the §7a conformance handlers (behind a conformance flag), and the §6.13(b)
// outbound seam.
//
// Idiom: a handler is a std::function over (Peer&, Connection&, Envelope, exec, caller_cap,
// op) → Outcome. The dispatcher wraps an Outcome in an EXECUTE_RESPONSE; errors are values
// (the §5.2 trichotomy → wire status), never thrown. Concurrency: per-connection state +
// the §6.13(b) reentry seam live in Connection (set by the transport).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_PEER_HPP
#define ENTITY_CORE_PEER_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "entity_core/capability.hpp"
#include "entity_core/entity.hpp"
#include "entity_core/peer_identity.hpp"
#include "entity_core/store.hpp"

namespace entity_core {

// The §6.13(b)/§6.11 reentry seam: a handler-originated outbound EXECUTE travels back to the
// caller over the SAME inbound connection. The transport supplies the implementation; the
// dispatch layer only sees this interface (no socket details leak into dispatch).
class OutboundSeam {
public:
    virtual ~OutboundSeam() = default;
    // Write `request` (an EXECUTE envelope) and await its correlated EXECUTE_RESPONSE by
    // request_id. Returns the response envelope or nullopt if the connection closed first.
    virtual std::optional<Envelope> outbound(const Envelope& request) = 0;
};

// Per-connection state (§4.2) + the reentry seam.
struct Connection {
    bool established = false;
    std::array<std::byte, 32> issued_nonce{};
    bool have_nonce = false;
    std::optional<std::string> hello_peer_id;
    OutboundSeam* seam = nullptr;          // §6.13(b) reentry seam (transport-owned)
    std::atomic<int> out_counter{0};
};

// An outcome carries (status, result entity, included list).
struct Outcome {
    std::uint64_t status = 200;
    EntityPtr result;
    std::vector<EntityPtr> included;
};

class Peer {
public:
    // Build a peer from a 32-byte seed. open_grants = the degenerate default→* seed policy
    // (--debug-open-grants). conformance = wire the §7a handlers (--validate; OFF by default).
    static Result<std::unique_ptr<Peer>> create(std::span<const std::byte> seed,
                                                bool open_grants, bool conformance);

    const std::string& local() const noexcept { return local_; }
    Store& store() noexcept { return store_; }
    const PeerIdentity& identity() const noexcept { return identity_; }

    // The §6.5 dispatch chain. Consumes an inbound envelope, returns a response envelope or
    // nullopt for a non-EXECUTE root (§3.3 server side ignores).
    std::optional<Envelope> dispatch(Connection& conn, const Envelope& env);

private:
    using Handler = std::function<void(Peer&, Connection&, const Envelope&, const Entity& exec,
                                       const Entity* caller_cap, const std::string& op,
                                       Outcome&)>;

    Peer() = default;

    PeerIdentity identity_;
    Store store_;
    std::string local_;
    bool open_grants_ = false;
    bool conformance_ = false;
    std::vector<std::pair<std::string, Handler>> handlers_;  // pattern → fn (the §6.6 map)

    // setup
    Result<void> init(bool open_grants, bool conformance);
    void register_handler(const std::string& pattern, Handler fn);
    const Handler* lookup_handler(const std::string& pattern) const;
    Result<void> bootstrap_handler_entities(const std::string& pattern, const std::string& name,
                                            std::span<const std::string_view> ops);
    Result<void> publish_core_types();
    void bootstrap_authority(bool open_grants);

    // handlers
    void h_connect(Connection&, const Envelope&, const Entity&, const Entity*,
                   const std::string&, Outcome&);
    void h_tree(const Envelope&, const Entity&, const std::string&, Outcome&);
    void h_handlers(const Entity&, const std::string&, Outcome&);
    void h_capability(const Entity&, const Entity*, const std::string&, Outcome&);
    void h_type(const Entity&, const std::string&, Outcome&);
    void h_validate_echo(const Entity&, const std::string&, Outcome&);
    void h_validate_dispatch_outbound(Connection&, const Entity&, const std::string&, Outcome&);

    // helpers
    std::string abs_path(std::string_view rel) const;
    Result<std::pair<EntityPtr, EntityPtr>> mint_token(
        std::span<const std::byte> grantee, EcfValue grants,
        std::optional<std::span<const std::byte>> parent);
    void attach_cap(Outcome&, const EntityPtr& token, const EntityPtr& sig);
    EcfValue derive_seed_grants(const Entity& remote_peer, const std::string& remote_peer_id);
    void ingest_signatures(const Envelope& env);
    std::optional<std::string> resolve_handler_path(const std::string& path) const;
    void build_listing(const std::string& path, Outcome&);
    void mint_bounded(const Entity* caller_cap, const EcfValue* requested,
                      std::span<const std::byte> grantee,
                      std::optional<std::span<const std::byte>> parent, Outcome&);
};

}  // namespace entity_core

#endif  // ENTITY_CORE_PEER_HPP
