// entity_core/transport.hpp — L4 TCP transport: listener/dialer, one std::thread reader per
// connection, §6.11 request_id demux (an unordered_map<request_id, condvar-slot>; the reader
// signals the waiting outbound via a std::condition_variable), §4.8 inbound-concurrent-with-
// outbound dispatch (each inbound EXECUTE serviced on its own thread so the reader keeps
// reading + a handler-originated outbound does not block it), §7b TCP_NODELAY on every
// connection socket, a per-connection write mutex, and the §6.13(b) reentry seam.
//
// Concurrency model (profile [concurrency]: threaded): one reader thread per connection — a
// blocking recv only blocks that connection's own thread (the Swift cooperative-pool trap is
// sidestepped structurally; std::thread maps to an OS thread). The store's shared_mutex
// (store.hpp) gives §4.8 data-race safety; shared_ptr entity lifetime is atomic (A-C-009
// pre-resolved). RAII everywhere — sockets/threads owned by objects whose destructors reap.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_TRANSPORT_HPP
#define ENTITY_CORE_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "entity_core/entity.hpp"
#include "entity_core/peer.hpp"

namespace entity_core {

// ── server side ──────────────────────────────────────────────────────────────────
class Listener {
public:
    // Bind 127.0.0.1:port (0 = auto) + spawn the accept loop.
    static Result<std::unique_ptr<Listener>> start(Peer& peer, int port);
    ~Listener();

    int port() const noexcept { return port_; }

    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    int port_ = 0;
    explicit Listener(std::unique_ptr<Impl> i, int p);
};

// ── client side: dialer + initiator session ────────────────────────────────────────
class Session {
public:
    // Dial host:port, start the reader thread, drive the §4.1 handshake.
    static Result<std::unique_ptr<Session>> dial(Peer& initiator, const std::string& host,
                                                 int port);
    ~Session();

    const std::string& remote_peer() const noexcept { return remote_peer_id_; }
    bool has_capability() const noexcept { return capability_ != nullptr; }

    // Build, sign, send an authenticated EXECUTE; await its correlated response (request_id
    // demux, N7). `resource` is an EcfValue map or nullopt.
    std::optional<Envelope> execute(const std::string& uri, const std::string& operation,
                                    const Entity& params, std::optional<EcfValue> resource);

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string remote_peer_id_;
    EntityPtr capability_;
    EntityPtr granter_peer_;
    EntityPtr cap_signature_;
    Session();
    Result<void> handshake(Peer& initiator);
};

// response helpers
std::uint64_t response_status(const Envelope& resp);
EntityPtr response_result(const Envelope& resp);

}  // namespace entity_core

#endif  // ENTITY_CORE_TRANSPORT_HPP
