// transport.cpp — L4 TCP transport. See transport.hpp. Idiomatic C++: std::thread reader
// per connection, std::mutex/std::condition_variable demux, RAII socket/thread ownership.
//
// Framing (§1.6): a 4-byte big-endian length prefix then the CBOR envelope payload. The
// length is checked against wire::kMaxFrame (16 MiB) BEFORE the body is read (§4.10(a) →
// clean close on an over-limit prefix).
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/transport.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <list>
#include <mutex>
#include <thread>

#include "entity_core/wire.hpp"

namespace entity_core {

namespace {

// Read exactly n bytes. `*partial` reports whether ANY byte arrived before the stream
// ended — the discriminator between an ordinary hangup and a §4.11 truncated frame.
bool read_n_p(int fd, std::byte* buf, std::size_t n, bool* partial) {
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd, buf + got, n - got, 0);
        if (r <= 0) {
            if (partial) *partial = (got > 0);
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    return true;
}

bool read_n(int fd, std::byte* buf, std::size_t n) { return read_n_p(fd, buf, n, nullptr); }

bool write_n(int fd, const std::byte* buf, std::size_t n) {
    std::size_t put = 0;
    while (put < n) {
        ssize_t w = ::send(fd, buf + put, n - put, MSG_NOSIGNAL);
        if (w <= 0) return false;
        put += static_cast<std::size_t>(w);
    }
    return true;
}

}  // namespace

// ── Io: one connection's socket + demux table + the §6.13(b) reentry seam ───────────
class Io : public OutboundSeam {
public:
    explicit Io(int fd) : fd_(fd) {
        int one = 1;
        ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));  // §7b
    }
    ~Io() override {
        ::close(fd_);
    }

    // Force a blocked recv() to return + mark closed (idempotent).
    void close_io() {
        {
            std::lock_guard lk(demux_mu_);
            closed_ = true;
            cv_.notify_all();
        }
        ::shutdown(fd_, SHUT_RDWR);
    }

    // Read one frame's payload.
    //
    // THE THREE OUTCOMES ARE NOT TWO (§4.11, 0.8.2.25). `Eof` is an ordinary hangup at a
    // frame boundary and is owed NOTHING — there is nobody left to answer. `Truncated`
    // and `TooLarge` are REFUSALS and are each owed a coded EXECUTE_RESPONSE with its own
    // code. This used to collapse all three into one `Error` that ended the loop with no
    // frame at all, which is §4.11's named "closed with no coded frame" non-conformance.
    enum class FrameStatus { Ok, Eof, Truncated, TooLarge };
    FrameStatus read_frame(std::vector<std::byte>& out) {
        std::byte hdr[4];
        bool partial = false;
        if (!read_n_p(fd_, hdr, 4, &partial)) {
            // A close having read ZERO bytes is an ordinary hangup; having read SOME, the
            // length prefix never completed and the frame is truncated. Both surface as
            // recv() answering 0, so the distinction can only be made here, where the
            // frame boundary is known — and getting it wrong the other way answers 400 to
            // every peer that simply closes.
            return partial ? FrameStatus::Truncated : FrameStatus::Eof;
        }
        std::uint32_t len = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(hdr[0])) << 24) |
                            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(hdr[1])) << 16) |
                            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(hdr[2])) << 8) |
                            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(hdr[3]));
        // §4.10(a): bound the payload BEFORE buffering the body. N14 raised the 413 from
        // SHOULD to MUST at 0.8.2.25 — the condition is detected at the length prefix with
        // the connection intact and nothing spent, so close-without-frame is no longer
        // licensed.
        if (len > wire::kMaxFrame) return FrameStatus::TooLarge;
        // A ZERO-LENGTH frame is COMPLETE, not truncated: the body read touches no bytes
        // and the empty payload reaches the decoder, which refuses it as bytes that never
        // become an Envelope.
        out.resize(len);
        if (len && !read_n(fd_, out.data(), len)) return FrameStatus::Truncated;
        return FrameStatus::Ok;
    }

    bool write_envelope(const Envelope& env) {
        auto payload = env.to_wire();
        if (!payload) return false;
        std::uint32_t plen = static_cast<std::uint32_t>(payload->size());
        std::byte hdr[4] = {
            std::byte(static_cast<std::uint8_t>(plen >> 24)),
            std::byte(static_cast<std::uint8_t>(plen >> 16)),
            std::byte(static_cast<std::uint8_t>(plen >> 8)),
            std::byte(static_cast<std::uint8_t>(plen)),
        };
        std::lock_guard lk(write_mu_);  // serialize the shared stream (§4.8)
        return write_n(fd_, hdr, 4) && (plen == 0 || write_n(fd_, payload->data(), plen));
    }

    // §6.13(b)/§6.11 reentry primitive: write `request` + await its correlated response by
    // request_id (the reader routes it back). Used by the dispatch-outbound seam + session.
    std::optional<Envelope> outbound(const Envelope& request) override {
        std::string rid = request.root()->text("request_id").value_or("");
        auto slot = std::make_shared<Slot>(rid);
        {
            std::lock_guard lk(demux_mu_);
            slots_.push_back(slot);
        }
        bool wrote = write_envelope(request);
        std::optional<Envelope> resp;
        {
            std::unique_lock lk(demux_mu_);
            if (wrote) {
                cv_.wait(lk, [&] { return slot->filled || closed_; });
                resp = std::move(slot->response);
            }
            slots_.remove(slot);
        }
        return resp;
    }

    // Route an EXECUTE_RESPONSE to its awaiting slot.
    void route(Envelope env) {
        std::string rid = env.root()->text("request_id").value_or("");
        std::lock_guard lk(demux_mu_);
        for (auto& s : slots_) {
            if (s->request_id == rid && !s->filled) {
                s->response = std::move(env);
                s->filled = true;
                cv_.notify_all();
                return;
            }
        }
        // no waiter: drop
    }

private:
    struct Slot {
        explicit Slot(std::string rid) : request_id(std::move(rid)) {}
        std::string request_id;
        std::optional<Envelope> response;
        bool filled = false;
    };

    int fd_;
    std::mutex write_mu_;
    std::mutex demux_mu_;
    std::condition_variable cv_;
    std::list<std::shared_ptr<Slot>> slots_;
    bool closed_ = false;
};

namespace {

// §6.3: recover ONLY the request_id from a frame the strict decoder rejected, so the
// rejection can be delivered as a correlated `400 non_canonical_ecf` response instead of
// silence. The frame stays rejected -- nothing else is read out of it.
//
// The envelope and entity-wrapper shapes are fixed maps with no legal tag position
// (§6.3), so a frame whose ONLY defect is a tag inside some entity's `data` still has a
// structurally sound root -- which is exactly the case this recovers.
std::optional<std::string> salvage_request_id(std::span<const std::byte> payload) {
    auto v = ecf::decode_salvage(payload);
    if (!v) return std::nullopt;
    const auto* root = v->find("root");
    if (!root) return std::nullopt;
    const auto* data = root->find("data");
    if (!data) return std::nullopt;
    const auto* rid = data->find("request_id");
    if (!rid) return std::nullopt;
    const auto* t = rid->get_if<ecf::Text>();
    if (!t) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(t->data()), t->size());
}

// The (status, code, message) §4.11 assigns a pre-admission failure's CAUSE.
//
// "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" — a
// single code for the class would answer an honest caller under the wrong reason and send
// them to the wrong layer.
//
//   connect-auth proof-of-possession      -> 401 authentication_failed  (§4.6/§4.7, h_connect's)
//   envelope over the configured maximum  -> 413 payload_too_large      (§4.10(a), N14)
//   resolution integrity (mis-keyed)      -> 400 hash_mismatch          (§5.2a, §1.8)
//   framing / never becomes an Envelope   -> 400 invalid_request        (§4.7, §4.11)
//   root is neither EXECUTE nor RESPONSE  -> 400 invalid_request        (§3.3, §4.11 — in dispatch)
//
// THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
// non-conformant "on the framing arm" and gives its reason in the same sentence:
// ENTITY-CBOR-ENCODING "defines that code for CBOR tag-policy violations specifically",
// which that document still MUSTs at decode time (§6.3). The two rows are disjoint by
// CAUSE rather than in conflict: a tag in a DATA-FIELD position is the policy violation
// with its own code, while a tag in the envelope shape is a structurally invalid frame —
// the framing arm. Everything else this decoder calls non-canonical (a non-minimal head,
// an indefinite length, mis-ordered keys) is genuinely "non-canonical CBOR that never
// becomes an Envelope" and takes `invalid_request`.
//
// The messages are a FIXED TABLE, never a rendered internal error: a wire-visible string
// must stay ASCII (two peers in this cohort have been killed at runtime by a non-ASCII
// byte in an encoded string), and nothing here echoes attacker-supplied bytes back.
struct Refusal {
    std::uint64_t status;
    const char* code;
    const char* message;
};

Refusal decode_refusal(ecf::EcfError e) {
    switch (e) {
        case ecf::EcfError::HashMismatch:
            return {400, "hash_mismatch",
                    "an entity was addressed by a hash that does not bind to it"};
        case ecf::EcfError::TagRejected:
            return {400, "non_canonical_ecf",
                    "CBOR tags are forbidden anywhere in an entity data field"};
        default:
            return {400, "invalid_request", "frame did not decode into an envelope"};
    }
}

// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
// refused BEFORE it becomes an admitted request.
//
// "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
// wire [MUST] — correlated by `request_id` where the id is available, and otherwise as a
// best-effort coded frame carrying no correlation."
//
// §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
// therefore reaches none of these, which is why §4.11 exists. The two non-conformant
// behaviours it names are SEPARATE failures and this peer had one of each: DROPPING the
// frame (the un-salvageable arm, which fell through to silence — "the weaker of the two
// precisely because nothing surfaces it"), and CLOSING with no coded frame (the oversize
// and truncated arms, which ended reader_loop outright). A bare close is
// indistinguishable from a network fault (§4.6), and on a multiplexed connection it
// destroys unrelated ADMITTED requests.
//
// AN EMPTY `request_id` IS THE BEST-EFFORT FORM, not a bug: it is what the section
// prescribes where no id can be recovered, and guessing one would correlate the refusal
// to somebody else's in-flight request.
//
// Best-effort throughout — a failure here degrades to the silence this exists to remove.
void refuse_pre_admission(Io& io, const std::string& request_id, Refusal r) {
    auto e = wire::error_result(r.code, std::string(r.message));
    if (!e) return;
    auto resp = wire::make_response(request_id, r.status, **e);
    if (!resp) return;
    io.write_envelope(Envelope(*resp));
}

// The per-connection reader loop (§6.11 demux + §4.8 inbound dispatch). Each inbound EXECUTE
// is dispatched on its OWN detached thread so the reader keeps reading + a handler-originated
// outbound (§6.13(b)) does not block it.
void reader_loop(Peer* peer, std::shared_ptr<Connection> conn, std::shared_ptr<Io> io) {
    for (;;) {
        std::vector<std::byte> payload;
        auto st = io->read_frame(payload);
        if (st != Io::FrameStatus::Ok) {
            // §4.11 (0.8.2.25). The stream is desynchronized on both REFUSABLE arms — an
            // oversize body was never drained, a truncated one never arrived — so the
            // coded frame goes out and THEN the loop ends. §4.11 makes the frame mandatory
            // and leaves the close to us; closing is the only sound choice once the
            // framing is lost, and it is a CHOICE rather than an alternative to answering.
            // An ordinary hangup is not a refusal and gets nothing.
            if (st == Io::FrameStatus::TooLarge) {
                refuse_pre_admission(*io, "", {413, "payload_too_large",
                                               "inbound frame exceeds the configured maximum size"});
            } else if (st == Io::FrameStatus::Truncated) {
                refuse_pre_admission(*io, "", {400, "invalid_request",
                                               "frame did not decode into an envelope"});
            }
            break;
        }
        auto env = Envelope::from_wire(payload);
        if (!env) {
            // §6.3: "Rejection returns 400 non_canonical_ecf" -- a rejected frame is
            // owed a STATUS, not silence. This used to `continue`, which rejected the
            // frame (correct) and then dropped it on the floor (wrong): the sender saw
            // no response at all and blocked until its own timeout, violating §6.3's
            // second sentence and §4.9(c) deliver-or-signal. It also made a refusal
            // indistinguishable from a dead peer, and on a single-connection oracle run
            // it poisons every later request on the same connection.
            //
            // The frame is still REJECTED -- only enough is salvaged to correlate the
            // response. Where even the request_id is unrecoverable §4.11 prescribes the
            // UNCORRELATED best-effort frame, which is what the empty id produces; this
            // used to fall through to silence, §4.11's other named non-conformance.
            //
            // THE CODE IS THE CAUSE'S (§4.11, §5.2a) — see decode_refusal(). This answered
            // `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned them apart
            // (measured on the wire: arc-probe B1/B2).
            refuse_pre_admission(*io, salvage_request_id(payload).value_or(""),
                                 decode_refusal(env.error()));
            continue;  // keep reading (N6/§4.9)
        }
        if (env->root()->type() == "system/protocol/execute/response") {
            io->route(std::move(*env));
        } else {
            // §4.8: dispatch on its own thread; capture by value to keep peer/conn/io alive.
            Envelope inbound = std::move(*env);
            std::thread([peer, conn, io, e = std::move(inbound)]() mutable {
                auto resp = peer->dispatch(*conn, e);
                if (resp) io->write_envelope(*resp);
            }).detach();
        }
    }
    io->close_io();
}

}  // namespace

// ── Listener ────────────────────────────────────────────────────────────────────────
struct Listener::Impl {
    Peer* peer = nullptr;
    int server_fd = -1;
    std::atomic<bool> stop{false};
    std::thread accept_thread;
    // Each accepted connection: keep its Io + Connection + reader thread alive until reaped.
    //
    // AND NOTHING REAPED THEM. This list was push_back-only: no erase anywhere, so a
    // finished connection's `Io` stayed referenced for the process lifetime — and
    // `~Io` is what calls `::close(fd_)`, while `close_io()` only `shutdown()`s. So
    // the peer retained ONE FILE DESCRIPTOR PER CONNECTION, forever, and the comment
    // above ("until reaped") described an intention rather than the code.
    //
    // Measured on the running peer rather than argued from the source: 4 fds idle →
    // **1419 after one `--profile core` suite → 2834 after two**, linear and
    // unbounded. It has never failed a run because the container's soft limit is
    // 524288; under the conventional 1024 it would exhaust descriptors partway
    // through a single suite, and `accept()` would then fail with EMFILE. It is
    // remotely triggerable by anyone who can open a connection.
    //
    // `done` is what makes the reap safe without blocking the accept loop: the reader
    // sets it as its LAST act, so an entry is only ever erased once its thread has
    // finished, and the erase joins that thread before dropping the shared_ptrs.
    // Detached §4.8 dispatch threads hold their own shared_ptr copies, so the fd
    // survives exactly as long as someone is still using it — the refcount is the
    // ownership discipline here, the way `join()` is in the thread-per-connection
    // peers.
    struct Conn {
        std::shared_ptr<Io> io;
        std::shared_ptr<Connection> conn;
        std::thread reader;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex conns_mu;
    std::list<Conn> conns;

    // Join and drop every connection whose reader has finished. Called from the
    // accept loop AFTER accept() returns, so a connection that ended while we were
    // parked is released on the next one rather than at process exit.
    void reap_finished() {
        for (auto it = conns.begin(); it != conns.end();) {
            if (it->done->load(std::memory_order_acquire)) {
                if (it->reader.joinable()) it->reader.join();
                it = conns.erase(it);  // last shared_ptr → ~Io → ::close(fd)
            } else {
                ++it;
            }
        }
    }

    ~Impl() {
        stop = true;
        if (server_fd >= 0) {
            ::shutdown(server_fd, SHUT_RDWR);
            ::close(server_fd);
        }
        if (accept_thread.joinable()) accept_thread.join();
        // close + join every live connection (deterministic reap → no leaks).
        std::lock_guard lk(conns_mu);
        for (auto& c : conns) {
            c.io->close_io();
            if (c.reader.joinable()) c.reader.join();
        }
    }

    void accept_loop() {
        while (!stop) {
            int client = ::accept(server_fd, nullptr, nullptr);
            if (client < 0) {
                if (errno == EINTR) continue;
                break;
            }
            auto io = std::make_shared<Io>(client);
            auto conn = std::make_shared<Connection>();
            conn->seam = io.get();  // §6.13(b) reentry seam: this is the inbound connection
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::lock_guard lk(conns_mu);
            reap_finished();
            conns.push_back(Conn{io, conn,
                                 std::thread([this, conn, io, done] {
                                     reader_loop(peer, conn, io);
                                     // LAST: the accept loop may join this thread and
                                     // drop the connection the instant it reads true.
                                     done->store(true, std::memory_order_release);
                                 }),
                                 done});
        }
    }
};

Listener::Listener(std::unique_ptr<Impl> i, int p) : impl_(std::move(i)), port_(p) {}
Listener::~Listener() = default;

Result<std::unique_ptr<Listener>> Listener::start(Peer& peer, int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return std::unexpected(ecf::EcfError::BadInput);
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(fd, 64) < 0) {
        ::close(fd);
        return std::unexpected(ecf::EcfError::BadInput);
    }
    socklen_t alen = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &alen);
    int bound = ntohs(addr.sin_port);

    auto impl = std::make_unique<Impl>();
    impl->peer = &peer;
    impl->server_fd = fd;
    impl->accept_thread = std::thread([raw = impl.get()] { raw->accept_loop(); });
    return std::unique_ptr<Listener>(new Listener(std::move(impl), bound));
}

// ── Session ───────────────────────────────────────────────────────────────────────
struct Session::Impl {
    Peer* initiator = nullptr;
    std::shared_ptr<Io> io;
    std::shared_ptr<Connection> conn;
    std::thread reader;
    std::atomic<int> req_counter{0};

    ~Impl() {
        if (io) io->close_io();
        if (reader.joinable()) reader.join();
    }
    std::string next_request_id() { return "req-" + std::to_string(++req_counter); }
};

Session::Session() = default;
Session::~Session() = default;

std::uint64_t response_status(const Envelope& resp) {
    return resp.root()->uint("status").value_or(0);
}

EntityPtr response_result(const Envelope& resp) {
    return resp.root()->entity_field("result");
}

std::optional<Envelope> Session::execute(const std::string& uri, const std::string& operation,
                                         const Entity& params, std::optional<EcfValue> resource) {
    std::string rid = impl_->next_request_id();
    auto& id = impl_->initiator->identity();
    auto exec = wire::make_execute(rid, uri, operation, params, id.identity_hash(),
                                   std::span<const std::byte>(capability_->hash()),
                                   std::move(resource));
    if (!exec) return std::nullopt;
    auto exec_sig = id.sign(**exec);
    if (!exec_sig) return std::nullopt;
    Envelope env(*exec);
    // §5.8 authority chain travels in included.
    env.add(capability_);
    env.add(granter_peer_);
    env.add(id.peer_entity());
    env.add(cap_signature_);
    env.add(*exec_sig);
    return impl_->io->outbound(env);
}

Result<void> Session::handshake(Peer& initiator) {
    auto& id = initiator.identity();
    auto send = [&](const Envelope& req) { return impl_->io->outbound(req); };
    auto resp_ok = [](const std::optional<Envelope>& r) {
        return r && response_status(*r) == 200;
    };

    // ── hello ──
    std::array<std::byte, 32> nonce{};
    for (std::size_t i = 0; i < 32; ++i) {
        nonce[i] = std::byte(static_cast<std::uint8_t>(cap::now_ms() >> (i % 8)) ^
                             static_cast<std::uint8_t>(i * 17 + 3));
    }
    using V = std::string_view;
    std::array<V, 1> protos{"entity-core/1.0"};
    std::array<V, 1> hf{"ecfv1-sha256"};
    std::array<V, 1> kt{"ed25519"};
    auto hm = EcfValue::map();
    hm.put(EcfValue::text("peer_id"), EcfValue::text(id.peer_id()));
    hm.put(EcfValue::text("nonce"), EcfValue::bytes(nonce));
    hm.put(EcfValue::text("protocols"), value::text_array(protos));
    hm.put(EcfValue::text("timestamp"), EcfValue::uint(cap::now_ms()));
    hm.put(EcfValue::text("hash_formats"), value::text_array(hf));
    hm.put(EcfValue::text("key_types"), value::text_array(kt));
    auto hello = Entity::make("system/protocol/connect/hello", std::move(hm));
    if (!hello) return std::unexpected(hello.error());
    auto exec1 = wire::make_execute(impl_->next_request_id(), "system/protocol/connect", "hello",
                                    **hello, std::nullopt, std::nullopt, std::nullopt);
    if (!exec1) return std::unexpected(exec1.error());
    auto r1 = send(Envelope(*exec1));
    if (!resp_ok(r1)) return std::unexpected(ecf::EcfError::BadInput);
    auto remote_hello = response_result(*r1);
    auto remote_pid = remote_hello ? remote_hello->text("peer_id") : std::nullopt;
    auto remote_nonce = remote_hello ? remote_hello->bytes("nonce") : std::nullopt;
    if (!remote_pid || !remote_nonce || remote_nonce->size() != 32) {
        return std::unexpected(ecf::EcfError::BadInput);
    }
    remote_peer_id_ = *remote_pid;
    std::array<std::byte, 32> echoed{};
    std::memcpy(echoed.data(), remote_nonce->data(), 32);

    // ── authenticate ──
    auto am = EcfValue::map();
    am.put(EcfValue::text("peer_id"), EcfValue::text(id.peer_id()));
    am.put(EcfValue::text("public_key"), EcfValue::bytes(id.public_key()));
    am.put(EcfValue::text("key_type"), EcfValue::text("ed25519"));
    am.put(EcfValue::text("nonce"), EcfValue::bytes(echoed));
    auto auth = Entity::make("system/protocol/connect/authenticate", std::move(am));
    if (!auth) return std::unexpected(auth.error());
    auto auth_sig = id.sign(**auth);
    if (!auth_sig) return std::unexpected(auth_sig.error());
    auto exec2 = wire::make_execute(impl_->next_request_id(), "system/protocol/connect",
                                    "authenticate", **auth, std::nullopt, std::nullopt,
                                    std::nullopt);
    if (!exec2) return std::unexpected(exec2.error());
    Envelope env2(*exec2);
    env2.add(id.peer_entity());
    env2.add(*auth_sig);
    auto r2 = send(env2);
    if (!resp_ok(r2)) return std::unexpected(ecf::EcfError::BadInput);

    // parse the §4.4 initial capability grant.
    auto grant = response_result(*r2);
    auto tok_h = grant ? grant->bytes("token") : std::nullopt;
    EntityPtr token = (tok_h && tok_h->size() == kHashLen) ? r2->find(*tok_h) : nullptr;
    if (!token) return std::unexpected(ecf::EcfError::BadInput);
    auto granter_h = token->bytes("granter");
    EntityPtr granter = (granter_h && granter_h->size() == kHashLen) ? r2->find(*granter_h)
                                                                     : nullptr;
    EntityPtr cap_sig;
    for (const auto& e : r2->included()) {
        if (e->type() == "system/signature") {
            auto tg = e->bytes("target");
            if (tg && tg->size() == kHashLen &&
                std::equal(tg->begin(), tg->end(), token->hash().begin())) {
                cap_sig = e;
                break;
            }
        }
    }
    if (!granter || !cap_sig) return std::unexpected(ecf::EcfError::BadInput);
    capability_ = token;
    granter_peer_ = granter;
    cap_signature_ = cap_sig;
    return {};
}

Result<std::unique_ptr<Session>> Session::dial(Peer& initiator, const std::string& host,
                                               int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return std::unexpected(ecf::EcfError::BadInput);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1 ||
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return std::unexpected(ecf::EcfError::BadInput);
    }
    std::unique_ptr<Session> s(new Session());
    s->impl_ = std::make_unique<Impl>();
    s->impl_->initiator = &initiator;
    s->impl_->io = std::make_shared<Io>(fd);
    s->impl_->conn = std::make_shared<Connection>();
    s->impl_->conn->seam = s->impl_->io.get();
    // the client reader: a core responder sends only EXECUTE_RESPONSEs (routed by demux); an
    // inbound EXECUTE (reentry) dispatches on its own thread.
    s->impl_->reader = std::thread(reader_loop, &initiator, s->impl_->conn, s->impl_->io);
    if (auto r = s->handshake(initiator); !r) return std::unexpected(r.error());
    return s;
}

}  // namespace entity_core
