require "socket"
require "random/secure"
require "./entity"
require "./envelope"
require "./identity"
require "./wire"
require "./handler"
require "./capability"
require "./peer"
require "./error"

module EntityCore
  # Transport (L4): TCP listener + dialer, per-connection reader fibers, §6.11
  # request_id demux, the §4.8 inbound-concurrent-with-outbound dispatch, and the
  # §6.13(b) reentry seam. Plus the initiator dialer/handshake that drives the
  # two-peer loopback.
  #
  # == Concurrency model (A-CRY-005): CSP fibers, single OS thread
  #
  # ONE reader `Fiber` per connection reads + demuxes inbound frames (§6.11): an
  # EXECUTE_RESPONSE routes to its awaiting outbound caller by request_id through a
  # pending `{request_id => Channel}` map (the CSP shape — a fiber parks on
  # `channel.receive`, the reader `channel.send`s the correlated response); an
  # inbound EXECUTE is dispatched on ITS OWN spawned fiber (§4.8) so a handler that
  # originates an outbound EXECUTE (§6.13(b)) and awaits its response does NOT block
  # the reader. Writes (inbound responses + outbound requests share the stream) are
  # serialized by a per-connection write `Mutex`.
  #
  # Blocking socket IO (read/write/accept) yields the fiber to the scheduler via
  # Crystal's event loop, so a fiber-per-connection peer is genuinely concurrent for
  # the IO-bound §4.8/§4.9 workload on the single default thread — no thread starves
  # (unlike a bounded structured-concurrency pool). `TCP_NODELAY` is set on every
  # socket (§7b): Nagle + delayed-ACK is the small-frame req/resp throughput killer.
  module Transport
    extend self

    def set_nodelay(socket : TCPSocket) : Nil
      socket.tcp_nodelay = true
    rescue
      # best-effort; some platforms/sockets may not support it
    end

    # ── per-connection IO (shared by server + client) ────────────────────────────

    # Per-connection IO: the framed stream, the write lock, and the §6.11 demux
    # table. A reader fiber owns `read`; any fiber may `outbound` (it parks on a
    # per-request Channel until the reader routes the response).
    class Io
      getter socket : TCPSocket

      def initialize(@socket : TCPSocket)
        Transport.set_nodelay(@socket)
        @write_mutex = Mutex.new
        @pending = {} of String => Channel(Envelope?)
        @pending_mutex = Mutex.new
        @closed = false
      end

      def read_frame : Bytes?
        Wire.read_frame(@socket)
      end

      def write_framed(env : Envelope) : Nil
        payload = Wire.frame_of_envelope(env)
        @write_mutex.synchronize { Wire.write_frame(@socket, payload) }
      end

      # §6.13(b) outbound primitive: send a request envelope, await its correlated
      # EXECUTE_RESPONSE (§6.11). Parks the calling (dispatch) fiber on a Channel;
      # the reader routes the response. Returns nil if the connection closes first.
      def outbound(request : Envelope) : Envelope?
        request_id = request.root.text("request_id") || ""
        ch = Channel(Envelope?).new(1)
        @pending_mutex.synchronize { @pending[request_id] = ch }
        begin
          write_framed(request)
          ch.receive
        rescue TransportError
          nil
        rescue Channel::ClosedError
          nil
        ensure
          @pending_mutex.synchronize { @pending.delete(request_id) }
        end
      end

      def route_response(env : Envelope) : Nil
        request_id = env.root.text("request_id") || ""
        ch = @pending_mutex.synchronize { @pending[request_id]? }
        return unless ch
        ch.send(env) rescue nil
        nil
      end

      def close : Nil
        return if @closed
        @closed = true
        # wake any parked outbound waiters so they return nil
        @pending_mutex.synchronize do
          @pending.each_value do |ch|
            ch.send(nil) rescue nil
          end
        end
        @socket.close rescue nil
        nil
      end
    end

    # The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on
    # its own fiber (§4.8) + write the response. Returns when the connection closes /
    # a malformed frame ends it.
    # Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a
    # frame refused BEFORE it becomes an admitted request.
    #
    # "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE
    # on the wire [MUST] — correlated by request_id where the id is available, and
    # otherwise as a best-effort coded frame carrying no correlation."
    #
    # §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS"
    # and therefore reaches none of these, which is why §4.11 exists. Both of the
    # non-conformant behaviours it names SEPARATELY were present on this peer:
    # DROPPING the frame (the un-salvageable decode arm, "the weaker of the two
    # precisely because nothing surfaces it") and CLOSING with no coded frame (the
    # oversize and truncated arms' bare `break`).
    #
    # AN EMPTY request_id IS THE BEST-EFFORT FORM, not a bug: it is what the section
    # prescribes where no id can be recovered.
    def refuse_pre_admission(io : Io, request_id : String, refusal : {Int32, String, String}) : Nil
      status, code, message = refusal
      io.write_framed(
        Envelope.of(Wire.make_response(request_id, status, Wire.error_result(code, message)))
      )
    rescue TransportError
      # A write failure here is a dead socket, not a protocol decision.
    end

    def read_loop(peer : Peer, conn : Conn, io : Io) : Nil
      loop do
        payload =
          begin
            io.read_frame
          rescue e : PayloadTooLargeError | TruncatedFrameError
            # §4.11: BOTH of these are REFUSALS owed a coded frame, and both used
            # to be a bare `break` — "closing with no coded frame", which is
            # indistinguishable from a network fault and, on a multiplexed
            # connection, destroys unrelated ADMITTED requests. §4.10(a)'s mood was
            # raised SHOULD -> MUST at 0.8.2.25 (N14): the over-size condition is
            # detected at the length prefix with the connection intact and nothing
            # spent, so the permissive mood had nothing to license.
            #
            # The stream is desynchronized on both arms — an oversize body was
            # never drained, a truncated one never arrived — so the frame goes out
            # and THEN the connection closes. §4.11 makes the frame mandatory and
            # leaves the close to us; closing is the only sound choice once the
            # framing is lost, and it is a CHOICE rather than an alternative to
            # answering.
            #
            # §4.11's best-effort UNCORRELATED form: no request_id can be recovered
            # from a frame whose body never arrived, and guessing one would
            # correlate the refusal to somebody else's in-flight request.
            Transport.refuse_pre_admission(io, "", Wire.pre_admission_refusal(e))
            break
          rescue TransportError
            break # an ordinary hangup or a dead socket: not a refusal of anything
          end
        break if payload.nil? # clean EOF at a frame boundary — owed nothing

        env =
          begin
            Wire.envelope_of_frame(payload)
          rescue e : CodecError | ProtocolError
            # A COMPLETE frame the decoder refused. The framing is intact, so we
            # answer and KEEP SERVING — and the refusal MUST be a status rather than
            # silence (§4.11; §4.9(c) says the same from the other direction). This
            # used to be a bare `next`, which rejected the frame (correct) and then
            # dropped it on the floor (wrong): the sender saw no response at all and
            # blocked until its own timeout, so a refusal was indistinguishable from
            # a dead peer.
            #
            # THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
            # `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned them
            # apart: a mis-keyed `included` entry is `400 hash_mismatch` (its
            # encoding is canonical — what is false is the claim the key makes), a
            # tag-policy violation keeps `non_canonical_ecf`, and everything else
            # that never becomes an Envelope is `400 invalid_request`.
            #
            # The frame is still REJECTED — only enough is salvaged to correlate the
            # response, and an unrecoverable id takes §4.11's uncorrelated
            # best-effort form rather than the silence it used to take.
            Transport.refuse_pre_admission(
              io, Wire.salvage_request_id(payload) || "", Wire.pre_admission_refusal(e)
            )
            next # keep reading
          end

        if env.root.type == "system/protocol/execute/response"
          io.route_response(env)
        else
          spawn do
            resp =
              begin
                peer.dispatch(conn, env)
              rescue
                request_id = env.root.text("request_id") || ""
                Envelope.of(Wire.make_response(request_id, 500, Wire.error_result("internal_error")))
              end
            # Unconditional: `dispatch` now answers EVERY inbound root, including
            # the non-EXECUTE one that used to come back nil and be dropped
            # (§4.11, N12/N17).
            begin
              io.write_framed(resp)
            rescue TransportError
              # write failure ends this exchange; reader keeps going
            end
          end
        end
      end
    ensure
      io.close
    end

    # ── server: listener + accept loop ────────────────────────────────────────────

    # A running listener: the bound server socket + accept fiber. The host owns the
    # accept loop; this wrapper is used by the smoke runner's in-process server.
    class Listener
      getter port : Int32

      def initialize(@server : TCPServer, @port : Int32)
      end

      def close : Nil
        @server.close rescue nil
      end
    end

    # Bind 127.0.0.1:port (0 = auto) and spawn the accept loop.
    def start_listener(peer : Peer, port : Int32) : Listener
      server = TCPServer.new("127.0.0.1", port)
      bound = server.local_address.port
      spawn do
        loop do
          client =
            begin
              server.accept
            rescue
              break # socket closed → stop
            end
          spawn { serve_connection(peer, client) }
        end
      end
      Listener.new(server, bound)
    end

    def serve_connection(peer : Peer, client : TCPSocket) : Nil
      io = Io.new(client)
      conn = Conn.new
      # wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
      conn.outbound = ->(env : Envelope) { io.outbound(env) }
      read_loop(peer, conn, io)
    rescue
      client.close rescue nil
    end

    # ════════════════════════════════════════════════════════════════════════════
    # Client side — the dialer + initiator handshake (drives the loopback)
    # ════════════════════════════════════════════════════════════════════════════

    # A dialed, authenticated session (§4.4): the IO, the minted cap + granter + sig.
    class Session
      getter remote_peer_id : String?
      getter capability : Entity?
      property granter_peer : Entity?
      property cap_signature : Entity?

      def initialize(@io : Io, @local : Identity)
        @req_counter = 0_u64
        @counter_mutex = Mutex.new
        @remote_peer_id = nil
        @capability = nil
        @granter_peer = nil
        @cap_signature = nil
      end

      def io : Io
        @io
      end

      def local : Identity
        @local
      end

      def remote_peer_id=(v : String?)
        @remote_peer_id = v
      end

      def capability=(v : Entity?)
        @capability = v
      end

      def next_request_id : String
        n = @counter_mutex.synchronize { @req_counter += 1; @req_counter }
        "req-#{n}"
      end

      # Send REQUEST and await its correlated EXECUTE_RESPONSE (request_id demux).
      def send_request(request : Envelope) : Envelope?
        @io.outbound(request)
      end

      # Build, sign, and send an authenticated EXECUTE; await the response. The full
      # §5.8 authority chain travels in `included`.
      def execute(uri : String, operation : String, params : Entity,
                  resource : ::Hash(Cbor::EcValue, Cbor::EcValue)? = nil) : Envelope?
        cap = @capability.not_nil!
        gp = @granter_peer.not_nil!
        cs = @cap_signature.not_nil!
        exec = Wire.make_execute(next_request_id, uri, operation, params,
          author: @local.identity_hash, capability: cap.content_hash, resource: resource)
        exec_sig = @local.sign(exec)
        inc = [cap, gp, @local.peer_entity, cs, exec_sig]
        send_request(Envelope.of(exec, inc))
      end

      def close : Nil
        @io.close
      end
    end

    # Open a client connection to host:port and start its reader fiber.
    def dial(initiator : Peer, host : String, port : Int32) : Session
      sock = TCPSocket.new(host, port)
      io = Io.new(sock)
      session = Session.new(io, initiator.identity)
      # the client reader: a core responder sends only EXECUTE_RESPONSEs; route
      # them. Wire the outbound seam so a §6.13(b) reentry can drive this socket.
      conn = Conn.new
      conn.outbound = ->(env : Envelope) { io.outbound(env) }
      spawn { read_loop(initiator, conn, io) }
      handshake(session)
      session
    end

    # Drive the §4.1 forward handshake as initiator: hello then authenticate. On
    # success, populate the session with the §4.4 capability the responder minted.
    def handshake(session : Session) : Nil
      local = session.local
      # ── hello ──
      hdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      hdata["peer_id"] = local.peer_id
      hdata["nonce"] = Random::Secure.random_bytes(32)
      hdata["protocols"] = ["entity-core/1.0".as(Cbor::EcValue)]
      hdata["timestamp"] = Cbor::EcInt.from(Capability.now_ms)
      hdata["hash_formats"] = ["ecfv1-sha256".as(Cbor::EcValue)]
      hdata["key_types"] = ["ed25519".as(Cbor::EcValue)]
      hello = Entity.make("system/protocol/connect/hello", hdata)
      r1 = session.send_request(Envelope.new(
        Wire.make_execute(session.next_request_id, "system/protocol/connect", "hello", hello)))
      require_ok(r1, "hello")
      remote_hello = Wire.response_result(r1.not_nil!).not_nil!
      session.remote_peer_id = remote_hello.text("peer_id")
      remote_nonce = remote_hello.bytes("nonce").not_nil!

      # ── authenticate ──
      adata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      adata["peer_id"] = local.peer_id
      adata["public_key"] = local.public_key
      adata["key_type"] = "ed25519"
      adata["nonce"] = remote_nonce
      auth = Entity.make("system/protocol/connect/authenticate", adata)
      auth_sig = local.sign(auth)
      auth_inc = [local.peer_entity, auth_sig]
      r2 = session.send_request(Envelope.of(
        Wire.make_execute(session.next_request_id, "system/protocol/connect", "authenticate", auth), auth_inc))
      require_ok(r2, "authenticate")

      # parse the §4.4 initial capability grant
      grant = Wire.response_result(r2.not_nil!).not_nil!
      token_h = grant.bytes("token").not_nil!
      token = r2.not_nil!.included_get(token_h)
      raise TransportError.new("authenticate grant omits the capability token") if token.nil?
      granter_h = token.bytes("granter").not_nil!
      granter_peer = r2.not_nil!.included_get(granter_h)
      cap_sig = Capability.find_signature(token.content_hash, r2.not_nil!.included)
      raise TransportError.new("authenticate grant omits the granter identity") if granter_peer.nil?
      raise TransportError.new("authenticate grant omits the capability signature") if cap_sig.nil?

      session.capability = token
      session.granter_peer = granter_peer
      session.cap_signature = cap_sig
      nil
    end

    private def require_ok(env : Envelope?, step : String) : Nil
      raise TransportError.new("#{step} failed: no response") if env.nil?
      status = Wire.response_status(env)
      return if status == 200_u64
      r = Wire.response_result(env)
      code = r.try &.text("code")
      msg = r.try &.text("message")
      raise TransportError.new("#{step} failed: #{status} #{code} #{msg}")
    end
  end
end
