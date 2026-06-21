# frozen_string_literal: true

require "socket"
require "securerandom"

require_relative "entity"
require_relative "envelope"
require_relative "identity"
require_relative "wire"
require_relative "handler"
require_relative "capability"
require_relative "error"

module EntityCore
  # Transport (L4): TCP listener + dialer, per-connection reader threads, §6.11
  # request_id demux, the §4.8 inbound-concurrent-with-outbound dispatch, and the
  # §6.13(b) reentry seam. Plus the initiator dialer/handshake that drives the
  # two-peer loopback.
  #
  # == Concurrency model (A-RUBY-004): thread-per-connection under the GVL
  #
  # ONE Ruby +Thread+ per connection reads + demuxes inbound frames (§6.11): an
  # EXECUTE_RESPONSE routes to its awaiting outbound caller by request_id through
  # a +pending {request_id => Waiter}+ map woken by a +ConditionVariable+; an
  # inbound EXECUTE is dispatched on ITS OWN +Thread+ (§4.8) so a handler that
  # originates an outbound EXECUTE (§6.13(b)) and awaits its response does NOT
  # block the reader. Writes (inbound responses + outbound requests share the
  # stream) are serialized by a per-connection write +Mutex+.
  #
  # The honest GVL accounting: MRI serializes Ruby BYTECODE, but RELEASES the GVL
  # during blocking IO (socket read/write/accept, OpenSSL C calls), so this
  # IO-bound peer is genuinely concurrent — while one thread blocks in +recv+,
  # others run. +TCP_NODELAY+ is set on every socket (§7b): Nagle + delayed-ACK
  # is the small-frame req/resp throughput killer (the Zig lesson).
  module Transport
    module_function

    def set_nodelay(socket)
      socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    rescue StandardError
      # best-effort; some platforms/sockets may not support it
    end

    # ── per-connection IO (shared by server + client) ──────────────────────────

    # Per-connection IO: the framed stream, the write lock, and the §6.11 demux
    # table. A reader thread owns +read+; any thread may +outbound+ (it parks on
    # a per-request ConditionVariable until the reader routes the response).
    class Io
      def initialize(socket)
        @socket = socket
        Transport.set_nodelay(socket)
        @write_mutex = Mutex.new
        @pending = {}            # request_id → Waiter
        @pending_mutex = Mutex.new
        @closed = false
      end

      attr_reader :socket

      def read_frame
        Wire.read_frame(@socket)
      end

      def write_framed(env)
        payload = Wire.frame_of_envelope(env)
        @write_mutex.synchronize { Wire.write_frame(@socket, payload) }
      end

      # A single outbound waiter: a slot + a ConditionVariable for the §6.11
      # reentry rendezvous.
      Waiter = Struct.new(:mutex, :cond, :value, :done) do
        def self.create
          new(Mutex.new, ConditionVariable.new, nil, false)
        end
      end

      # §6.13(b) outbound primitive: send a request envelope, await its
      # correlated EXECUTE_RESPONSE (§6.11). Blocks the calling (dispatch worker)
      # thread; the reader routes the response. Returns nil if the connection
      # closes first.
      def outbound(request)
        request_id = request.root.text("request_id") || ""
        waiter = Waiter.create
        @pending_mutex.synchronize { @pending[request_id] = waiter }
        begin
          write_framed(request)
          waiter.mutex.synchronize do
            until waiter.done || @closed
              waiter.cond.wait(waiter.mutex, 0.05)
            end
            waiter.value
          end
        rescue TransportError
          nil
        ensure
          @pending_mutex.synchronize { @pending.delete(request_id) }
        end
      end

      def route_response(env)
        request_id = env.root.text("request_id") || ""
        waiter = @pending_mutex.synchronize { @pending[request_id] }
        return unless waiter

        waiter.mutex.synchronize do
          waiter.value = env
          waiter.done = true
          waiter.cond.signal
        end
      end

      def close
        return if @closed

        @closed = true
        # wake any parked outbound waiters so they return nil
        @pending_mutex.synchronize do
          @pending.each_value do |w|
            w.mutex.synchronize { w.cond.signal }
          end
        end
        begin
          @socket.close
        rescue IOError
          # best-effort
        end
      end
    end

    # The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch
    # on its own Thread (§4.8) + write the response. Returns when the connection
    # closes / a malformed frame ends it.
    def read_loop(peer, conn, io)
      loop do
        payload =
          begin
            io.read_frame
          rescue PayloadTooLargeError
            # §4.10(a): an over-limit frame prefix; we cannot trust the body
            # boundary, so close the connection (the prefix was already consumed).
            break
          rescue TransportError
            break
          end
        break if payload.nil? # clean EOF

        begin
          env = Wire.envelope_of_frame(payload)
        rescue CodecError, ProtocolError
          next # skip a malformed frame
        end

        if env.root.type == "system/protocol/execute/response"
          io.route_response(env)
        else
          Thread.new do
            resp =
              begin
                peer.dispatch(conn, env)
              rescue StandardError
                request_id = env.root.text("request_id") || ""
                Envelope.new(Wire.make_response(request_id, 500, Wire.error_result("internal_error")))
              end
            if resp
              begin
                io.write_framed(resp)
              rescue TransportError
                # write failure ends this exchange; reader keeps going
              end
            end
          end
        end
      end
    ensure
      io.close
    end

    # ── server: listener + accept loop ──────────────────────────────────────────

    # A running listener: the bound port plus a handle to stop it.
    class Listener
      attr_reader :port

      def initialize(server, port, accept_thread)
        @server = server
        @port = port
        @accept_thread = accept_thread
      end

      def close
        @server.close
      rescue IOError
        # best-effort
      ensure
        @accept_thread&.kill
      end
    end

    # Bind 127.0.0.1:port (0 = auto) and spawn the accept loop.
    def start_listener(peer, port)
      server = TCPServer.new("127.0.0.1", port)
      bound = server.addr[1]
      accept = Thread.new do
        loop do
          client =
            begin
              server.accept
            rescue IOError, Errno::EBADF
              break # socket closed → stop
            end
          Thread.new { serve_connection(peer, client) }
        end
      end
      Listener.new(server, bound, accept)
    end

    def serve_connection(peer, client)
      io = Io.new(client)
      conn = Conn.new
      # wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
      conn.outbound = ->(env) { io.outbound(env) }
      read_loop(peer, conn, io)
    rescue StandardError
      begin
        client.close
      rescue IOError
        # best-effort
      end
    end

    # ════════════════════════════════════════════════════════════════════════════
    # Client side — the dialer + initiator handshake (drives the loopback)
    # ════════════════════════════════════════════════════════════════════════════

    # A dialed, authenticated session (§4.4): the IO, the minted cap + granter + sig.
    class Session
      attr_reader :remote_peer_id, :capability

      def initialize(io, local)
        @io = io
        @local = local
        @req_counter = 0
        @counter_mutex = Mutex.new
        @remote_peer_id = nil
        @capability = nil
        @granter_peer = nil
        @cap_signature = nil
      end

      attr_accessor :granter_peer, :cap_signature
      attr_writer :remote_peer_id, :capability

      def next_request_id
        n = @counter_mutex.synchronize { @req_counter += 1 }
        "req-#{n}"
      end

      # Send REQUEST and await its correlated EXECUTE_RESPONSE (request_id demux).
      def send_request(request)
        @io.outbound(request)
      end

      # Build, sign, and send an authenticated EXECUTE; await the response. The
      # full §5.8 authority chain travels in +included+.
      def execute(uri, operation, params, resource = nil)
        exec = Wire.make_execute(next_request_id, uri, operation, params,
                                 author: @local.identity_hash, capability: @capability.content_hash, resource: resource)
        exec_sig = @local.sign(exec)
        inc = [
          Envelope::Included.new(hash: @capability.content_hash, entity: @capability),
          Envelope::Included.new(hash: @granter_peer.content_hash, entity: @granter_peer),
          Envelope::Included.new(hash: @local.identity_hash, entity: @local.peer_entity),
          Envelope::Included.new(hash: @cap_signature.content_hash, entity: @cap_signature),
          Envelope::Included.new(hash: exec_sig.content_hash, entity: exec_sig)
        ]
        send_request(Envelope.new(exec, inc))
      end

      def close
        @io.close
      end
    end

    # Open a client connection to host:port and start its reader thread.
    def dial(initiator, host, port)
      sock = TCPSocket.new(host, port)
      io = Io.new(sock)
      session = Session.new(io, initiator.identity)
      # the client reader: a core responder sends only EXECUTE_RESPONSEs; route
      # them. Wire the outbound seam so a §6.13(b) reentry can drive this socket.
      conn = Conn.new
      conn.outbound = ->(env) { io.outbound(env) }
      Thread.new { read_loop(initiator, conn, io) }
      handshake(session)
      session
    end

    # Drive the §4.1 forward handshake as initiator: hello then authenticate. On
    # success, populate the session with the §4.4 capability the responder minted.
    def handshake(session)
      local = session.instance_variable_get(:@local)
      # ── hello ──
      hello = Entity.make("system/protocol/connect/hello",
                          {
                            "peer_id" => local.peer_id,
                            "nonce" => SecureRandom.bytes(32),
                            "protocols" => ["entity-core/1.0"],
                            "timestamp" => Capability.now_ms,
                            "hash_formats" => ["ecfv1-sha256"],
                            "key_types" => ["ed25519"]
                          })
      r1 = session.send_request(Envelope.new(
        Wire.make_execute(session.next_request_id, "system/protocol/connect", "hello", hello)
      ))
      require_ok(r1, "hello")
      remote_hello = Wire.response_result(r1)
      session.remote_peer_id = remote_hello.text("peer_id")
      remote_nonce = remote_hello.bytes("nonce")

      # ── authenticate ──
      auth = Entity.make("system/protocol/connect/authenticate",
                         {
                           "peer_id" => local.peer_id,
                           "public_key" => local.public_key,
                           "key_type" => "ed25519",
                           "nonce" => remote_nonce
                         })
      auth_sig = local.sign(auth)
      auth_inc = [
        Envelope::Included.new(hash: local.identity_hash, entity: local.peer_entity),
        Envelope::Included.new(hash: auth_sig.content_hash, entity: auth_sig)
      ]
      r2 = session.send_request(Envelope.new(
        Wire.make_execute(session.next_request_id, "system/protocol/connect", "authenticate", auth), auth_inc
      ))
      require_ok(r2, "authenticate")

      # parse the §4.4 initial capability grant
      grant = Wire.response_result(r2)
      token_h = grant.bytes("token")
      token = r2.included_get(token_h)
      raise TransportError, "authenticate grant omits the capability token" if token.nil?

      granter_h = token.bytes("granter")
      granter_peer = r2.included_get(granter_h)
      cap_sig = Capability.find_signature(token.content_hash, r2.included)
      raise TransportError, "authenticate grant omits the granter identity" if granter_peer.nil?
      raise TransportError, "authenticate grant omits the capability signature" if cap_sig.nil?

      session.capability = token
      session.granter_peer = granter_peer
      session.cap_signature = cap_sig
    end

    def require_ok(env, step)
      raise TransportError, "#{step} failed: no response" if env.nil?

      status = Wire.response_status(env)
      return if status == 200

      r = Wire.response_result(env)
      code = r&.text("code")
      msg = r&.text("message")
      raise TransportError, "#{step} failed: #{status} #{code} #{msg}"
    end
  end
end
