# frozen_string_literal: true

require "securerandom"

require_relative "entity"
require_relative "envelope"
require_relative "identity"
require_relative "store"
require_relative "capability"
require_relative "wire"
require_relative "handler"
require_relative "core_types"
require_relative "error"

module EntityCore
  # Peer assembly: bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2:
  # connect, tree, handler, capability), the §6.5 dispatch chain, §6.6
  # resolution, and per-connection state. The pure protocol brain — a function
  # from inbound envelope to outbound response envelope. Transport lives in
  # Transport.
  #
  # Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch chain
  # order (verify → resolve → check-permission → handler), and §4.4 initial-grant
  # delivery are derived directly from V7.
  class Peer
    attr_reader :identity, :store, :local_peer

    def initialize(identity, store, local_peer, open_grants, conformance)
      @identity = identity
      @store = store
      @local_peer = local_peer
      @open_grants = open_grants
      @conformance = conformance
      @handlers = {} # pattern → handler instance
    end

    # ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ───────────────────────

    def random_bytes(n)
      SecureRandom.bytes(n)
    end

    # ── grant construction (§4.4 / §5.4) ──────────────────────────────────────

    def self.scope_cbor(incl, excl = nil)
      excl ? { "include" => incl, "exclude" => excl } : { "include" => incl }
    end

    # Build a grant cbor-map. +peers+ nil → omit (defaults to local at check time).
    def self.grant(handlers, resources, operations, peers = nil)
      g = {
        "handlers" => scope_cbor(handlers),
        "resources" => scope_cbor(resources),
        "operations" => scope_cbor(operations)
      }
      g["peers"] = scope_cbor(peers) if peers
      g
    end

    # The §4.4 discovery floor: every authenticated identity gets at least this.
    def discovery_floor
      [
        self.class.grant(["system/tree"], ["system/type/*", "system/handler/*"], ["get"]),
        self.class.grant(["system/capability"], [], ["request"])
      ]
    end

    # Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants).
    def open_grants_scope
      [self.class.grant(["*"], ["*", "/*/*"], ["*"], ["*"])]
    end

    # Full owner authority over the local namespace /{peer_id}/* (§6.9a).
    def owner_grants
      [self.class.grant(["*"], ["*"], ["*"], [@local_peer])]
    end

    # ── token mint (§4.4 / §6.9a) ─────────────────────────────────────────────

    Minted = Data.define(:token, :signature)

    def mint_token(grantee_hash, grants, parent = nil)
      data = {
        "granter" => @identity.identity_hash,
        "grantee" => grantee_hash,
        "grants" => grants,
        "created_at" => Capability.now_ms
      }
      data["parent"] = parent if parent
      token = Entity.make("system/capability/token", data)
      Minted.new(token: token, signature: @identity.sign(token))
    end

    def cap_included(minted)
      [
        Envelope::Included.new(hash: minted.token.content_hash, entity: minted.token),
        Envelope::Included.new(hash: @identity.identity_hash, entity: @identity.peer_entity),
        Envelope::Included.new(hash: minted.signature.content_hash, entity: minted.signature)
      ]
    end

    # ── §6.9a seed policy (authenticate-time grant derivation) ─────────────────

    def seed_entry_grants(entry)
      case entry.type
      when "system/capability/token"
        sig_path = "/#{@local_peer}/system/signature/#{hex(entry.content_hash)}"
        sgn = @store.get_at(sig_path)
        if sgn && Identity.verify_signature(sgn, @identity.peer_entity)
          Capability.map_list(entry.data_map, "grants") || []
        else
          []
        end
      when "system/capability/policy-entry"
        Capability.map_list(entry.data_map, "grants") || []
      else
        []
      end
    end

    # §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 →
    # default), then UNION the matched scope with the §4.4 discovery floor.
    def derive_seed_grants(remote_peer, remote_peer_id)
      base = "/#{@local_peer}/system/capability/policy/"
      entry = @store.get_at(base + hex(remote_peer.content_hash)) ||
              @store.get_at(base + remote_peer_id) ||
              @store.get_at("#{base}default")
      floor = discovery_floor
      return floor if entry.nil?

      policy = seed_entry_grants(entry)
      return floor if policy.empty?

      floor + policy
    end

    # ══════════════════════════════════════════════════════════════════════════
    # Handlers (duck-typed operation ladders — the dynamic idiom axis)
    # ══════════════════════════════════════════════════════════════════════════

    def self.str_array(exec, key)
      params = exec.entity_field("params")
      params && Capability.text_list(params.data_map, key)
    end

    # §4.1 / §4.6 — the connect handler (hello / authenticate).
    class ConnectHandler < Handler
      op :hello
      op :authenticate

      def initialize(peer)
        super()
        @peer = peer
      end

      def op_hello(ctx)
        conn = ctx.conn
        exec = ctx.exec
        return Outcome.err(409, "connection_already_established") if conn.established

        # §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        hf = Peer.str_array(exec, "hash_formats")
        hash_ok = hf.nil? || hf.include?("ecfv1-sha256")
        kt = Peer.str_array(exec, "key_types")
        key_ok = kt.nil? || kt.include?("ed25519")
        return Outcome.err(400, "incompatible_hash_format") unless hash_ok
        return Outcome.err(400, "unsupported_key_type") unless key_ok

        params = exec.entity_field("params")
        initiator = params&.text("peer_id")
        nonce = @peer.random_bytes(32)
        conn.hello_peer_id = initiator
        conn.issued_nonce = nonce
        Outcome.ok(Entity.make("system/protocol/connect/hello",
                               {
                                 "peer_id" => @peer.local_peer,
                                 "nonce" => nonce,
                                 "protocols" => ["entity-core/1.0"],
                                 "timestamp" => Capability.now_ms,
                                 "hash_formats" => ["ecfv1-sha256"],
                                 "key_types" => ["ed25519"]
                               }))
      end

      def op_authenticate(ctx)
        conn = ctx.conn
        exec = ctx.exec
        return Outcome.err(409, "connection_already_established") if conn.established
        return Outcome.err(401, "invalid_nonce") if conn.issued_nonce.nil? # authenticate before hello

        auth = exec.entity_field("params")
        return Outcome.err(401, "authentication_failed") if auth.nil?

        # §4.6 hardening: reject unsupported key_type / non-32-byte pubkey /
        # non-ed25519 peer_id.
        kt_field = auth.text("key_type")
        bad_kt = !kt_field.nil? && kt_field != "ed25519"
        pub = auth.bytes("public_key")
        bad_kt = true if !bad_kt && pub && pub.bytesize != 32
        claimed = auth.text("peer_id")
        if !bad_kt && claimed
          begin
            key_type, = PeerId.parse(claimed)
            bad_kt = true unless key_type == 1 # ed25519
          rescue StandardError
            # unparseable peer_id → fall through to the step checks below
          end
        end
        return Outcome.err(400, "unsupported_key_type") if bad_kt

        echoed = auth.bytes("nonce")
        # step 1: nonce-echo
        return Outcome.err(401, "invalid_nonce") unless echoed && echoed == conn.issued_nonce
        return Outcome.err(401, "authentication_failed") if pub.nil?

        # step 2: proof of possession
        sgn = Capability.find_signature(auth.content_hash, ctx.included)
        sig_ok = false
        if sgn
          sb = sgn.bytes("signature")
          sig_ok = Signature.verify_raw(pub, auth.content_hash, sb, :ed25519) if sb
        end
        return Outcome.err(401, "authentication_failed") unless sig_ok

        # step 3: identity binding
        return Outcome.err(401, "identity_mismatch") unless claimed && claimed == Identity.peer_id_of_public_key(pub)
        return Outcome.err(401, "identity_mismatch") if conn.hello_peer_id && conn.hello_peer_id != claimed

        # success: mint the initial capability for the remote (§4.4 / §6.9a)
        remote_peer = Identity.peer_entity_of_public_key(pub)
        grants = @peer.derive_seed_grants(remote_peer, claimed)
        minted = @peer.mint_token(remote_peer.content_hash, grants, nil)
        conn.established = true
        Outcome.ok(
          Entity.make("system/capability/grant", { "token" => minted.token.content_hash }),
          @peer.cap_included(minted)
        )
      end
    end

    # §6.3 — the tree handler (get / put).
    class TreeHandler < Handler
      op :get
      op :put

      def initialize(peer)
        super()
        @peer = peer
        @store = peer.store
        @local_peer = peer.local_peer
      end

      def op_get(ctx)
        exec = ctx.exec
        target = Peer.exec_resource_target(exec)
        return Outcome.err(400, "invalid_path", target) if target && !Peer.path_flex_ok?(target)
        return @peer.build_listing("/#{@local_peer}/") if target.nil?
        return @peer.build_listing(Capability.canonicalize(@local_peer, target)) if target.empty? || target.end_with?("/")

        path = Capability.canonicalize(@local_peer, target)
        e = @store.get_at(path)
        return Outcome.err(404, "not_found", path) if e.nil?

        params = exec.entity_field("params")
        mode = params&.text("mode")
        return Outcome.ok(Entity.make("system/hash", { "hash" => e.content_hash })) if mode == "hash"

        Outcome.ok(e)
      end

      def op_put(ctx)
        exec = ctx.exec
        target = Peer.exec_resource_target(exec)
        return Outcome.err(400, "ambiguous_resource", "tree: missing resource target") if target.nil?
        return Outcome.err(400, "invalid_path", target) unless Peer.path_flex_ok?(target)

        path = Capability.canonicalize(@local_peer, target)
        params = exec.entity_field("params")
        entity = params&.entity_field("entity")
        expected = params&.bytes("expected_hash")
        return Outcome.err(400, "unexpected_params", "put: missing entity") if entity.nil?

        # §3.9 compare-and-swap, atomic in the store under one critical section.
        if @store.bind_cas(path, entity, expected)
          Outcome.ok(Entity.make("system/hash", { "hash" => entity.content_hash }))
        else
          Outcome.err(409, "hash_mismatch", path)
        end
      end
    end

    # §6.2 — the capability handler (request / delegate / revoke / configure).
    class CapabilityHandler < Handler
      op :request
      op :delegate
      op :revoke
      op :configure

      def initialize(peer)
        super()
        @peer = peer
        @store = peer.store
        @local_peer = peer.local_peer
        @identity = peer.identity
      end

      def op_request(ctx)
        exec = ctx.exec
        params = exec.entity_field("params")
        author = exec.bytes("author")
        return Outcome.err(403, "capability_denied") if author.nil?

        mint_bounded(ctx.caller_cap, Peer.req_grants(params), author, nil)
      end

      def op_delegate(ctx)
        exec = ctx.exec
        params = exec.entity_field("params")
        author = exec.bytes("author")
        ph = params&.bytes("parent")
        return Outcome.err(400, "unexpected_params", "delegate: parent required") if ph.nil?
        return Outcome.err(400, "unexpected_params", "delegate: zero parent") if Peer.zero_hash?(ph)
        unless author && author == @identity.identity_hash
          return Outcome.err(501, "unsupported_operation", "delegate: same-peer-only in v1")
        end

        mint_bounded(ctx.caller_cap, Peer.req_grants(params), author, ph)
      end

      def op_revoke(ctx)
        exec = ctx.exec
        params = exec.entity_field("params")
        token_h = params&.bytes("token")
        return Outcome.err(400, "unexpected_params", "revoke: missing token") if token_h.nil?
        return Outcome.err(400, "unexpected_params", "revoke: zero token") if Peer.zero_hash?(token_h)

        marker = Entity.make("system/capability/revocation",
                             { "token" => token_h, "revoked_at" => Capability.now_ms })
        @store.bind("/#{@local_peer}/system/capability/revocations/#{Peer.hex(token_h)}", marker)
        Outcome.ok(Wire.empty_params)
      end

      def op_configure(ctx)
        exec = ctx.exec
        params = exec.entity_field("params")
        pp = params&.text("peer_pattern")
        return Outcome.err(400, "unexpected_params", "configure: missing peer_pattern") if pp.nil?

        is_hex = pp.length == 66 && pp.each_char.all? { |c| c =~ /[0-9a-f]/ }
        unless pp == "default" || is_hex || Capability.peer_id?(pp)
          return Outcome.err(400, "invalid_peer_pattern", pp)
        end

        @store.bind("/#{@local_peer}/system/capability/policy/#{pp}", params)
        Outcome.ok(Wire.empty_params)
      end

      def mint_bounded(caller_cap, req_grants, grantee_hash, parent)
        bounded = false
        if caller_cap
          parent_grants = Capability.grants_of_token(caller_cap)
          bounded = true
          req_grants.each do |cg_raw|
            c = Capability.parse_grant(cg_raw)
            # self-issued mint: granter = local → both frames local.
            some = parent_grants.any? { |pg| Capability.grant_subset(@local_peer, @local_peer, @local_peer, c, pg) }
            unless some
              bounded = false
              break
            end
          end
        end
        return Outcome.err(403, "scope_exceeds_authority") unless bounded

        minted = @peer.mint_token(grantee_hash, req_grants, parent)
        Outcome.ok(
          Entity.make("system/capability/grant", { "token" => minted.token.content_hash }),
          @peer.cap_included(minted)
        )
      end
    end

    # §6.2 / §6.13(a) — the handlers handler (register / unregister).
    class HandlersHandler < Handler
      op :register
      op :unregister

      def initialize(peer)
        super()
        @peer = peer
        @store = peer.store
        @local_peer = peer.local_peer
        @identity = peer.identity
      end

      def op_register(ctx)
        exec = ctx.exec
        pattern = Peer.register_pattern(exec)
        return Peer.register_pattern_error(exec) if pattern.nil?

        req = exec.entity_field("params")
        return Outcome.err(400, "unexpected_params", "register: missing params") if req.nil?
        unless req.type == "system/handler/register-request"
          return Outcome.err(400, "unexpected_params", "register expects register-request, got #{req.type}")
        end

        manifest = req.map_field("manifest") || {}
        name = manifest["name"]
        name = pattern unless name.is_a?(::String) && name.encoding != Encoding::BINARY
        operations = Capability.as_map(manifest["operations"]) || {}
        expr_path = manifest["expression_path"]
        expr_path = nil unless expr_path.is_a?(::String) && expr_path.encoding != Encoding::BINARY
        internal_scope = manifest["internal_scope"]
        grant_scope = Capability.map_list(req.data_map, "requested_scope")
        grant_scope ||= internal_scope.is_a?(::Array) ? Capability.map_list(req.data_map, "internal_scope") : nil
        grant_scope ||= []

        interface_rel = "system/handler/#{pattern}"
        # (1) handler manifest at the pattern path
        hp = { "interface" => interface_rel }
        hp["expression_path"] = expr_path if expr_path
        hp["internal_scope"] = internal_scope unless internal_scope.nil?
        @store.bind(abs(pattern), Entity.make("system/handler", hp))
        # (2) associated types at system/type/{type_name}
        types = req.map_field("types")
        if types
          types.each do |tk, tv|
            next unless tk.is_a?(::String) && tk.encoding != Encoding::BINARY

            td = tv.is_a?(::Hash) ? tv : { "def" => tv }
            @store.bind(abs("system/type/#{tk}"), Entity.make("system/type", td))
          end
        end
        # (3) self-issued signed handler grant + (4) grant-signature at §3.5
        minted = @peer.mint_token(@identity.identity_hash, grant_scope, nil)
        @store.bind(abs("system/capability/grants/#{pattern}"), minted.token)
        @store.bind(abs("system/signature/#{Peer.hex(minted.token.content_hash)}"), minted.signature)
        # (5) handler interface entity (discovery index)
        @store.bind(abs(interface_rel), Entity.make("system/handler/interface",
                                                    { "pattern" => pattern, "name" => name, "operations" => operations }))
        Outcome.ok(Entity.make("system/handler/register-result",
                               { "pattern" => pattern, "grant" => minted.token.data }))
      end

      def op_unregister(ctx)
        exec = ctx.exec
        pattern = Peer.register_pattern(exec)
        return Peer.register_pattern_error(exec) if pattern.nil?

        g = @store.get_at(abs("system/capability/grants/#{pattern}"))
        if g
          @store.unbind(abs("system/signature/#{Peer.hex(g.content_hash)}"))
          @store.unbind(abs("system/capability/grants/#{pattern}"))
        end
        @store.unbind(abs(pattern))
        @store.unbind(abs("system/handler/#{pattern}"))
        Outcome.ok(Wire.empty_params)
      end

      private

      def abs(rel)
        "/#{@local_peer}/#{rel}"
      end
    end

    # §7a conformance handler: echo (the §6.13(a) resolve→dispatch half).
    class EchoHandler < Handler
      op :echo

      def initialize(_peer = nil)
        super()
      end

      def op_echo(ctx)
        p = ctx.params
        p ? Outcome.ok(p) : Outcome.err(400, "invalid_params", "echo requires a params entity")
      end
    end

    # §7a conformance handler: dispatch-outbound (the §6.13(b)/§6.11 outbound seam).
    class DispatchOutboundHandler < Handler
      op :dispatch

      def initialize(peer)
        super()
        @peer = peer
      end

      def op_dispatch(ctx)
        p = ctx.params
        return Outcome.err(400, "invalid_params", "dispatch-outbound requires a params entity") if p.nil?

        target = p.text("target") || ""
        operation = p.text("operation") || ""
        value = p.field("value")
        capability = p.entity_field("reentry_capability")
        granter_peer = p.entity_field("reentry_granter")
        cap_sig = p.entity_field("reentry_cap_signature")
        unless value && capability && granter_peer && cap_sig
          return Outcome.err(400, "invalid_params", "dispatch-outbound requires value + reentry authority")
        end

        # §7a.1 generic relay: the `value` field is the bytes of the downstream's
        # params entity data and MUST be forwarded verbatim, never re-wrapped.
        inner_data = value.is_a?(::Hash) ? value : { "value" => value }
        inner = Entity.make("primitive/any", inner_data)
        resource = Wire.resource_target("system/handler/#{target}")
        env = @peer.outbound_dispatch(ctx.conn, target, operation, inner, capability, granter_peer, cap_sig, resource)
        return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection") if env.nil?

        status = env.root.uint("status")
        result_cbor = env.root.field("result") || {}
        Outcome.ok(Entity.make("primitive/any", { "status" => status || 0, "result" => result_cbor }))
      end
    end

    # ── §6.13(b) handler-facing outbound dispatch ──────────────────────────────

    def outbound_dispatch(conn, uri, operation, params, capability, granter_peer, cap_sig, resource)
      send_fn = conn.outbound
      return nil if send_fn.nil?

      request_id = "out-#{conn.next_out_counter}"
      exec = Wire.make_execute(request_id, uri, operation, params,
                               author: @identity.identity_hash, capability: capability.content_hash, resource: resource)
      exec_sig = @identity.sign(exec)
      included = [
        Envelope::Included.new(hash: capability.content_hash, entity: capability),
        Envelope::Included.new(hash: granter_peer.content_hash, entity: granter_peer),
        Envelope::Included.new(hash: @identity.identity_hash, entity: @identity.peer_entity),
        Envelope::Included.new(hash: cap_sig.content_hash, entity: cap_sig),
        Envelope::Included.new(hash: exec_sig.content_hash, entity: exec_sig)
      ]
      send_fn.call(Envelope.new(exec, included))
    end

    # ── tree listing (§3.9) ────────────────────────────────────────────────────

    def build_listing(path)
      rows = @store.listing(path).reject do |row|
        row.hash_hex && !row.has_children && deletion_marker?(unhex(row.hash_hex))
      end
      entries = {}
      rows.each do |row|
        data =
          if row.hash_hex
            { "has_children" => row.has_children, "hash" => unhex(row.hash_hex) }
          else
            { "has_children" => row.has_children }
          end
        entries[row.segment] = Entity.make("system/tree/listing-entry", data).to_cbor
      end
      Outcome.ok(Entity.make("system/tree/listing",
                             { "path" => path, "entries" => entries, "count" => rows.length, "offset" => 0 }))
    end

    def deletion_marker?(hash)
      e = @store.get_by_hash(hash)
      e && e.type == "system/deletion-marker"
    end

    # ── dispatcher-level signature ingestion (§6.5) ────────────────────────────

    def ingest_signatures(env)
      env.included.each do |pair|
        e = pair.entity
        next unless e.type == "system/signature"

        @store.put_entity(e)
        signer_h = e.bytes("signer")
        next if signer_h.nil?

        signer_peer = env.included_get(signer_h)
        next if signer_peer.nil?

        @store.put_entity(signer_peer)
        target = e.bytes("target")
        pk = signer_peer.bytes("public_key")
        next unless target && pk

        pid = Identity.peer_id_of_public_key(pk)
        @store.bind("/#{pid}/system/signature/#{hex(target)}", e)
      end
    end

    # ── handler resolution (§6.6) — backward tree-walk ─────────────────────────

    # Return the longest prefix of +path+ bound to a system/handler entity, or nil.
    def resolve_handler(path)
      segs = path.split("/", -1)
      segs.length.downto(1) do |i|
        prefix = segs[0, i].join("/")
        e = @store.get_at(prefix)
        return prefix if e && e.type == "system/handler"
      end
      nil
    end

    def strip_local(pattern)
      prefix = "/#{@local_peer}/"
      pattern.start_with?(prefix) ? pattern[prefix.length..] : pattern
    end

    # ── entity-native dispatch (v7.74 §6.13(a)) ────────────────────────────────

    def entity_native_dispatch(handler_path)
      he = @store.get_at(handler_path)
      return Outcome.err(404, "handler_not_found", handler_path) if he.nil?

      expr_path = he.text("expression_path")
      return Outcome.err(501, "no_handler_body", handler_path) if expr_path.nil?

      abs = Capability.canonicalize(@local_peer, expr_path)
      expr = @store.get_at(abs)
      return Outcome.err(404, "expression_not_found", abs) if expr.nil?

      if expr.type == "compute/literal"
        value = expr.field("value")
        return Outcome.err(400, "unexpected_params", "compute/literal missing value") if value.nil?

        Outcome.ok(Entity.make("compute/result", { "value" => value, "expression" => expr.content_hash }))
      else
        Outcome.err(501, "unsupported_expression", expr.type)
      end
    end

    # ── dispatch chain (§6.5) ──────────────────────────────────────────────────

    # The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or nil for a
    # non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
    def dispatch(conn, env)
      exec = env.root
      return nil unless exec.type == "system/protocol/execute"

      request_id = exec.text("request_id") || ""
      outcome =
        begin
          dispatch_inner(conn, env, exec)
        rescue UnresolvableGranteeError
          Outcome.err(401, "unresolvable_grantee")
        rescue PayloadTooLargeError
          Outcome.err(413, "payload_too_large")
        rescue StandardError => e
          warn "#{e.class}: #{e.message}\n#{e.backtrace&.first(8)&.join("\n")}" if ENV["PEER_DEBUG_500"]
          Outcome.err(500, "internal_error")
        end
      Envelope.new(Wire.make_response(request_id, outcome.status, outcome.result), outcome.included)
    end

    def dispatch_inner(conn, env, exec)
      uri = exec.text("uri") || ""
      operation = exec.text("operation") || ""
      if uri == "system/protocol/connect"
        return @handlers["system/protocol/connect"].handle(
          operation, HandlerContext.new(exec: exec, conn: conn, included: env.included, caller_cap: nil, env: env)
        )
      end

      ingest_signatures(env)
      case Capability.verify_request(@local_peer, @store, env)
      when :authn_fail then return Outcome.err(401, "authentication_failed")
      when :authz_deny then return Outcome.err(403, "capability_denied")
      when :chain_too_deep then return Outcome.err(400, "chain_depth_exceeded")
      end

      path = Capability.canonicalize(@local_peer, Capability.normalize_uri(uri))
      # §1.4: inbound dispatch must target the local peer.
      return Outcome.err(404, "handler_not_found", "not local peer") unless Capability.extract_peer(@local_peer, path) == @local_peer

      pattern = resolve_handler(path)
      return Outcome.err(404, "handler_not_found", path) if pattern.nil?

      cap_h = exec.bytes("capability")
      caller_cap = cap_h ? env.included_get(cap_h) : nil
      return Outcome.err(403, "capability_denied") if caller_cap.nil?

      resolve_fn = ->(h) { Capability.cap_resolve(env.included, @store, h) }
      granter_peer = Capability.resolve_granter_peer_id(resolve_fn, caller_cap) || @local_peer
      if Capability.check_permission(@local_peer, granter_peer, exec, caller_cap, pattern) == :deny
        return Outcome.err(403, "capability_denied")
      end

      stripped = strip_local(pattern)
      inst = @handlers[stripped]
      if inst
        inst.handle(operation, HandlerContext.new(exec: exec, conn: conn, included: env.included, caller_cap: caller_cap, env: env))
      else
        entity_native_dispatch(pattern)
      end
    end

    # ── bootstrap (§6.9) ───────────────────────────────────────────────────────

    def self.op_spec(input, output)
      h = {}
      h["input_type"] = input if input
      h["output_type"] = output if output
      h
    end

    def bootstrap_handler_entities(pattern, name, ops)
      operations = {}
      ops.each { |op, input, output| operations[op] = self.class.op_spec(input, output) }
      @store.bind("/#{@local_peer}/#{pattern}", Entity.make("system/handler", { "interface" => "system/handler/#{pattern}" }))
      @store.bind("/#{@local_peer}/system/handler/#{pattern}",
                  Entity.make("system/handler/interface", { "pattern" => pattern, "name" => name, "operations" => operations }))
      minted = mint_token(@identity.identity_hash, [], nil)
      @store.bind("/#{@local_peer}/system/capability/grants/#{pattern}", minted.token)
    end

    # Construct + bootstrap a peer from a 32-byte Ed25519 seed.
    def self.create(seed, open_grants: false, conformance: false)
      identity = Identity.of_seed(seed)
      store = Store.new
      local = identity.peer_id
      peer = new(identity, store, local, open_grants, conformance)

      # local identity entity in the store (root-granter resolution)
      store.put_entity(identity.peer_entity)
      # publish the core type floor (S3 minimal subset; full 53 at S4)
      CoreTypes.publish(store, local)

      bootstrap = [
        ["system/tree", TreeHandler.new(peer), "Tree", [["get", nil, nil], ["put", nil, nil]]],
        ["system/handler", HandlersHandler.new(peer), "Handlers",
         [["register", "system/handler/register-request", "system/handler/register-result"],
          ["unregister", "system/handler/unregister-request", nil]]],
        ["system/capability", CapabilityHandler.new(peer), "Capability",
         [["request", "system/capability/request", "system/capability/grant"],
          ["revoke", "system/capability/revoke-request", nil],
          ["configure", "system/capability/policy-entry", nil],
          ["delegate", "system/capability/delegate-request", "system/capability/grant"]]],
        ["system/protocol/connect", ConnectHandler.new(peer), "Connect",
         [["hello", nil, nil], ["authenticate", nil, nil]]]
      ]
      bootstrap.each do |pattern, handler, name, ops|
        peer.instance_variable_get(:@handlers)[pattern] = handler
        peer.bootstrap_handler_entities(pattern, name, ops)
      end

      # §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap + default
      # scope-template entry. Read back by authenticate (dual-form lookup).
      policy_base = "/#{local}/system/capability/policy/"
      owner = peer.mint_token(identity.identity_hash, peer.owner_grants, nil)
      store.bind(policy_base + hex(identity.identity_hash), owner.token)
      store.bind("/#{local}/system/signature/#{hex(owner.token.content_hash)}", owner.signature)
      default_grants = open_grants ? peer.open_grants_scope : peer.discovery_floor
      default_entry = Entity.make("system/capability/policy-entry",
                                  { "peer_pattern" => "default", "grants" => default_grants })
      store.bind("#{policy_base}default", default_entry)

      # §7a conformance handlers — only bootstrapped under --validate
      if conformance
        conf = [
          ["system/validate/echo", EchoHandler.new, "validate-echo", [["echo", nil, nil]]],
          ["system/validate/dispatch-outbound", DispatchOutboundHandler.new(peer), "validate-dispatch-outbound", [["dispatch", nil, nil]]]
        ]
        conf.each do |pattern, handler, name, ops|
          peer.instance_variable_get(:@handlers)[pattern] = handler
          peer.bootstrap_handler_entities(pattern, name, ops)
        end
      end
      peer
    end

    # ── small helpers ──────────────────────────────────────────────────────────

    def self.exec_resource_target(exec)
      r = exec.map_field("resource")
      return nil if r.nil?

      targets = Capability.text_list(r, "targets")
      targets && !targets.empty? ? targets.first : nil
    end

    def self.path_flex_ok?(target)
      return false if target.include?(" ")

      segs0 = target.split("/", -1)
      if target.start_with?("/")
        if segs0.length >= 2 && segs0[0].empty?
          abs_ok = Capability.peer_id?(segs0[1])
          body = segs0[1..]
        else
          abs_ok = false
          body = segs0
        end
      else
        abs_ok = true
        body = segs0
      end
      return false unless abs_ok

      body = body[0...-1] if !body.empty? && body.last.empty?
      body.none? { |s| s.empty? || s == "." || s == ".." }
    end

    def self.zero_hash?(h)
      h.each_byte.all?(&:zero?)
    end

    def self.req_grants(params)
      return [] if params.nil?

      Capability.map_list(params.data_map, "grants") || []
    end

    def self.register_pattern(exec)
      target = exec_resource_target(exec)
      return nil if target.nil?

      prefix = "system/handler/"
      return nil if !target.start_with?(prefix) || target.length == prefix.length

      target[prefix.length..]
    end

    def self.register_pattern_error(exec)
      target = exec_resource_target(exec)
      if target.nil?
        Outcome.err(400, "ambiguous_resource", "register/unregister require exactly one resource target")
      else
        Outcome.err(400, "invalid_resource", "resource target MUST be system/handler/{pattern}")
      end
    end

    def self.hex(bytes)
      bytes.b.unpack1("H*")
    end

    def hex(bytes)
      bytes.b.unpack1("H*")
    end

    def unhex(str)
      [str].pack("H*").b
    end
  end
end
