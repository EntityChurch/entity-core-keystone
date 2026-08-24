require "./peer"
require "./handler"
require "./capability"
require "./peer_id"
require "./signature"
require "./wire"

module EntityCore
  class Peer
    # §4.1 / §4.6 — the connect handler (hello / authenticate).
    class ConnectHandler < Handler
      def initialize(@peer : Peer)
      end

      def handle(operation : String, ctx : HandlerContext) : Outcome
        case operation
        when "hello"        then op_hello(ctx)
        when "authenticate" then op_authenticate(ctx)
        else
          Outcome.err(501, "unsupported_operation", operation)
        end
      end

      private def op_hello(ctx : HandlerContext) : Outcome
        conn = ctx.conn
        exec = ctx.exec
        return Outcome.err(409, "connection_already_established") if conn.established

        # §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        hf = Peer.str_array(exec, "hash_formats")
        hash_ok = hf.nil? || hf.includes?("ecfv1-sha256")
        kt = Peer.str_array(exec, "key_types")
        key_ok = kt.nil? || kt.includes?("ed25519")
        return Outcome.err(400, "incompatible_hash_format") unless hash_ok
        return Outcome.err(400, "unsupported_key_type") unless key_ok

        params = exec.entity_field("params")
        initiator = params.try &.text("peer_id")
        nonce = @peer.random_bytes(32)
        conn.hello_peer_id = initiator
        conn.issued_nonce = nonce

        data = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        data["peer_id"] = @peer.local_peer
        data["nonce"] = nonce
        data["protocols"] = ["entity-core/1.0".as(Cbor::EcValue)]
        data["timestamp"] = Cbor::EcInt.from(Capability.now_ms)
        data["hash_formats"] = ["ecfv1-sha256".as(Cbor::EcValue)]
        data["key_types"] = ["ed25519".as(Cbor::EcValue)]
        Outcome.ok(Entity.make("system/protocol/connect/hello", data))
      end

      private def op_authenticate(ctx : HandlerContext) : Outcome
        conn = ctx.conn
        exec = ctx.exec
        # RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
        # single-use nonce. The anti-replay property is the MUST and the
        # mechanism (established-state tracking) is impl-defined, but the
        # STATUS is pinned to 401 invalid_nonce — a 409 state-conflict
        # under-signals the replay.
        return Outcome.err(401, "invalid_nonce") if conn.established
        return Outcome.err(401, "invalid_nonce") if conn.issued_nonce.nil? # authenticate before hello

        auth = exec.entity_field("params")
        return Outcome.err(401, "authentication_failed") if auth.nil?

        # §4.6 hardening: reject unsupported key_type / non-32-byte pubkey /
        # non-ed25519 peer_id.
        kt_field = auth.text("key_type")
        bad_kt = !kt_field.nil? && kt_field != "ed25519"
        pub = auth.bytes("public_key")
        bad_kt = true if !bad_kt && pub && pub.size != 32
        claimed = auth.text("peer_id")
        if !bad_kt && claimed
          begin
            key_type, _, _ = PeerId.parse(claimed)
            bad_kt = true unless key_type == 1_u64 # ed25519
          rescue
            # unparseable peer_id → fall through to the step checks below
          end
        end
        return Outcome.err(400, "unsupported_key_type") if bad_kt

        echoed = auth.bytes("nonce")
        issued = conn.issued_nonce
        # step 1: nonce-echo
        return Outcome.err(401, "invalid_nonce") unless echoed && issued && echoed == issued
        return Outcome.err(401, "authentication_failed") if pub.nil?

        # step 2: proof of possession
        sgn = Capability.find_signature(auth.content_hash, ctx.included)
        sig_ok = false
        if sgn
          sb = sgn.bytes("signature")
          sig_ok = Signature.verify_raw(pub, auth.content_hash, sb) if sb
        end
        return Outcome.err(401, "authentication_failed") unless sig_ok

        # step 3: identity binding
        return Outcome.err(401, "identity_mismatch") unless claimed && claimed == Identity.peer_id_of_public_key(pub)
        hp = conn.hello_peer_id
        return Outcome.err(401, "identity_mismatch") if hp && hp != claimed

        # success: mint the initial capability for the remote (§4.4 / §6.9a)
        remote_peer = Identity.peer_entity_of_public_key(pub)
        grants = @peer.derive_seed_grants(remote_peer, claimed)
        minted = @peer.mint_token(remote_peer.content_hash, grants, nil)
        conn.established = true
        gdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        gdata["token"] = minted.token.content_hash
        Outcome.ok(Entity.make("system/capability/grant", gdata), @peer.cap_included(minted))
      end
    end

    # §6.3 — the tree handler (get / put).
    class TreeHandler < Handler
      def initialize(@peer : Peer)
        @store = peer.store
        @local_peer = peer.local_peer
      end

      def handle(operation : String, ctx : HandlerContext) : Outcome
        case operation
        when "get" then op_get(ctx)
        when "put" then op_put(ctx)
        else
          Outcome.err(501, "unsupported_operation", operation)
        end
      end

      private def op_get(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        target = Peer.exec_resource_target(exec)
        return Outcome.err(400, "invalid_path", target) if target && !Peer.path_flex_ok?(target)
        return @peer.build_listing("/#{@local_peer}/") if target.nil?
        return @peer.build_listing(Capability.canonicalize(@local_peer, target)) if target.empty? || target.ends_with?("/")

        path = Capability.canonicalize(@local_peer, target)
        e = @store.get_at(path)
        return Outcome.err(404, "not_found", path) if e.nil?

        params = exec.entity_field("params")
        mode = params.try &.text("mode")
        if mode == "hash"
          hdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
          hdata["hash"] = e.content_hash
          return Outcome.ok(Entity.make("system/hash", hdata))
        end
        Outcome.ok(e)
      end

      private def op_put(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        target = Peer.exec_resource_target(exec)
        return Outcome.err(400, "ambiguous_resource", "tree: missing resource target") if target.nil?
        return Outcome.err(400, "invalid_path", target) unless Peer.path_flex_ok?(target)

        path = Capability.canonicalize(@local_peer, target)
        params = exec.entity_field("params")
        entity = params.try &.entity_field("entity")
        expected = params.try &.bytes("expected_hash")
        return Outcome.err(400, "unexpected_params", "put: missing entity") if entity.nil?

        # §3.9 compare-and-swap, atomic in the store.
        if @store.bind_cas(path, entity, expected)
          hdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
          hdata["hash"] = entity.content_hash
          Outcome.ok(Entity.make("system/hash", hdata))
        else
          Outcome.err(409, "hash_mismatch", path)
        end
      end
    end

    # §6.2 — the capability handler (request / delegate / revoke / configure).
    class CapabilityHandler < Handler
      def initialize(@peer : Peer)
        @store = peer.store
        @local_peer = peer.local_peer
        @identity = peer.identity
      end

      def handle(operation : String, ctx : HandlerContext) : Outcome
        case operation
        when "request"   then op_request(ctx)
        when "delegate"  then op_delegate(ctx)
        when "revoke"    then op_revoke(ctx)
        when "configure" then op_configure(ctx)
        else
          Outcome.err(501, "unsupported_operation", operation)
        end
      end

      private def op_request(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        params = exec.entity_field("params")
        author = exec.bytes("author")
        return Outcome.err(403, "capability_denied") if author.nil?
        mint_bounded(ctx.caller_cap, Peer.req_grants(params), author, nil)
      end

      private def op_delegate(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        params = exec.entity_field("params")
        author = exec.bytes("author")
        ph = params.try &.bytes("parent")
        return Outcome.err(400, "unexpected_params", "delegate: parent required") if ph.nil?
        return Outcome.err(400, "unexpected_params", "delegate: zero parent") if Peer.zero_hash?(ph)
        unless author && author == @identity.identity_hash
          return Outcome.err(501, "unsupported_operation", "delegate: same-peer-only in v1")
        end
        mint_bounded(ctx.caller_cap, Peer.req_grants(params), author, ph)
      end

      private def op_revoke(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        params = exec.entity_field("params")
        token_h = params.try &.bytes("token")
        return Outcome.err(400, "unexpected_params", "revoke: missing token") if token_h.nil?
        return Outcome.err(400, "unexpected_params", "revoke: zero token") if Peer.zero_hash?(token_h)

        mdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        mdata["token"] = token_h
        mdata["revoked_at"] = Cbor::EcInt.from(Capability.now_ms)
        marker = Entity.make("system/capability/revocation", mdata)
        @store.bind("/#{@local_peer}/system/capability/revocations/#{token_h.hexstring}", marker)
        Outcome.ok(Wire.empty_params)
      end

      private def op_configure(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        params = exec.entity_field("params")
        pp = params.try &.text("peer_pattern")
        return Outcome.err(400, "unexpected_params", "configure: missing peer_pattern") if pp.nil?

        is_hex = pp.size == 66 && pp.each_char.all? { |c| ('0'..'9').includes?(c) || ('a'..'f').includes?(c) }
        unless pp == "default" || is_hex || Capability.peer_id?(pp)
          return Outcome.err(400, "invalid_peer_pattern", pp)
        end
        @store.bind("/#{@local_peer}/system/capability/policy/#{pp}", params.not_nil!)
        Outcome.ok(Wire.empty_params)
      end

      private def mint_bounded(caller_cap : Entity?, req_grants : Array(Cbor::EcValue),
                               grantee_hash : Bytes, parent : Bytes?) : Outcome
        bounded = false
        if caller_cap
          parent_grants = Capability.grants_of_token(caller_cap)
          bounded = true
          req_grants.each do |cg_raw|
            m = cg_raw.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
            next unless m
            c = Capability.parse_grant(m)
            some = parent_grants.any? { |pg| Capability.grant_subset(@local_peer, @local_peer, @local_peer, c, pg) }
            unless some
              bounded = false
              break
            end
          end
        end
        return Outcome.err(403, "scope_exceeds_authority") unless bounded

        minted = @peer.mint_token(grantee_hash, req_grants, parent)
        gdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        gdata["token"] = minted.token.content_hash
        Outcome.ok(Entity.make("system/capability/grant", gdata), @peer.cap_included(minted))
      end
    end

    # §6.2 / §6.13(a) — the handlers handler (register / unregister).
    class HandlersHandler < Handler
      def initialize(@peer : Peer)
        @store = peer.store
        @local_peer = peer.local_peer
        @identity = peer.identity
      end

      def handle(operation : String, ctx : HandlerContext) : Outcome
        case operation
        when "register"   then op_register(ctx)
        when "unregister" then op_unregister(ctx)
        else
          Outcome.err(501, "unsupported_operation", operation)
        end
      end

      private def abs(rel : String) : String
        "/#{@local_peer}/#{rel}"
      end

      private def op_register(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        pattern = Peer.register_pattern(exec)
        return Peer.register_pattern_error(exec) if pattern.nil?

        req = exec.entity_field("params")
        return Outcome.err(400, "unexpected_params", "register: missing params") if req.nil?
        unless req.type == "system/handler/register-request"
          return Outcome.err(400, "unexpected_params", "register expects register-request, got #{req.type}")
        end

        manifest = req.map_field("manifest") || ::Hash(Cbor::EcValue, Cbor::EcValue).new
        name_v = manifest["name"]?
        name = name_v.as?(String) || pattern
        operations = manifest["operations"]?.as?(::Hash(Cbor::EcValue, Cbor::EcValue)) || ::Hash(Cbor::EcValue, Cbor::EcValue).new
        expr_path = manifest["expression_path"]?.as?(String)
        internal_scope = manifest["internal_scope"]?

        grant_scope = Capability.map_list(req.data_map, "requested_scope").try(&.map(&.as(Cbor::EcValue)))
        if grant_scope.nil? && internal_scope.is_a?(Array(Cbor::EcValue))
          grant_scope = Capability.map_list(req.data_map, "internal_scope").try(&.map(&.as(Cbor::EcValue)))
        end
        grant_scope ||= [] of Cbor::EcValue

        interface_rel = "system/handler/#{pattern}"
        # (1) handler manifest at the pattern path
        hp = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        hp["interface"] = interface_rel
        hp["expression_path"] = expr_path if expr_path
        hp["internal_scope"] = internal_scope unless internal_scope.nil?
        @store.bind(abs(pattern), Entity.make("system/handler", hp))

        # (2) associated types at system/type/{type_name}
        types = req.map_field("types")
        if types
          types.each do |tk, tv|
            next unless tk.is_a?(String)
            td = tv.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
            unless td
              td = ::Hash(Cbor::EcValue, Cbor::EcValue).new
              td["def"] = tv
            end
            @store.bind(abs("system/type/#{tk}"), Entity.make("system/type", td))
          end
        end

        # (3) self-issued signed handler grant + (4) grant-signature at §3.5
        minted = @peer.mint_token(@identity.identity_hash, grant_scope, nil)
        @store.bind(abs("system/capability/grants/#{pattern}"), minted.token)
        @store.bind(abs("system/signature/#{minted.token.content_hash.hexstring}"), minted.signature)

        # (5) handler interface entity (discovery index)
        idata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        idata["pattern"] = pattern
        idata["name"] = name
        idata["operations"] = operations
        @store.bind(abs(interface_rel), Entity.make("system/handler/interface", idata))

        rdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        rdata["pattern"] = pattern
        rdata["grant"] = minted.token.data
        Outcome.ok(Entity.make("system/handler/register-result", rdata))
      end

      private def op_unregister(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        pattern = Peer.register_pattern(exec)
        return Peer.register_pattern_error(exec) if pattern.nil?

        g = @store.get_at(abs("system/capability/grants/#{pattern}"))
        if g
          @store.unbind(abs("system/signature/#{g.content_hash.hexstring}"))
          @store.unbind(abs("system/capability/grants/#{pattern}"))
        end
        @store.unbind(abs(pattern))
        @store.unbind(abs("system/handler/#{pattern}"))
        Outcome.ok(Wire.empty_params)
      end
    end

    # §7a conformance handler: echo (the §6.13(a) resolve→dispatch half). Returns
    # the params entity verbatim (the {value:X} echo-shape per §7a.1).
    class EchoHandler < Handler
      def handle(operation : String, ctx : HandlerContext) : Outcome
        return Outcome.err(501, "unsupported_operation", operation) unless operation == "echo"
        p = ctx.params
        p ? Outcome.ok(p) : Outcome.err(400, "invalid_params", "echo requires a params entity")
      end
    end

    # §7a conformance handler: dispatch-outbound (the §6.13(b)/§6.11 outbound seam).
    class DispatchOutboundHandler < Handler
      def initialize(@peer : Peer)
      end

      def handle(operation : String, ctx : HandlerContext) : Outcome
        return Outcome.err(501, "unsupported_operation", operation) unless operation == "dispatch"
        p = ctx.params
        return Outcome.err(400, "invalid_params", "dispatch-outbound requires a params entity") if p.nil?

        target = p.text("target") || ""
        operation_arg = p.text("operation") || ""
        value = p.field("value")
        capability = p.entity_field("reentry_capability")
        granter_peer = p.entity_field("reentry_granter")
        cap_sig = p.entity_field("reentry_cap_signature")
        unless value && capability && granter_peer && cap_sig
          return Outcome.err(400, "invalid_params", "dispatch-outbound requires value + reentry authority")
        end

        # §7a.1 generic relay: the `value` field is the bytes of the downstream's
        # params entity data and MUST be forwarded verbatim, never re-wrapped.
        inner_data =
          if value.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue))
            value
          else
            m = ::Hash(Cbor::EcValue, Cbor::EcValue).new
            m["value"] = value
            m
          end
        inner = Entity.make("primitive/any", inner_data)
        resource = Wire.resource_target("system/handler/#{target}")
        env = @peer.outbound_dispatch(ctx.conn, target, operation_arg, inner, capability, granter_peer, cap_sig, resource)
        return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection") if env.nil?

        status = env.root.uint("status") || 0_u64
        result_cbor = env.root.field("result")
        result_cbor = ::Hash(Cbor::EcValue, Cbor::EcValue).new if result_cbor.nil?
        odata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        odata["status"] = Cbor::EcInt.from(status)
        odata["result"] = result_cbor
        Outcome.ok(Entity.make("primitive/any", odata))
      end
    end
  end
end
