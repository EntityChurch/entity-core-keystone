require "random/secure"
require "./cbor"
require "./entity"
require "./envelope"
require "./identity"
require "./store"
require "./capability"
require "./wire"
require "./handler"
require "./core_types"
require "./error"

module EntityCore
  # Peer assembly: bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2:
  # connect, tree, handler, capability), the §6.5 dispatch chain, §6.6 resolution,
  # and per-connection state. The pure protocol brain — a function from inbound
  # envelope to outbound response envelope. Transport lives in Transport.
  #
  # Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch-chain order
  # (verify → resolve → check-permission → handler), and §4.4 initial-grant
  # delivery are derived directly from V8.
  class Peer
    getter identity : Identity
    getter store : Store
    getter local_peer : String

    # A minted token + its signature (§4.4 / §6.9a).
    struct Minted
      getter token : Entity
      getter signature : Entity

      def initialize(@token, @signature)
      end
    end

    @handlers : ::Hash(String, Handler)

    def initialize(@identity : Identity, @store : Store, @local_peer : String,
                   @open_grants : Bool, @conformance : Bool)
      @handlers = ::Hash(String, Handler).new
    end

    def handlers : ::Hash(String, Handler)
      @handlers
    end

    # ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ─────────────────────────

    def random_bytes(n : Int32) : Bytes
      Random::Secure.random_bytes(n)
    end

    # ── grant construction (§4.4 / §5.4) ────────────────────────────────────────

    alias EcMap = ::Hash(Cbor::EcValue, Cbor::EcValue)

    def self.scope_cbor(incl : Array(String), excl : Array(String)? = nil) : EcMap
      m = EcMap.new
      m["include"] = incl.map(&.as(Cbor::EcValue)).to_a
      m["exclude"] = excl.map(&.as(Cbor::EcValue)).to_a if excl
      m
    end

    # Build a grant cbor-map. `peers` nil → omit (defaults to local at check time).
    def self.grant(handlers : Array(String), resources : Array(String),
                   operations : Array(String), peers : Array(String)? = nil) : EcMap
      g = EcMap.new
      g["handlers"] = scope_cbor(handlers)
      g["resources"] = scope_cbor(resources)
      g["operations"] = scope_cbor(operations)
      g["peers"] = scope_cbor(peers) if peers
      g
    end

    # The §4.4 discovery floor: every authenticated identity gets at least this.
    def discovery_floor : Array(Cbor::EcValue)
      [
        Peer.grant(["system/tree"], ["system/type/*", "system/handler/*"], ["get"]).as(Cbor::EcValue),
        Peer.grant(["system/capability"], [] of String, ["request"]).as(Cbor::EcValue),
      ]
    end

    # Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants).
    def open_grants_scope : Array(Cbor::EcValue)
      [Peer.grant(["*"], ["*", "/*/*"], ["*"], ["*"]).as(Cbor::EcValue)]
    end

    # Full owner authority over the local namespace /{peer_id}/* (§6.9a).
    def owner_grants : Array(Cbor::EcValue)
      [Peer.grant(["*"], ["*"], ["*"], [@local_peer]).as(Cbor::EcValue)]
    end

    # ── §5.6 temporal ceiling (CAP-5 / CAP-6) ────────────────────────────────────

    # Convert a DURATION term to an absolute timestamp, reporting whether it
    # contributes a ceiling at all (nil = no term).
    #
    # §5.6 rule 3: a term whose conversion created_at+ttl is not representable is
    # treated as ABSENT, exactly as a null term is. It MUST NOT wrap and MUST NOT
    # saturate to a representable maximum — saturation encodes differently from
    # absence and manufactures expires_at == 2**64-1, a finite bound no reader can
    # distinguish from a deliberate one.
    #
    # ttl == 0 is NOT a special case here and deliberately so: §5.6 rule 2 makes 0
    # a DEFINED value yielding created_at (expire immediately). The absent field is
    # the only "no bound" spelling, and falling out of the arithmetic is what keeps
    # the two from ever collapsing into each other.
    def self.add_ttl(created_at : UInt64, ttl : UInt64) : UInt64?
      sum = created_at &+ ttl
      sum < created_at ? nil : sum   # UInt64 wrap => not representable => drop
    end

    # ── token mint (§4.4 / §6.9a) ────────────────────────────────────────────────

    # Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
    #
    # *expires_at* nil means no term was defined and the token genuinely has no
    # expiry (the ONLY "no bound" spelling). A non-nil value is emitted verbatim —
    # including one equal to *created_at*, which §5.6 rule 2 requires for
    # ttl_ms == 0 and which means "already expired at every observable instant",
    # not "unbounded".
    #
    # *created_at* is supplied rather than sampled here so a computed expiry is
    # guaranteed to be relative to the SAME instant that lands in the token;
    # sampling the clock twice skews the two.
    def mint_token_at(created_at : UInt64, grantee_hash : Bytes, grants : Array(Cbor::EcValue),
                      parent : Bytes? = nil, expires_at : UInt64? = nil) : Minted
      data = EcMap.new
      data["granter"] = @identity.identity_hash
      data["grantee"] = grantee_hash
      data["grants"] = grants
      data["created_at"] = Cbor::EcInt.from(created_at)
      data["expires_at"] = Cbor::EcInt.from(expires_at) if expires_at
      data["parent"] = parent if parent
      token = Entity.make("system/capability/token", data)
      Minted.new(token, @identity.sign(token))
    end

    # mint_token_at at the current instant with no §5.6 ceiling. Used by the paths
    # that mint a self-issued grant from local authority (bootstrap, handler
    # registration, the §4.4 handshake), where no MIN_DEFINED term is in play.
    def mint_token(grantee_hash : Bytes, grants : Array(Cbor::EcValue), parent : Bytes? = nil) : Minted
      mint_token_at(Capability.now_ms, grantee_hash, grants, parent)
    end

    def cap_included(minted : Minted) : Array(Entity)
      [minted.token, @identity.peer_entity, minted.signature]
    end

    # ── §6.9a seed policy (authenticate-time grant derivation) ───────────────────

    def seed_entry_grants(entry : Entity) : Array(Cbor::EcValue)
      case entry.type
      when "system/capability/token"
        sig_path = "/#{@local_peer}/system/signature/#{entry.content_hash.hexstring}"
        sgn = @store.get_at(sig_path)
        if sgn && Identity.verify_signature(sgn, @identity.peer_entity)
          Capability.map_list(entry.data_map, "grants").try(&.map(&.as(Cbor::EcValue))) || [] of Cbor::EcValue
        else
          [] of Cbor::EcValue
        end
      when "system/capability/policy-entry"
        Capability.map_list(entry.data_map, "grants").try(&.map(&.as(Cbor::EcValue))) || [] of Cbor::EcValue
      else
        [] of Cbor::EcValue
      end
    end

    # §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 →
    # default), then UNION the matched scope with the §4.4 discovery floor.
    def derive_seed_grants(remote_peer : Entity, remote_peer_id : String) : Array(Cbor::EcValue)
      base = "/#{@local_peer}/system/capability/policy/"
      entry = @store.get_at(base + remote_peer.content_hash.hexstring) ||
              @store.get_at(base + remote_peer_id) ||
              @store.get_at("#{base}default")
      floor = discovery_floor
      return floor if entry.nil?
      policy = seed_entry_grants(entry)
      return floor if policy.empty?
      floor + policy
    end

    # ── handler resolution (§6.6) — backward tree-walk ───────────────────────────

    # Return the longest prefix of `path` bound to a system/handler entity, or nil.
    def resolve_handler(path : String) : String?
      segs = path.split("/")
      i = segs.size
      while i >= 1
        prefix = segs[0, i].join("/")
        e = @store.get_at(prefix)
        return prefix if e && e.type == "system/handler"
        i -= 1
      end
      nil
    end

    def strip_local(pattern : String) : String
      prefix = "/#{@local_peer}/"
      pattern.starts_with?(prefix) ? pattern[prefix.size..] : pattern
    end

    # ── dispatcher-level signature ingestion (§6.5) ──────────────────────────────

    def ingest_signatures(env : Envelope) : Nil
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
        @store.bind("/#{pid}/system/signature/#{target.hexstring}", e)
      end
      nil
    end

    # ── §6.13(b) handler-facing outbound dispatch ────────────────────────────────

    def outbound_dispatch(conn : Conn, uri : String, operation : String, params : Entity,
                          capability : Entity, granter_peer : Entity, cap_sig : Entity,
                          resource : EcMap) : Envelope?
      send_fn = conn.outbound
      return nil if send_fn.nil?

      request_id = "out-#{conn.next_out_counter}"
      exec = Wire.make_execute(request_id, uri, operation, params,
        author: @identity.identity_hash, capability: capability.content_hash, resource: resource)
      exec_sig = @identity.sign(exec)
      included = [
        capability, granter_peer, @identity.peer_entity, cap_sig, exec_sig,
      ]
      send_fn.call(Envelope.of(exec, included))
    end

    # ── tree listing (§3.9) ────────────────────────────────────────────────────────

    def build_listing(path : String) : Outcome
      rows = @store.listing(path).reject do |row|
        hh = row.hash_hex
        hh && !row.has_children && deletion_marker?(hh.hexbytes)
      end
      entries = EcMap.new
      rows.each do |row|
        data = EcMap.new
        hh = row.hash_hex
        if hh
          data["has_children"] = row.has_children
          data["hash"] = hh.hexbytes
        else
          data["has_children"] = row.has_children
        end
        entries[row.segment] = Entity.make("system/tree/listing-entry", data).to_cbor
      end
      ldata = EcMap.new
      ldata["path"] = path
      ldata["entries"] = entries
      ldata["count"] = Cbor::EcInt.from(rows.size)
      ldata["offset"] = Cbor::EcInt.from(0)
      Outcome.ok(Entity.make("system/tree/listing", ldata))
    end

    def deletion_marker?(hash : Bytes) : Bool
      e = @store.get_by_hash(hash)
      !e.nil? && e.type == "system/deletion-marker"
    end

    # ── entity-native dispatch (§6.13(a)) ────────────────────────────────────────

    def entity_native_dispatch(handler_path : String) : Outcome
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
        rdata = EcMap.new
        rdata["value"] = value
        rdata["expression"] = expr.content_hash
        Outcome.ok(Entity.make("compute/result", rdata))
      else
        Outcome.err(501, "unsupported_expression", expr.type)
      end
    end

    # ── dispatch chain (§6.5) ──────────────────────────────────────────────────────

    # The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or nil for a
    # non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
    def dispatch(conn : Conn, env : Envelope) : Envelope?
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
        rescue ex
          STDERR.puts "dispatch 500: #{ex.class}: #{ex.message}" if ENV["PEER_DEBUG_500"]?
          Outcome.err(500, "internal_error")
        end
      Envelope.of(Wire.make_response(request_id, outcome.status, outcome.result), outcome.included)
    end

    private def dispatch_inner(conn : Conn, env : Envelope, exec : Entity) : Outcome
      uri = exec.text("uri") || ""
      operation = exec.text("operation") || ""
      if uri == "system/protocol/connect"
        h = @handlers["system/protocol/connect"]
        return h.handle(operation,
          HandlerContext.new(exec, conn, env.included, nil, env))
      end

      ingest_signatures(env)
      # §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
      # sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace took
      # the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the caller
      # to authenticate and retry, and for a foreign-namespace address that retry cannot
      # succeed at any authentication state — so the 401 names a remedy that does not exist."
      # §6.5 step 3 calls it "a gate, not an ordering preference" and §1.4 makes the downstream
      # permission check unreachable here.
      path = Capability.canonicalize(@local_peer, Capability.normalize_uri(uri))
      return Outcome.err(400, "invalid_request", "not local peer") unless Capability.extract_peer(@local_peer, path) == @local_peer

      case Capability.verify_request(@local_peer, @store, env)
      when Capability::RequestVerdict::AuthnFail
        return Outcome.err(401, "authentication_failed")
      when Capability::RequestVerdict::AuthzDeny
        return Outcome.err(403, "capability_denied")
      when Capability::RequestVerdict::ChainTooDeep
        return Outcome.err(400, "chain_depth_exceeded")
      else
        # Allow → fall through
      end

      # (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
      # 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
      pattern = resolve_handler(path)
      return Outcome.err(404, "handler_not_found", path) if pattern.nil?

      cap_h = exec.bytes("capability")
      caller_cap = cap_h ? env.included_get(cap_h) : nil
      return Outcome.err(403, "capability_denied") if caller_cap.nil?

      resolve_fn = ->(h : Bytes) { Capability.cap_resolve(env.included, @store, h) }
      granter_peer = Capability.resolve_granter_peer_id(resolve_fn, caller_cap) || @local_peer
      unless Capability.check_permission(@local_peer, granter_peer, exec, caller_cap, pattern)
        return Outcome.err(403, "capability_denied")
      end

      stripped = strip_local(pattern)
      inst = @handlers[stripped]?
      if inst
        inst.handle(operation, HandlerContext.new(exec, conn, env.included, caller_cap, env))
      else
        entity_native_dispatch(pattern)
      end
    end

    # ── bootstrap (§6.9) ────────────────────────────────────────────────────────────

    # An operation spec (input/output type names) for the handler interface index.
    record OpSpec, op : String, input : String?, output : String?

    def self.op_spec_cbor(input : String?, output : String?) : EcMap
      h = EcMap.new
      h["input_type"] = input if input
      h["output_type"] = output if output
      h
    end

    def bootstrap_handler_entities(pattern : String, name : String, ops : Array(OpSpec)) : Nil
      operations = EcMap.new
      ops.each { |o| operations[o.op] = Peer.op_spec_cbor(o.input, o.output) }
      hdata = EcMap.new
      hdata["interface"] = "system/handler/#{pattern}"
      @store.bind("/#{@local_peer}/#{pattern}", Entity.make("system/handler", hdata))
      idata = EcMap.new
      idata["pattern"] = pattern
      idata["name"] = name
      idata["operations"] = operations
      @store.bind("/#{@local_peer}/system/handler/#{pattern}",
        Entity.make("system/handler/interface", idata))
      minted = mint_token(@identity.identity_hash, [] of Cbor::EcValue, nil)
      @store.bind("/#{@local_peer}/system/capability/grants/#{pattern}", minted.token)
      nil
    end

    # Construct + bootstrap a peer from a 32-byte Ed25519 seed.
    def self.create(seed : Bytes, open_grants : Bool = false, conformance : Bool = false) : Peer
      identity = Identity.of_seed(seed)
      store = Store.new
      local = identity.peer_id
      peer = new(identity, store, local, open_grants, conformance)

      # local identity entity in the store (root-granter resolution)
      store.put_entity(identity.peer_entity)
      # publish the 53-type core floor
      CoreTypes.publish(store, local)

      register(peer, "system/tree", TreeHandler.new(peer), "Tree",
        [OpSpec.new("get", nil, nil), OpSpec.new("put", nil, nil)])
      register(peer, "system/handler", HandlersHandler.new(peer), "Handlers",
        [OpSpec.new("register", "system/handler/register-request", "system/handler/register-result"),
         OpSpec.new("unregister", "system/handler/unregister-request", nil)])
      register(peer, "system/capability", CapabilityHandler.new(peer), "Capability",
        [OpSpec.new("request", "system/capability/request", "system/capability/grant"),
         OpSpec.new("revoke", "system/capability/revoke-request", nil),
         OpSpec.new("configure", "system/capability/policy-entry", nil),
         OpSpec.new("delegate", "system/capability/delegate-request", "system/capability/grant")])
      register(peer, "system/protocol/connect", ConnectHandler.new(peer), "Connect",
        [OpSpec.new("hello", nil, nil), OpSpec.new("authenticate", nil, nil)])

      # §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap + default
      # scope-template entry. Read back by authenticate (dual-form lookup).
      policy_base = "/#{local}/system/capability/policy/"
      owner = peer.mint_token(identity.identity_hash, peer.owner_grants, nil)
      store.bind(policy_base + identity.identity_hash.hexstring, owner.token)
      store.bind("/#{local}/system/signature/#{owner.token.content_hash.hexstring}", owner.signature)
      default_grants = open_grants ? peer.open_grants_scope : peer.discovery_floor
      pedata = EcMap.new
      pedata["peer_pattern"] = "default"
      pedata["grants"] = default_grants
      store.bind("#{policy_base}default", Entity.make("system/capability/policy-entry", pedata))

      # §7a conformance handlers — only bootstrapped under --validate
      if conformance
        register(peer, "system/validate/echo", EchoHandler.new, "validate-echo",
          [OpSpec.new("echo", nil, nil)])
        register(peer, "system/validate/dispatch-outbound", DispatchOutboundHandler.new(peer),
          "validate-dispatch-outbound", [OpSpec.new("dispatch", nil, nil)])
      end
      peer
    end

    private def self.register(peer : Peer, pattern : String, handler : Handler,
                              name : String, ops : Array(OpSpec)) : Nil
      peer.handlers[pattern] = handler
      peer.bootstrap_handler_entities(pattern, name, ops)
      nil
    end

    # ── small helpers ────────────────────────────────────────────────────────────

    def self.exec_resource_target(exec : Entity) : String?
      r = exec.map_field("resource")
      return nil if r.nil?
      targets = Capability.text_list(r, "targets")
      targets && !targets.empty? ? targets.first : nil
    end

    def self.path_flex_ok?(target : String) : Bool
      return false if target.includes?(" ")
      # §1.4: a NUL byte (and any C0 control char) is invalid in any path segment.
      return false if target.each_char.any? { |c| c.ord < 0x20 }
      segs0 = target.split("/")
      if target.starts_with?("/")
        if segs0.size >= 2 && segs0[0].empty?
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

    def self.zero_hash?(h : Bytes) : Bool
      h.all? &.zero?
    end

    def self.req_grants(params : Entity?) : Array(Cbor::EcValue)
      return [] of Cbor::EcValue if params.nil?
      Capability.map_list(params.data_map, "grants").try(&.map(&.as(Cbor::EcValue))) || [] of Cbor::EcValue
    end

    def self.str_array(exec : Entity, key : String) : Array(String)?
      params = exec.entity_field("params")
      params ? Capability.text_list(params.data_map, key) : nil
    end

    def self.register_pattern(exec : Entity) : String?
      target = exec_resource_target(exec)
      return nil if target.nil?
      prefix = "system/handler/"
      return nil if !target.starts_with?(prefix) || target.size == prefix.size
      target[prefix.size..]
    end

    # §6.2: user-installed handlers MUST NOT register at system/* paths.
    def self.reserved_system_pattern?(pattern : String) : Bool
      pattern == "system" || pattern.starts_with?("system/")
    end

    def self.register_pattern_error(exec : Entity) : Outcome
      target = exec_resource_target(exec)
      if target.nil?
        Outcome.err(400, "ambiguous_resource", "register/unregister require exactly one resource target")
      else
        Outcome.err(400, "invalid_resource", "resource target MUST be system/handler/{pattern}")
      end
    end
  end
end

require "./handlers"
