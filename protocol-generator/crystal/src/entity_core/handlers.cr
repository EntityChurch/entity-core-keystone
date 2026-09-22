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
          # §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
          # 400 invalid_request, not the 501 every other handler answers. The table
          # separates a STATE conflict from an UNKNOWN operation because they select
          # different remedies — "an unknown connect operation is not out of order at
          # all; it exists in no state", so connection_sequence_error would point the
          # caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
          # scoped "in any state", so this arm covers pre-handshake AND established;
          # the genuine sequence cases are refused in op_hello/op_authenticate, 409.
          #
          # SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
          # (§3.3's 501 row, §6.2) is a different contract and is separately gated;
          # moving the shared 501 would trade one green check for another.
          Outcome.err(400, "invalid_request", "connect: unknown operation #{operation}")
        end
      end

      private def op_hello(ctx : HandlerContext) : Outcome
        conn = ctx.conn
        exec = ctx.exec
        return Outcome.err(409, "connection_already_established") if conn.established
        # §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        # HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        # implement arriving in a state that forbids it — the same class as
        # connection_already_established above, taking the same 409. A half-open
        # connection is NOT established, so the guard above cannot reach it; §4.7
        # names this gap explicitly because two adjacent rules each look like they
        # cover it and neither does.
        return Outcome.err(409, "connection_sequence_error") unless conn.issued_nonce.nil?

        # §4.5 negotiation: reject disjoint hash_formats / key_types up front.
        hf = Peer.str_array(exec, "hash_formats")
        hash_ok = hf.nil? || hf.includes?("ecfv1-sha256")
        kt = Peer.str_array(exec, "key_types")
        key_ok = kt.nil? || kt.includes?("ed25519")
        return Outcome.err(400, "incompatible_hash_format") unless hash_ok
        return Outcome.err(400, "unsupported_key_type") unless key_ok

        params = exec.entity_field("params")
        initiator = params.try &.text("peer_id")
        # §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
        # is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
        # its `peer_id` — so a hello may advertise a perfectly good accept-set and
        # still name an identity we cannot verify. Checking only the array leaves
        # that MUST unenforced at hello, which is where §4.5 wants it; authenticate
        # catches it one leg later, which is conformant but non-canonical.
        #
        # An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
        # field, not a key_type we lack, and authenticate already refuses it.
        if initiator
          begin
            hello_kt, _, _ = PeerId.parse(initiator)
            return Outcome.err(400, "unsupported_key_type") unless hello_kt == 1_u64
          rescue
            # unparseable peer_id → not our question; authenticate refuses it
          end
        end

        # §4.5 `protocols` — the one negotiated field Required with NO default, so
        # there is no floor to fall back to, and its two failure modes carry
        # different codes on purpose (§4.5 table row / §4.7 row 1):
        #
        #   absent or empty     -> 400 invalid_request       (a malformed hello)
        #   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        #
        # "a caller that named no version cannot be told the comparison failed" —
        # the remedies differ (send the field vs change the version) and §4.7 exists
        # so the code selects the remedy. The vocabulary is §8.4's protocol version
        # identifiers, today the single entity-core/1.0.
        #
        # ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        # precedence between the three, so a hello disjoint in more than one
        # dimension may be refused on any of them — but the choice is OBSERVABLE,
        # and the reference peer refuses key_types first. Checking protocols first
        # is equally spec-legal and makes AGILITY-UNKNOWN-1 answer
        # incompatible_protocol, because that probe's own hello carries protocols
        # ["entity-core/v7"] — a spec-line name, not a §8.4 identifier (F56).
        protos = Peer.str_array(exec, "protocols")
        if protos.nil? || protos.empty?
          return Outcome.err(400, "invalid_request", "hello: protocols absent or empty")
        end
        return Outcome.err(400, "incompatible_protocol") unless protos.includes?("entity-core/1.0")

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
        # §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        # resource.targets: a handler that counts the effective list and then
        # indexes targets[0] has implemented the arithmetic completely and is still
        # reading a path no authorization covered.
        eff, has_resource = Capability.effective_targets(@local_peer, exec)
        unless has_resource
          # THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN
          # SPECIFICATION IS WHAT SAYS SO. §3.3's "an empty effective list IS the
          # absent case" is scoped "for an operation that REQUIRES a resource"
          # (0.8.2.24, N7); `get` does not. For a resource-OPTIONAL operation
          # 0.8.2.25 (N10) decides the present-but-empty case by whether the absent
          # case is WIDER than the request — BROAD-RESULT refuses it,
          # OPTIONAL-FILTER answers it empty — and requires the operation to
          # declare which it is.
          #
          # EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
          # resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
          # listing", self-excluded case "400 path_required". Both arms below are
          # pinned by text and neither is this peer's choice.
          return @peer.build_listing("/#{@local_peer}/", ctx)
        end
        if eff.empty?
          # The self-excluded request: `resource` PRESENT, every target carved out
          # by the caller's own exclude. Serving it the absent case "answers a
          # request for one excluded path with a listing of the tree"
          # (EXTENSION-TREE §2.2a) — wider than what was asked for, which is what
          # BROAD-RESULT means.
          return Outcome.err(400, "path_required", "tree: effective target list is empty")
        end
        if eff.size > 1
          return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target")
        end
        target = eff.first
        return Outcome.err(400, "invalid_path", target) unless Peer.path_flex_ok?(target)
        if target.empty? || target.ends_with?("/")
          return @peer.build_listing(Capability.canonicalize(@local_peer, target), ctx)
        end
        # A resource-requiring operation takes a CONCRETE path (0.8.2.20); a
        # trailing slash is a listing request rather than a pattern, so only a star
        # makes the subject a §5.4 pattern.
        if target.includes?('*')
          return Outcome.err(400, "malformed_resource", target)
        end

        path = Capability.canonicalize(@local_peer, target)
        # §6.3: the handler MUST verify the CALLER's capability covers the path it
        # is about to read. Not a secondary check — the dispatch-level check never
        # saw this path if the caller excluded it.
        if (cap = ctx.caller_cap)
          unless Capability.check_path_permission(@local_peer, "get", path, cap, ctx.pattern)
            return Outcome.err(403, "capability_denied", path)
          end
        end
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

      # Digest byte length for a `content_hash_format` code per the §1.2 seed table,
      # or nil when this peer cannot VERIFY that code. The total wire length is this
      # plus the varint prefix, which is not a constant of the code (§7.3): codes
      # >= 0x80 occupy more than one byte.
      HASH_DIGEST_LEN = {0_u64 => 32, 1_u64 => 48}

      # §6.3's `put` admission ladder (normative, 0.8.2.11).
      #
      # `put` is a RECEIPT path: the submitter authors the entity, the peer
      # validates what it received (§1.8 item 1) and MUST NOT author a submitted
      # entity's content_hash on the submitter's behalf. Two ordered steps:
      #
      #   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data`
      #      (any CBOR value; null is a legal payload), and a `content_hash` that is
      #      a well-formed system/hash whose total byte length matches its format
      #      code (§1.2). Any failure -> 400 invalid_request. A well-formed hash
      #      naming a format code this peer cannot verify is the separate §1.2
      #      ingest-dispatch case -> 400 unsupported_content_hash_format.
      #   2. HASH — carried content_hash vs content_hash({type, data}).
      #      Disagreement -> 400 hash_mismatch.
      #
      # Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
      # inputs are exactly what step 1 establishes, so a submission that is both
      # malformed and mis-hashed is step 1's and answers invalid_request.
      #
      # Structural admission is not semantic validation: `data` is never checked
      # against the type named by `type`.
      #
      # Returns the admitted Entity, or the Outcome it was refused with.
      private def admit_put(v : Cbor::EcValue) : Entity | Outcome
        refuse = ->(code : String, message : String) { Outcome.err(400, code, message) }

        map = v.as?(::Hash(Cbor::EcValue, Cbor::EcValue))
        return refuse.call("invalid_request", "put: entity is not a map") if map.nil?

        type = map["type"]?.as?(String)
        if type.nil? || type.empty?
          return refuse.call("invalid_request", "put: entity.type absent, empty or not a text string")
        end
        # Presence, not truthiness: a CBOR null is a legal `data` payload.
        return refuse.call("invalid_request", "put: entity.data absent") unless map.has_key?("data")

        data = map["data"]
        carried = map["content_hash"]?.as?(Bytes)
        if carried.nil? || carried.empty?
          return refuse.call("invalid_request", "put: entity.content_hash absent or not a byte string")
        end

        begin
          format_code, consumed = Varint.decode(carried)
        rescue TruncatedError
          return refuse.call("invalid_request", "put: entity.content_hash is not a well-formed system/hash")
        end
        digest_len = HASH_DIGEST_LEN[format_code]?
        if digest_len.nil?
          # §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
          # invalid_request: the shape is fine, the algorithm is what we lack.
          return refuse.call("unsupported_content_hash_format", "put: unsupported content_hash_format")
        end
        if carried.size != consumed + digest_len
          return refuse.call("invalid_request", "put: content_hash length does not match its format code")
        end

        basis = ::Hash(Cbor::EcValue, Cbor::EcValue).new
        basis["type"] = type
        basis["data"] = data
        unless EntityCore::Hash.content_hash(basis, format_code) == carried
          return refuse.call("hash_mismatch", "put: content_hash does not match content_hash({type, data})")
        end

        # The carried hash IS the entity's address; recomputing it into the store
        # would be the authoring arm §6.3 forbids.
        Entity.new(type, data, carried)
      end

      private def op_put(ctx : HandlerContext) : Outcome
        exec = ctx.exec
        # Same ladder as `get`, with the two empties COLLAPSED rather than split:
        # EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
        # "an empty effective list IS the absent case" applies in its unscoped form
        # and both empties answer `path_required`. That is the same table `get`'s
        # branch cites, read one row down — the field is per-operation and neither
        # answer is derivable from this handler's source.
        #
        # Note the code change 0.8.2.20 forced: this branch answered
        # `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as the
        # exact inversion it forbids ("answering ambiguous_resource for an absent
        # resource inverts them"). The remedies differ — supply a resource is not
        # disambiguate your request — and the code is what selects between them.
        eff, has_resource = Capability.effective_targets(@local_peer, exec)
        if !has_resource || eff.empty?
          return Outcome.err(400, "path_required", "tree: put requires a resource target")
        end
        if eff.size > 1
          return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target")
        end
        target = eff.first
        return Outcome.err(400, "invalid_path", target) unless Peer.path_flex_ok?(target)
        return Outcome.err(400, "malformed_resource", target) if target.includes?('*')

        path = Capability.canonicalize(@local_peer, target)
        # §6.3, as in `get`: the caller's own capability must cover the path this
        # handler is about to write.
        if (cap = ctx.caller_cap)
          unless Capability.check_path_permission(@local_peer, "put", path, cap, ctx.pattern)
            return Outcome.err(403, "capability_denied", path)
          end
        end
        params = exec.entity_field("params")
        raw_entity = params.try &.field("entity")
        expected = params.try &.bytes("expected_hash")
        return Outcome.err(400, "unexpected_params", "put: missing entity") if raw_entity.nil?

        admitted = admit_put(raw_entity)
        return admitted if admitted.is_a?(Outcome)

        entity = admitted

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
        mint_bounded(ctx.env, ctx.caller_cap, params, Peer.req_grants(params), author, nil)
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
        mint_bounded(ctx.env, ctx.caller_cap, params, Peer.req_grants(params), author, ph)
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

      private def mint_bounded(env : Envelope, caller_cap : Entity?, params : Entity?,
                               req_grants : Array(Cbor::EcValue),
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

        # §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE
        # and convert the duration term against that same instant.
        #
        # Note what this is NOT: an authorization decision. An over-long ttl_ms from
        # a bounded caller MINTS a clamped token and returns 200 — "rejecting it is
        # non-conformant" (§5.6). The bound exists because `request` mints a ROOT
        # token (parent: null), so §5.6's parent-child attenuation never reaches it;
        # without this clamp, temporal attenuation is the one dimension a requester
        # could escape, and policy withdrawal would have no bounded latency.
        created_at = Capability.now_ms
        ceiling : UInt64? = nil
        fold = ->(term : UInt64?) do
          if t = term
            c = ceiling
            ceiling = (c.nil? || t < c) ? t : c
          end
        end
        if parent
          pt = Capability.cap_resolve(env.included, @store, parent)
          fold.call(pt.uint("expires_at")) if pt                     # absolute
        end
        fold.call(caller_cap.uint("expires_at")) if caller_cap       # absolute
        if ttl = params.try &.uint("ttl_ms")                         # duration
          fold.call(Peer.add_ttl(created_at, ttl))
        end

        minted = @peer.mint_token_at(created_at, grantee_hash, req_grants, parent, ceiling)
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
        if Peer.reserved_system_pattern?(pattern)
          return Outcome.err(403, "forbidden_pattern",
            "§6.2: user-installed handlers MUST NOT register at system/* paths: " + pattern)
        end

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
        return Outcome.err(503, "no_outbound_seam", "no live section 6.11 reentry connection") if env.nil?

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
