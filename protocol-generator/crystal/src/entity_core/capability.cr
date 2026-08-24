require "./cbor"
require "./entity"
require "./envelope"
require "./identity"
require "./store"
require "./error"

module EntityCore
  # Capability system (L3): the §5 verification core — pattern matching (§5.4),
  # request verification (§5.2), delegation-chain verification (§5.5), attenuation
  # (§5.6), caveats (§5.7), revocation (§5.1). Derived from the §5 pseudocode.
  #
  # The verdict is a bare Verdict enum (§5.10 Layer-1 determinism); the dispatcher
  # maps Deny → 403, ChainTooDeep → 400, AuthnFail → 401, and the §5.5
  # unresolvable-grantee → 401 carve-out is raised as UnresolvableGranteeError.
  #
  # §PR-8 / §5.5a granter-frame: the RESOURCE dimension's patterns canonicalize
  # against the GRANTER's peer_id; handlers/operations/peers stay on the local
  # frame. For the self-issued dominant path (granter = local) this is
  # byte-identical; only the foreign-granter cross-peer case flips.
  module Capability
    BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    BASE58_SET      = BASE58_ALPHABET.each_char.to_set

    # §4.10(b) max delegation-chain depth — an over-deep chain is 400
    # chain_depth_exceeded (structural excess), NOT 403.
    MAX_CHAIN_DEPTH = 64

    # The §5.2 verify-request verdict (mapped 200-path / 401 / 403 / 400 by the
    # dispatcher, §5.2a trichotomy).
    enum RequestVerdict
      Allow
      AuthnFail
      AuthzDeny
      ChainTooDeep
    end

    # A parsed include/exclude scope.
    struct Scope
      getter incl : Array(String)
      getter excl : Array(String)

      def initialize(@incl : Array(String), @excl : Array(String))
      end
    end

    # A parsed grant (four dimensions; peers nil → local at check time).
    struct GrantRec
      getter handlers : Scope
      getter resources : Scope
      getter operations : Scope
      getter peers : Scope?

      def initialize(@handlers, @resources, @operations, @peers)
      end
    end

    extend self

    # ── typed-field helpers (over a cbor EcValue map, nil-safe) ──────────────────

    alias EcMap = ::Hash(Cbor::EcValue, Cbor::EcValue)

    def as_map(value : Cbor::EcValue) : EcMap?
      value.as?(EcMap)
    end

    # Text-string list at `key` (drops non-text elements).
    def text_list(map : EcMap?, key : String) : Array(String)?
      return nil if map.nil?
      v = map[key]?
      return nil unless v.is_a?(Array(Cbor::EcValue))
      v.compact_map(&.as?(String))
    end

    # Map list at `key` (drops non-map elements).
    def map_list(map : EcMap?, key : String) : Array(EcMap)?
      return nil if map.nil?
      v = map[key]?
      return nil unless v.is_a?(Array(Cbor::EcValue))
      v.compact_map(&.as?(EcMap))
    end

    def uint(map : EcMap?, key : String) : UInt64?
      return nil if map.nil?
      v = map[key]?
      return nil unless v.is_a?(Cbor::EcInt)
      v.major == 0_u8 ? v.arg : nil
    end

    def now_ms : UInt64
      (Time.utc.to_unix_ms).to_u64
    end

    # ── grant / scope parse ──────────────────────────────────────────────────────

    def parse_scope(map : EcMap?) : Scope
      return Scope.new([] of String, [] of String) if map.nil?
      Scope.new(text_list(map, "include") || [] of String,
        text_list(map, "exclude") || [] of String)
    end

    def parse_grant(map : EcMap) : GrantRec
      peers_v = map["peers"]?
      peers = peers_v ? parse_scope(as_map(peers_v)) : nil
      GrantRec.new(
        parse_scope(as_map(map["handlers"]? || nil)),
        parse_scope(as_map(map["resources"]? || nil)),
        parse_scope(as_map(map["operations"]? || nil)),
        peers
      )
    end

    def grants_of_token(token : Entity) : Array(GrantRec)
      raw = map_list(token.data_map, "grants")
      return [] of GrantRec if raw.nil?
      raw.map { |g| parse_grant(g) }
    end

    # ── §5.4 pattern matching ─────────────────────────────────────────────────────

    def normalize_uri(uri : String) : String
      uri.starts_with?("entity://") ? "/#{uri[9..]}" : uri
    end

    # Resolve peer-relative paths to absolute /{local}/... form.
    def canonicalize(local_peer : String, path : String) : String
      if path.starts_with?("./") || path.starts_with?("../")
        raise ProtocolError.new("canonicalize: reserved directory-relative path")
      end
      raise ProtocolError.new("canonicalize: ambiguous bare peer wildcard") if path.starts_with?("*/")
      return path if path.starts_with?("/")
      "/#{local_peer}/#{path}"
    end

    def matches_pattern(path : String, pattern : String) : Bool
      return true if pattern == "*"
      if pattern.starts_with?("/*/")
        remainder = pattern[3..]
        return false if path.empty?
        i = path.index('/', 1)
        return false if i.nil?
        return matches_pattern(path[(i + 1)..], remainder)
      end
      return path.starts_with?(pattern[0...-1]) if pattern.size >= 2 && pattern.ends_with?("/*")
      path == pattern
    end

    def matches_scope(local_peer : String, value : String, scope : Scope) : Bool
      cv = canonicalize(local_peer, value)
      covered(local_peer, scope.incl, cv) && !covered(local_peer, scope.excl, cv)
    end

    private def covered(frame : String, pats : Array(String), cv : String) : Bool
      pats.any? { |p| matches_pattern(cv, canonicalize(frame, p)) }
    end

    # ── §5.2 check-permission ──────────────────────────────────────────────────────

    def first_segment(uri : String) : String
      u = uri.starts_with?("/") ? uri[1..] : uri
      i = u.index('/')
      i ? u[0...i] : u
    end

    def peer_id?(seg : String) : Bool
      return false if seg.size < 46
      seg.each_char.all? { |c| BASE58_SET.includes?(c) }
    end

    def extract_peer(local_peer : String, uri : String) : String
      first = first_segment(normalize_uri(uri))
      peer_id?(first) ? first : local_peer
    end

    # Concrete-target subset. The grant's own resource patterns canonicalize
    # against the GRANTER's peer_id (§PR-8); caller-supplied targets/exclude stay
    # on the LOCAL frame (§5.4).
    def check_resource_scope(local_peer : String, granter_peer : String, resource : EcMap, scope : Scope) : Bool
      targets = text_list(resource, "targets")
      caller_excl = text_list(resource, "exclude")
      return false if targets.nil? || targets.empty?
      targets.all? do |tgt|
        ct = canonicalize(local_peer, tgt)
        if caller_excl && covered_frame(local_peer, caller_excl, ct)
          true # caller excluded → vacuously ok
        else
          covered_frame(granter_peer, scope.incl, ct) && !covered_frame(granter_peer, scope.excl, ct)
        end
      end
    end

    private def covered_frame(frame : String, pats : Array(String), value : String) : Bool
      pats.any? { |p| matches_pattern(value, canonicalize(frame, p)) }
    end

    # §PR-8 — canonicalization frame for CAP's grant resource patterns = the
    # GRANTER's peer_id. Unresolvable → nil (caller falls back to local).
    def resolve_granter_peer_id(resolve : Bytes -> Entity?, cap : Entity) : String?
      gh = cap.bytes("granter")
      return nil if gh.nil?
      g = resolve.call(gh)
      return nil if g.nil?
      pk = g.bytes("public_key")
      pk ? Identity.peer_id_of_public_key(pk) : nil
    end

    # Gate the wire request at the dispatch authorization boundary (§3.2.3).
    # `granter_peer` is the §PR-8 frame for the cap's grant resource patterns.
    def check_permission(local_peer : String, granter_peer : String, exec : Entity,
                         token : Entity, handler_pattern : String) : Bool
      operation = exec.text("operation") || ""
      uri = exec.text("uri") || ""
      target_peer = extract_peer(local_peer, uri)
      resource = exec.map_field("resource")
      grants_of_token(token).each do |g|
        ok = matches_scope(local_peer, operation, g.operations) &&
             matches_scope(local_peer, handler_pattern, g.handlers)
        if ok
          peers = g.peers || Scope.new([local_peer], [] of String)
          ok = matches_scope(local_peer, target_peer, peers)
        end
        ok = check_resource_scope(local_peer, granter_peer, resource, g.resources) if ok && resource
        return true if ok
      end
      false
    end

    # ── signature / resolution helpers ────────────────────────────────────────────

    def find_signature(target : Bytes, included : Array(Envelope::Included)) : Entity?
      included.each do |i|
        e = i.entity
        next unless e.type == "system/signature"
        tg = e.bytes("target")
        return e if tg && tg == target
      end
      nil
    end

    # The signature over `target` authored by `signer_hash` (multi-sig needs the
    # per-signer signature, not just the first for the target).
    def find_signature_by(target : Bytes, signer_hash : Bytes, included : Array(Envelope::Included)) : Entity?
      included.each do |i|
        e = i.entity
        next unless e.type == "system/signature"
        next unless e.bytes("target") == target
        return e if e.bytes("signer") == signer_hash
      end
      nil
    end

    def cap_resolve(included : Array(Envelope::Included), store : Store, hash : Bytes) : Entity?
      e = included_get(included, hash)
      e || store.get_by_hash(hash)
    end

    def included_get(included : Array(Envelope::Included), hash : Bytes) : Entity?
      included.each do |i|
        return i.entity if i.hash == hash
      end
      nil
    end

    # ── §5.5a per-link canonicalization frame ──────────────────────────────────────

    def link_granter_peer(resolve : Bytes -> Entity?, local_peer : String, cap : Entity) : String?
      gh = cap.bytes("granter")
      return local_peer if gh.nil?
      g = resolve.call(gh)
      return nil if g.nil?
      pk = g.bytes("public_key")
      pk ? Identity.peer_id_of_public_key(pk) : nil
    end

    # ── §5.6 attenuation ───────────────────────────────────────────────────────────

    private def scope_subset(child_peer : String, parent_peer : String, child : Scope, parent : Scope) : Bool
      child.incl.each do |cp|
        cc = canonicalize(child_peer, cp)
        return false unless parent.incl.any? { |pp| matches_pattern(cc, canonicalize(parent_peer, pp)) }
      end
      parent.excl.each do |pe|
        cpe = canonicalize(parent_peer, pe)
        return false unless child.excl.any? { |ce| matches_pattern(cpe, canonicalize(child_peer, ce)) }
      end
      true
    end

    def grant_subset(local_peer : String, child_peer : String, parent_peer : String,
                     child : GrantRec, parent : GrantRec) : Bool
      return false unless scope_subset(local_peer, local_peer, child.handlers, parent.handlers)
      return false unless scope_subset(local_peer, local_peer, child.operations, parent.operations)
      return false unless scope_subset(child_peer, parent_peer, child.resources, parent.resources)
      cp = child.peers || Scope.new([local_peer], [] of String)
      pp = parent.peers || Scope.new([local_peer], [] of String)
      scope_subset(local_peer, local_peer, cp, pp)
    end

    private def attenuated?(local_peer : String, child_peer : String, parent_peer : String,
                            child : Entity, parent : Entity) : Bool
      cg = grants_of_token(child)
      pg = grants_of_token(parent)
      cg.each do |c|
        return false unless pg.any? { |p| grant_subset(local_peer, child_peer, parent_peer, c, p) }
      end
      pe = parent.uint("expires_at")
      ce = child.uint("expires_at")
      return false if pe && ce.nil? # child infinite, parent finite
      return ce.not_nil! <= pe if pe && ce
      true
    end

    private def check_delegation_caveats(parent : Entity, child : Entity, depth : Int32) : Bool
      caveats = parent.map_field("delegation_caveats")
      return true if caveats.nil?
      nd = caveats["no_delegation"]?
      return false if nd == true

      depth_ok = true
      m = uint(caveats, "max_delegation_depth")
      depth_ok = depth < m.to_i if m

      ttl_ok = true
      max_ttl = uint(caveats, "max_delegation_ttl")
      if max_ttl
        ex = child.uint("expires_at")
        cr = child.uint("created_at")
        ttl_ok =
          if ex && cr
            (ex - cr) <= max_ttl
          elsif ex
            true # created_at absent — can't bound, admit
          else
            false # infinite child lifetime exceeds any limit
          end
      end
      depth_ok && ttl_ok
    end

    # ── chain collection + depth pre-check ─────────────────────────────────────────

    # Walk parent pointers collecting the chain. Returns `{chain_or_nil, ok}`.
    private def collect_chain(cap : Entity, resolve : Bytes -> Entity?) : {Array(Entity)?, Bool}
      acc = [] of Entity
      current = cap
      depth = 0
      loop do
        return {nil, false} if depth > MAX_CHAIN_DEPTH
        acc << current
        ph = current.bytes("parent")
        return {acc, true} if ph.nil?
        parent = resolve.call(ph)
        return {nil, false} if parent.nil?
        current = parent
        depth += 1
      end
    end

    # §4.10(b) structural-bound pre-check: true if the authority chain rooted at
    # `capability` exceeds MAX_CHAIN_DEPTH (64). Walks parent pointers WITHOUT
    # verifying signatures — depth is purely structural, gated BEFORE the per-link
    # authz walk so over-depth → 400 chain_depth_exceeded (distinct from 403
    # capability_denied). An UNREACHABLE parent is NOT a depth problem — it returns
    # false here and is left for verify_capability_chain to deny (403).
    def chain_exceeds_depth?(store : Store, capability : Entity, included : Array(Envelope::Included)) : Bool
      resolve = ->(h : Bytes) { cap_resolve(included, store, h) }
      current = capability
      depth = 0
      loop do
        return true if depth > MAX_CHAIN_DEPTH
        ph = current.bytes("parent")
        return false if ph.nil? # root reached within bound
        parent = resolve.call(ph)
        return false if parent.nil? # unreachable — not a depth problem
        current = parent
        depth += 1
      end
    end

    # ── §3.6 / §5.5 multi-signature root (K-of-N quorum, root-only) ─────────────────

    private def multisig?(cap : Entity) : Bool
      !cap.map_field("granter").nil?
    end

    private def multisig_root_ok?(local_peer : String, resolve : Bytes -> Entity?,
                                  root : Entity, included : Array(Envelope::Included)) : Bool
      gm = root.map_field("granter")
      return false if gm.nil?
      signers_v = gm["signers"]?
      threshold_v = gm["threshold"]?
      return false unless signers_v.is_a?(Array(Cbor::EcValue))
      return false unless threshold_v.is_a?(Cbor::EcInt) && threshold_v.major == 0_u8
      threshold = threshold_v.arg.to_i64
      signers = [] of Bytes
      signers_v.each do |s|
        return false unless s.is_a?(Bytes)
        signers << s
      end
      n = signers.size

      # M3: root-only, quorum shape, distinct signers.
      return false unless root.bytes("parent").nil?
      return false unless n >= 2 && threshold >= 2 && threshold <= n
      return false unless signers.map(&.hexstring).uniq.size == n

      # M6: the local peer MUST be a quorum member.
      local_in_signers = signers.any? do |sh|
        s = resolve.call(sh)
        pk = s.try &.bytes("public_key")
        pk && Identity.peer_id_of_public_key(pk) == local_peer
      end
      return false unless local_in_signers

      # M4: count DISTINCT signers with a valid signature over the root content hash.
      root_hash = root.content_hash
      valid = [] of String
      signers.each do |sh|
        s = resolve.call(sh)
        next if s.nil?
        sig = find_signature_by(root_hash, sh, included)
        if sig && Identity.verify_signature(sig, s)
          valid << sh.hexstring
        end
      end
      valid.uniq.size >= threshold
    end

    # ── §5.5 chain verification ────────────────────────────────────────────────────

    def verify_capability_chain(local_peer : String, store : Store, capability : Entity,
                                included : Array(Envelope::Included)) : Bool
      resolve = ->(h : Bytes) { cap_resolve(included, store, h) }
      chain, ok = collect_chain(capability, resolve)
      return false unless ok && chain

      root = chain.last
      if multisig?(root)
        return false unless multisig_root_ok?(local_peer, resolve, root, included)
      else
        root_ok = false
        rgh = root.bytes("granter")
        if rgh
          g = resolve.call(rgh)
          if g
            pk = g.bytes("public_key")
            root_ok = !pk.nil? && Identity.peer_id_of_public_key(pk) == local_peer
          end
        end
        return false unless root_ok
      end

      good = true
      n = chain.size
      i = 0
      while i < n && good
        current = chain[i]
        # signature: signer == granter, verify against granter identity
        gh = current.bytes("granter")
        if gh
          sgn = find_signature(current.content_hash, included)
          granter = resolve.call(gh)
          if sgn && granter
            signer = sgn.bytes("signer")
            good = false unless signer && signer == gh && Identity.verify_signature(sgn, granter)
          else
            good = false
          end
        elsif multisig?(current)
          # §3.6 multi-sig root: authorized by the K-of-N quorum verified above.
        else
          good = false
        end
        # grantee resolution → 401 carve-out
        geh = current.bytes("grantee")
        if geh
          raise UnresolvableGranteeError.new if resolve.call(geh).nil?
        else
          raise UnresolvableGranteeError.new
        end
        # temporal validity
        tnow = now_ms
        nb = current.uint("not_before")
        good = false if nb && tnow < nb
        ex = current.uint("expires_at")
        good = false if ex && ex < tnow
        # delegation link
        if i < n - 1
          parent = chain[i + 1]
          child_peer = link_granter_peer(resolve, local_peer, current)
          parent_peer = link_granter_peer(resolve, local_peer, parent)
          if child_peer.nil? || parent_peer.nil?
            good = false
          else
            pg = parent.bytes("grantee")
            cg = current.bytes("granter")
            unless pg && cg && pg == cg &&
                   attenuated?(local_peer, child_peer, parent_peer, current, parent) &&
                   check_delegation_caveats(parent, current, i)
              good = false
            end
          end
        end
        i += 1
      end
      good
    end

    def revoked?(local_peer : String, store : Store, capability : Entity,
                 included : Array(Envelope::Included)) : Bool
      resolve = ->(h : Bytes) { cap_resolve(included, store, h) }
      chain, ok = collect_chain(capability, resolve)
      root_hash = (ok && chain) ? chain.last.content_hash : capability.content_hash
      !revoke_marker(local_peer, store, capability.content_hash).nil? ||
        !revoke_marker(local_peer, store, root_hash).nil?
    end

    private def revoke_marker(local_peer : String, store : Store, hash : Bytes) : Entity?
      store.get_at("/#{local_peer}/system/capability/revocations/#{hash.hexstring}")
    end

    # ── §5.2 verify-request (3-way verdict) ────────────────────────────────────────

    def verify_request(local_peer : String, store : Store, envelope : Envelope) : RequestVerdict
      exec = envelope.root
      included = envelope.included
      sgn = find_signature(exec.content_hash, included)
      return RequestVerdict::AuthnFail if sgn.nil?

      author_h = exec.bytes("author")
      signer = sgn.bytes("signer")
      return RequestVerdict::AuthnFail unless signer && author_h && signer == author_h

      author = included_get(included, author_h)
      return RequestVerdict::AuthnFail if author.nil?
      return RequestVerdict::AuthnFail unless Identity.verify_signature(sgn, author)

      ch = exec.bytes("capability")
      cap = ch ? included_get(included, ch) : nil
      return RequestVerdict::AuthzDeny if cap.nil?

      # §4.10(b): a chain exceeding max depth → 400 chain_depth_exceeded
      # (structural excess) BEFORE the per-link authz walk — distinct from 403.
      return RequestVerdict::ChainTooDeep if chain_exceeds_depth?(store, cap, included)

      return RequestVerdict::AuthzDeny unless verify_capability_chain(local_peer, store, cap, included)

      grantee = cap.bytes("grantee")
      return RequestVerdict::AuthzDeny unless grantee && author_h && grantee == author_h
      return RequestVerdict::AuthzDeny if revoked?(local_peer, store, cap, included)

      RequestVerdict::Allow
    end
  end
end
