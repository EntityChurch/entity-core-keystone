# frozen_string_literal: true

require "set"

require_relative "entity"
require_relative "envelope"
require_relative "identity"
require_relative "error"

module EntityCore
  # Capability system (L3): the §5 verification core — pattern matching (§5.4),
  # request verification (§5.2 verify_request / check_permission),
  # delegation-chain verification (§5.5), attenuation (§5.6), caveats (§5.7),
  # revocation (§5.1). Derived from the §5 pseudocode directly (spec-first).
  #
  # The verdict is a bare :allow / :deny (§5.10 Layer-1 determinism); the
  # dispatcher maps :deny → 403, with the §5.5 unresolvable-grantee → 401
  # carve-out raised as UnresolvableGranteeError.
  #
  # §PR-8 / §5.5a granter-frame: the RESOURCE dimension's patterns canonicalize
  # against the GRANTER's peer_id; handlers/operations/peers stay on the local
  # frame. For the self-issued dominant path (granter = local) this is
  # byte-identical to the pre-fix behavior; only the foreign-granter cross-peer
  # case flips (exercised at S4).
  module Capability
    BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    BASE58_SET = BASE58_ALPHABET.each_char.to_set.freeze

    # §4.10(b) max delegation-chain depth — an over-deep chain is 400
    # chain_depth_exceeded (structural excess), NOT 403.
    MAX_CHAIN_DEPTH = 64

    Scope = Data.define(:incl, :excl)
    GrantRec = Data.define(:handlers, :resources, :operations, :peers)

    module_function

    # ── grant / scope parse ──────────────────────────────────────────────────

    def parse_scope(map)
      return Scope.new(incl: [], excl: []) if map.nil?

      incl = text_list(map, "include") || []
      excl = text_list(map, "exclude") || []
      Scope.new(incl: incl, excl: excl)
    end

    def parse_grant(map)
      peers = map && map["peers"] ? parse_scope(as_map(map["peers"])) : nil
      GrantRec.new(
        handlers: parse_scope(as_map(map && map["handlers"])),
        resources: parse_scope(as_map(map && map["resources"])),
        operations: parse_scope(as_map(map && map["operations"])),
        peers: peers
      )
    end

    def grants_of_token(token)
      raw = map_list(token.data_map, "grants")
      return [] if raw.nil?

      raw.map { |g| parse_grant(g) }
    end

    # ── §5.4 pattern matching ─────────────────────────────────────────────────

    def normalize_uri(uri)
      uri.start_with?("entity://") ? "/#{uri[9..]}" : uri
    end

    # Resolve peer-relative paths to absolute /{local}/... form.
    def canonicalize(local_peer, path)
      if path.start_with?("./") || path.start_with?("../")
        raise ProtocolError, "canonicalize: reserved directory-relative path"
      end
      raise ProtocolError, "canonicalize: ambiguous bare peer wildcard" if path.start_with?("*/")
      return path if path.start_with?("/")

      "/#{local_peer}/#{path}"
    end

    def matches_pattern(path, pattern)
      return true if pattern == "*"

      if pattern.start_with?("/*/")
        remainder = pattern[3..]
        return false if path.empty?

        i = path.index("/", 1)
        return false if i.nil?

        return matches_pattern(path[(i + 1)..], remainder)
      end
      return path.start_with?(pattern[0...-1]) if pattern.length >= 2 && pattern.end_with?("/*")

      path == pattern
    end

    def matches_scope(local_peer, value, scope)
      cv = canonicalize(local_peer, value)
      covered(local_peer, scope.incl, cv) && !covered(local_peer, scope.excl, cv)
    end

    def covered(frame, pats, cv)
      pats.any? { |p| matches_pattern(cv, canonicalize(frame, p)) }
    end
    private_class_method :covered

    # ── §5.2 check-permission ──────────────────────────────────────────────────

    def first_segment(uri)
      u = uri.start_with?("/") ? uri[1..] : uri
      i = u.index("/")
      i ? u[0...i] : u
    end

    def peer_id?(seg)
      return false if seg.length < 46

      seg.each_char.all? { |c| BASE58_SET.include?(c) }
    end

    def extract_peer(local_peer, uri)
      first = first_segment(normalize_uri(uri))
      peer_id?(first) ? first : local_peer
    end

    # Concrete-target subset (the core surface the oracle exercises). The grant's
    # own resource patterns canonicalize against the GRANTER's peer_id (§PR-8 /
    # V2(a)); the caller-supplied targets/exclude stay on the LOCAL frame (§5.4).
    def check_resource_scope(local_peer, granter_peer, resource, scope)
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

    def covered_frame(frame, pats, value)
      pats.any? { |p| matches_pattern(value, canonicalize(frame, p)) }
    end
    private_class_method :covered_frame

    # §PR-8 — the frame for canonicalizing CAP's grant resource patterns is the
    # GRANTER's peer_id. Single-sig granter → derive peer_id from its
    # public_key; unresolvable → nil (caller falls back to local).
    def resolve_granter_peer_id(resolve, cap)
      gh = cap.bytes("granter")
      return nil if gh.nil?

      g = resolve.call(gh)
      return nil if g.nil?

      pk = g.bytes("public_key")
      pk && Identity.peer_id_of_public_key(pk)
    end

    # Gate the wire request at the dispatch authorization boundary (§3.2.3 /
    # v7.73). +granter_peer+ is the §PR-8 canonicalization frame for the cap's
    # grant resource patterns; every other dimension stays on the local frame.
    def check_permission(local_peer, granter_peer, exec, token, handler_pattern)
      operation = exec.text("operation") || ""
      uri = exec.text("uri") || ""
      target_peer = extract_peer(local_peer, uri)
      resource = exec.map_field("resource")
      grants_of_token(token).each do |g|
        ok = matches_scope(local_peer, operation, g.operations) &&
             matches_scope(local_peer, handler_pattern, g.handlers)
        if ok
          peers = g.peers || Scope.new(incl: [local_peer], excl: [])
          ok = matches_scope(local_peer, target_peer, peers)
        end
        ok = check_resource_scope(local_peer, granter_peer, resource, g.resources) if ok && resource
        return :allow if ok
      end
      :deny
    end

    # ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    def find_signature(target, included)
      included.each do |i|
        e = i.entity
        next unless e.type == "system/signature"

        tg = e.bytes("target")
        return e if tg && tg == target
      end
      nil
    end

    def cap_resolve(included, store, hash)
      e = included_get(included, hash)
      e || store.get_by_hash(hash)
    end

    def included_get(included, hash)
      h = hash.b
      pair = included.find { |i| i.hash == h }
      pair&.entity
    end

    # §PR-8 / §5.5a per-link canonicalization frame for CAP's resource patterns =
    # its granter's peer_id. Multi-sig root (no granter hash) → local_peer.
    # Single-sig: derive from the resolved granter's public_key; unresolvable →
    # nil (caller denies).
    def link_granter_peer(resolve, local_peer, cap)
      gh = cap.bytes("granter")
      return local_peer if gh.nil?

      g = resolve.call(gh)
      return nil if g.nil?

      pk = g.bytes("public_key")
      pk && Identity.peer_id_of_public_key(pk)
    end

    def scope_subset(child_peer, parent_peer, child, parent)
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
    private_class_method :scope_subset

    def grant_subset(local_peer, child_peer, parent_peer, child, parent)
      return false unless scope_subset(local_peer, local_peer, child.handlers, parent.handlers)
      return false unless scope_subset(local_peer, local_peer, child.operations, parent.operations)
      return false unless scope_subset(child_peer, parent_peer, child.resources, parent.resources)

      cp = child.peers || Scope.new(incl: [local_peer], excl: [])
      pp = parent.peers || Scope.new(incl: [local_peer], excl: [])
      scope_subset(local_peer, local_peer, cp, pp)
    end

    def attenuated?(local_peer, child_peer, parent_peer, child, parent)
      cg = grants_of_token(child)
      pg = grants_of_token(parent)
      cg.each do |c|
        return false unless pg.any? { |p| grant_subset(local_peer, child_peer, parent_peer, c, p) }
      end
      pe = parent.uint("expires_at")
      ce = child.uint("expires_at")
      return false if pe && ce.nil? # child infinite, parent finite
      return ce <= pe if pe

      true
    end
    private_class_method :attenuated?

    def check_delegation_caveats(parent, child, depth)
      caveats = parent.map_field("delegation_caveats")
      return true if caveats.nil?
      return false if caveats["no_delegation"] == true

      depth_ok = true
      m = uint(caveats, "max_delegation_depth")
      depth_ok = depth < m if m

      ttl_ok = true
      max_ttl = uint(caveats, "max_delegation_ttl")
      if max_ttl
        ex = child.uint("expires_at")
        cr = child.uint("created_at")
        ttl_ok = if ex && cr
                   (ex - cr) <= max_ttl
                 elsif ex
                   true # created_at absent — can't bound, admit
                 else
                   false # infinite child lifetime exceeds any limit
                 end
      end
      depth_ok && ttl_ok
    end
    private_class_method :check_delegation_caveats

    # Walk parent pointers collecting the chain. Returns +[chain, ok]+.
    def collect_chain(cap, resolve)
      acc = []
      current = cap
      depth = 0
      loop do
        return [nil, false] if depth > MAX_CHAIN_DEPTH

        acc << current
        ph = current.bytes("parent")
        return [acc, true] if ph.nil?

        parent = resolve.call(ph)
        return [nil, false] if parent.nil?

        current = parent
        depth += 1
      end
    end
    private_class_method :collect_chain

    # §4.10(b) structural-bound pre-check: true if the authority chain rooted at
    # +capability+ exceeds the max depth (64). Walks parent pointers WITHOUT
    # verifying signatures — depth is a purely structural property, gated BEFORE
    # the per-link authz walk so an over-deep chain is reported as 400
    # chain_depth_exceeded (structural excess), distinct from a 403
    # capability_denied authz failure (arch ruling, v7.75 §4.10(b)). An
    # UNREACHABLE parent is NOT a depth problem — it returns false here and is
    # left for verify_capability_chain to deny (403).
    def chain_exceeds_depth?(store, capability, included)
      resolve = ->(h) { cap_resolve(included, store, h) }
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

    def verify_capability_chain(local_peer, store, capability, included)
      resolve = ->(h) { cap_resolve(included, store, h) }
      chain, ok = collect_chain(capability, resolve)
      return :deny unless ok

      root = chain.last
      root_ok = false
      rgh = root.bytes("granter")
      if rgh
        g = resolve.call(rgh)
        if g
          pk = g.bytes("public_key")
          root_ok = !pk.nil? && Identity.peer_id_of_public_key(pk) == local_peer
        end
      end
      return :deny unless root_ok

      good = true
      n = chain.length
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
        else
          good = false
        end
        # grantee resolution → 401 carve-out
        geh = current.bytes("grantee")
        if geh
          raise UnresolvableGranteeError if resolve.call(geh).nil?
        else
          raise UnresolvableGranteeError
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
      good ? :allow : :deny
    end

    def revoked?(local_peer, store, capability, included)
      resolve = ->(h) { cap_resolve(included, store, h) }
      chain, ok = collect_chain(capability, resolve)
      root_hash = ok ? chain.last.content_hash : capability.content_hash
      !revoke_marker(local_peer, store, capability.content_hash).nil? ||
        !revoke_marker(local_peer, store, root_hash).nil?
    end

    def revoke_marker(local_peer, store, hash)
      store.get_at("/#{local_peer}/system/capability/revocations/#{hash.b.unpack1('H*')}")
    end
    private_class_method :revoke_marker

    # ── §5.2 verify-request (3-way verdict) ───────────────────────────────────
    #
    # Returns one of :allow / :authn_fail / :authz_deny / :chain_too_deep. The
    # dispatcher maps these to 200-path / 401 / 403 / 400 (§5.2a trichotomy).

    def verify_request(local_peer, store, envelope)
      exec = envelope.root
      included = envelope.included
      sgn = find_signature(exec.content_hash, included)
      return :authn_fail if sgn.nil?

      author_h = exec.bytes("author")
      signer = sgn.bytes("signer")
      return :authn_fail unless signer && author_h && signer == author_h

      author = included_get(included, author_h)
      return :authn_fail if author.nil?
      return :authn_fail unless Identity.verify_signature(sgn, author)

      ch = exec.bytes("capability")
      cap = ch ? included_get(included, ch) : nil
      return :authz_deny if cap.nil?

      # §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
      # chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
      # distinct from 403 capability_denied. The 400 lets the caller distinguish
      # "shorten your chain" from "you lack the capability".
      return :chain_too_deep if chain_exceeds_depth?(store, cap, included)

      return :authz_deny if verify_capability_chain(local_peer, store, cap, included) == :deny

      grantee = cap.bytes("grantee")
      return :authz_deny unless grantee && author_h && grantee == author_h
      return :authz_deny if revoked?(local_peer, store, cap, included)

      :allow
    end

    # ── small typed-field helpers (over a cbor map, nil-safe) ──────────────────

    def as_map(value)
      value if value.is_a?(::Hash)
    end

    def text_list(map, key)
      return nil if map.nil?

      v = map[key]
      return nil unless v.is_a?(::Array)

      v.select { |item| item.is_a?(::String) && item.encoding != Encoding::BINARY }
    end

    def map_list(map, key)
      return nil if map.nil?

      v = map[key]
      return nil unless v.is_a?(::Array)

      v.select { |item| item.is_a?(::Hash) }
    end

    def uint(map, key)
      return nil if map.nil?

      v = map[key]
      v if v.is_a?(::Integer)
    end
  end
end
