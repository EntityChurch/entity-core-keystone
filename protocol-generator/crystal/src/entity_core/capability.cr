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

    # The unmatchable value (0.8.2.20). Unreachable as a canonical path by
    # CONSTRUCTION: its first segment cannot be a peer_id, since peer_id? requires
    # >= 46 Base58 characters and "-" is outside the Base58 alphabet.
    NEVER_MATCH = "/never-match"

    # Resolve peer-relative paths to absolute /{local}/... form.
    #
    # TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". This
    # used to RAISE, and the raise was reachable from the wire — every normative call
    # site is a matcher with no error channel to consume one, so the exception escaped
    # the matcher, the resilience frame caught it, and "../x" in a resource exclude
    # answered 500 (measured 2026-09-14). The diagnostic belongs at admission (§6.5),
    # which has a caller to answer.
    def canonicalize(local_peer : String, path : String) : String
      return NEVER_MATCH if path.starts_with?("./") || path.starts_with?("../")
      return NEVER_MATCH if path.starts_with?("*/")
      return path if path.starts_with?("/")
      "/#{local_peer}/#{path}"
    end

    def matches_pattern(path : String, pattern : String) : Bool
      # NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
      # rule rather than a property of the string: the arm below returns true for a
      # bare "*", so safety must not rest on a value merely looking unmatchable.
      return false if path == NEVER_MATCH || pattern == NEVER_MATCH
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

    # Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
    # call site — no default — so a new one cannot inherit the wrong matcher silently,
    # which is exactly the F40 defect.
    enum ScopeKind
      Id   # operations, peers   — system/capability/id-scope
      Path # handlers, resources — system/capability/path-scope
    end

    # §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
    # forms — bare "*" and a trailing slash-star segment-prefix. None of the §5.4 path
    # transforms apply, so a pattern carrying path syntax is matched as a literal string:
    # a non-match, never a fault.
    def matches_id_pattern(value : String, pattern : String) : Bool
      return true if pattern == "*"
      if pattern.size >= 2 && pattern.ends_with?("/*")
        return value.starts_with?(pattern[0...-1])
      end
      value == pattern
    end

    private def covered_id(pats : Array(String), value : String) : Bool
      pats.any? { |p| matches_id_pattern(value, p) }
    end

    # AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
    # fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
    # fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
    # its author wrote): same value, same matcher, opposite safety direction, so the
    # reading is chosen where the POSITION is known and matches_pattern stays uniform
    # over its operands.
    #
    # EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
    # asked of every dimension, transcribing §5.2's loop before that loop grew its
    # type dispatch. NEVER_MATCH is a §5.4 PATH-canonicalization sentinel and has no
    # meaning on an id-scope dimension, whose patterns are literal identifiers that
    # §5.2's own id-scope arm forbids putting through the §5.4 transforms. Asking it
    # outside the type dispatch ran an id pattern through those transforms purely to
    # classify it and then DENIED THE WHOLE DIMENSION on a property unrelated to
    # whether the exclude carves anything out: an `operations` exclude naming an
    # ordinary namespaced operation with a leading star-slash — a literal matching
    # nothing under the id-scope grammar — canonicalized to the sentinel and denied
    # every operation. Over-denial, and invisible on any well-formed grant.
    private def exclude_unmatchable?(frame : String, excl : Array(String)) : Bool
      excl.any? { |p| canonicalize(frame, p) == NEVER_MATCH }
    end

    def matches_scope(local_peer : String, value : String, scope : Scope, kind : ScopeKind) : Bool
      if kind.id?
        # No sentinel guard here, and that is 0.8.2.24's ruling rather than an
        # omission: §5.4 says "a capability carrying an unmatchable PATH-SCOPE
        # pattern is INVALID ... It does NOT reach `operations` or `peers` [MUST]".
        # Under the id-scope grammar every non-star pattern is a literal, and a
        # literal is never structurally unmatchable, so there is nothing here for
        # the sentinel to detect.
        return covered_id(scope.incl, value) && !covered_id(scope.excl, value)
      end
      return false if exclude_unmatchable?(local_peer, scope.excl)   # 0.8.2.21 — deny
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
      # An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
      # target: the coverage test below is correct in isolation and is simply never
      # reached on a sentinel, because matches_pattern answers false.
      return false if exclude_unmatchable?(granter_peer, scope.excl)
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
        ok = matches_scope(local_peer, operation, g.operations, ScopeKind::Id) &&
             matches_scope(local_peer, handler_pattern, g.handlers, ScopeKind::Path)
        if ok
          peers = g.peers || Scope.new([local_peer], [] of String)
          ok = matches_scope(local_peer, target_peer, peers, ScopeKind::Id)
        end
        ok = check_resource_scope(local_peer, granter_peer, resource, g.resources) if ok && resource
        return true if ok
      end
      false
    end

    # ── §5.2 effective targets and §6.3 check_path_permission ─────────────────────

    # §5.2's effective target list (0.8.2.20): the caller's OWN `resource.exclude`
    # removes entries from the request BEFORE anything else looks at it.
    #
    # The survivors are returned in the caller's OWN SPELLING, not canonicalized —
    # 0.8.2.21 is explicit that `effective_targets` yields raw survivors, and the
    # distinction is load-bearing because the value flows on to the store lookup,
    # which canonicalizes for itself.
    #
    # The second element says whether a `resource` was present AT ALL. An ABSENT
    # resource and a resource whose every target was excluded are different inputs
    # to §3.3, and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them
    # DIFFERENT REQUESTS with different answers.
    #
    # THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
    # "that projection MUST NOT be lossy about its own emptiness — narrow when
    # narrowing leaves something, and retain the raw pair when narrowing would
    # empty it." A function returning only a list cannot satisfy that: collapsing
    # `[qA] exclude [qA]` to `[]` deletes the two-empties discriminator before any
    # handler can read it, and the handler's refusal arm becomes dead code that
    # only a WIRE drive can detect. This peer has exactly ONE narrowing seam — this
    # function, called by the tree handler — and §6.5's dispatch chain does not
    # project, so there is no second door to keep in step.
    def effective_targets(local_peer : String, exec : Entity) : {Array(String), Bool}
      r = exec.map_field("resource")
      return {[] of String, false} if r.nil?
      targets = text_list(r, "targets")
      return {[] of String, false} if targets.nil?
      caller_excl = text_list(r, "exclude") || [] of String
      survivors = targets.reject do |t|
        ct = canonicalize(local_peer, t)
        # The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's
        # table rules it separately from the grant arm): canonicalize answers
        # NEVER_MATCH and matches_pattern then answers false, so the target simply
        # survives. That asymmetry is 0.8.2.21's whole point and it is INHERITED
        # from the primitives here rather than restated.
        caller_excl.any? { |x| matches_pattern(ct, canonicalize(local_peer, x)) }
      end
      {survivors, true}
    end

    # §6.3's handler-level path check.
    #
    # IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever
    # the subject is derived after dispatch, and the dispatch-level check can be
    # made VACUOUS by caller-controlled input: a caller who excludes the one target
    # its capability does not cover removes that target from `check_permission`'s
    # view entirely, and a handler that then acts on it has authorized nothing.
    #
    # THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here — the path is local
    # by construction at this point (§1.4's inbound rule refuses a foreign namespace
    # at §6.5 step 3, before any handler runs), and §6.3's signature names only
    # handlers, operations and resources.
    #
    # THE FRAME IS local_peer, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN SIGNATURE
    # RATHER THAN A CHOICE. §6.3's block reads
    # `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)`
    # — there is no granter parameter to pass. §5.5a governs chain ATTENUATION,
    # where the subject is a pattern compared against a parent's pattern; this call
    # site compares a CONCRETE local path the handler is about to touch.
    #
    # There is no caller-exclude set at this call site: the subject is a single
    # concrete path, and the caller's exclusions have already been applied in
    # deriving it. Every grant exclude covering the subject therefore denies —
    # which `matches_scope` already implements, including 0.8.2.21's sentinel rule,
    # so this function is three calls to it and nothing else.
    #
    # An empty `resources.include` is a legal grant shape (§5.2: handlers that touch
    # no tree paths) and DENIES every path here, which is what that note says it
    # should — `covered` over an empty include list is false.
    def check_path_permission(local_peer : String, operation : String, path : String,
                              token : Entity, handler_pattern : String) : Bool
      # canonicalize is total and may answer NEVER_MATCH, which matches no grant
      # (§5.4) — so a malformed path falls through to DENY rather than being matched
      # against anything.
      cp = canonicalize(local_peer, path)
      grants_of_token(token).each do |g|
        next unless matches_scope(local_peer, handler_pattern, g.handlers, ScopeKind::Path)
        next unless matches_scope(local_peer, operation, g.operations, ScopeKind::Id)
        next unless matches_scope(local_peer, cp, g.resources, ScopeKind::Path)
        return true
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

    # §6.2 CAP-6a: true when every temporal field on a RECEIVED token is either
    # absent (legal) or representable as a UInt64.
    #
    # This is the reader-side half of CAP-6 and it is where a peer fails OPEN. The
    # idiomatic accessor `Entity#uint` answers nil both when a field is ABSENT and
    # when it is PRESENT but not a major-0 EcInt — a negative integer or a bignum —
    # so a token carrying expires_at:-1 silently skipped the expiry check and was
    # honored with 200. §6.2 CAP-6a is explicit: such a token "is malformed. A
    # verifier MUST refuse it and MUST NOT treat the unrepresentable field as
    # absent." An absent expires_at stays legal and is NOT rejected here.
    #
    # Refusal must be the §5.2 capability_denied disposition (a status-bearing
    # response), never a decode-layer silent drop or a transport close.
    def temporal_fields_representable?(tok : Entity) : Bool
      {"expires_at", "not_before", "created_at"}.all? do |key|
        v = tok.data_map[key]?
        v.nil? || (v.is_a?(Cbor::EcInt) && v.major == 0_u8)
      end
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

    # §5.5a/§5.6 attenuation subset, TYPED BY SCOPE KIND (F50, ruled 0.8.2.16).
    #
    # §3.6's grammar binds the SCOPE TYPE, not one function: "An implementation on
    # the canonicalizing reading is non-conformant and MUST adopt the literal
    # matcher." F40 typed `matches_scope` and this sibling was left on the path
    # matcher for all four dimensions, so `operations` and `peers` — both id-scope
    # — were compared with §5.4 canonicalization and wildcard semantics they do not
    # have. The divergence is narrow and FAIL-CLOSED (an include of a namespaced
    # operation is not covered by a parent bare star under the path matcher, which
    # widens nothing but refuses legitimate delegation), which is exactly why no
    # hand-tried example found it.
    #
    # `kind` has NO DEFAULT and is named at every call site, because a default is
    # how the next dimension inherits the wrong matcher silently — the original F40
    # defect.
    private def scope_subset(child_peer : String, parent_peer : String,
                             child : Scope, parent : Scope, kind : ScopeKind) : Bool
      if kind.id?
        # Literal-with-two-wildcards, both operands as written: no canonicalization
        # frame applies to an identifier, so `child_peer`/`parent_peer` are unused
        # on this arm by construction rather than by omission.
        child.incl.each do |cp|
          return false unless parent.incl.any? { |pp| matches_id_pattern(cp, pp) }
        end
        parent.excl.each do |pe|
          return false unless child.excl.any? { |ce| matches_id_pattern(pe, ce) }
        end
        return true
      end
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
      return false unless scope_subset(local_peer, local_peer, child.handlers, parent.handlers, ScopeKind::Path)
      return false unless scope_subset(local_peer, local_peer, child.operations, parent.operations, ScopeKind::Id)
      return false unless scope_subset(child_peer, parent_peer, child.resources, parent.resources, ScopeKind::Path)
      cp = child.peers || Scope.new([local_peer], [] of String)
      pp = parent.peers || Scope.new([local_peer], [] of String)
      scope_subset(local_peer, local_peer, cp, pp, ScopeKind::Id)
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
      verify_capability_chain_rooted_at(local_peer, local_peer, store, capability, included)
    end

    # `verify_capability_chain` with the expected ROOT granter named separately from the
    # verifying peer.
    #
    # §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted
    # by the TARGET peer, so root-trust is relaxed away from the local peer — and every
    # other clause (per-link signatures, grantee resolution, temporal validity,
    # attenuation, caveats) is unchanged. Parameterized rather than forked because a second
    # copy of a chain walk is a second copy that drifts.
    #
    # A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `root_peer`
    # differs from `local_peer` the quorum arm is REFUSED outright rather than verified:
    # *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
    # GROUP's authority — its co-signers authorized it too. Accepting it would let any one
    # signer's target confer the whole group's grant, which is E3/F66's over-acceptance.
    # §5.5's M6 also requires the LOCAL peer in the signer set, so the quorum arm has no
    # meaning in a foreign frame even on its own terms.
    def verify_capability_chain_rooted_at(local_peer : String, root_peer : String,
                                          store : Store, capability : Entity,
                                          included : Array(Envelope::Included)) : Bool
      resolve = ->(h : Bytes) { cap_resolve(included, store, h) }
      chain, ok = collect_chain(capability, resolve)
      return false unless ok && chain

      root = chain.last
      if multisig?(root)
        return false unless root_peer == local_peer &&
                            multisig_root_ok?(local_peer, resolve, root, included)
      else
        root_ok = false
        rgh = root.bytes("granter")
        if rgh
          g = resolve.call(rgh)
          if g
            pk = g.bytes("public_key")
            root_ok = !pk.nil? && Identity.peer_id_of_public_key(pk) == root_peer
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
        # temporal validity.
        #
        # CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
        # created_at is MALFORMED and must be refused outright. This has to run
        # BEFORE the two range checks below, because those use `uint`, which cannot
        # tell "absent" from "present but not a UInt64" — so on its own it would
        # skip the check and honor the token (fail-open).
        good = false unless temporal_fields_representable?(current)
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


    # Decode an ARRAY of nested entities at `key`, falling back to the SINGULAR spelling
    # as a list of one (the §7a.1 transitional carriers).
    #
    # An EMPTY array means absent, not-a-list, or a MALFORMED array (a member that does
    # not decode) — never a silently shorter list, because the caller's all-or-none test
    # would then read a partial credential as a complete one.
    #
    # NO EARLY `return`, and that is not a style preference: a `return` inside the `if`
    # here made the crystal parser report "can't define def inside def" at the NEXT
    # top-level def, 40 lines away — a diagnostic that points at a correct declaration and
    # says nothing about the line that caused it. Bisected against three variants of this
    # body; the one without the early return is the one that compiles. `Entity.from_cbor`
    # RAISES on a malformed member rather than answering nil, so the malformed case falls
    # out through the `rescue` as the empty array.
    def entity_list_field(e : Entity, key : String, singular : String) : Array(Entity)
      out = Array(Entity).new
      v = e.field(key)
      if v.is_a?(Array(Cbor::EcValue))
        begin
          v.each do |item|
            out << Entity.from_cbor(item.as(::Hash(Cbor::EcValue, Cbor::EcValue)))
          end
        rescue
          out = Array(Entity).new
        end
      else
        one = e.entity_field(singular)
        out << one unless one.nil?
      end
      out
    end

    # ── §1.4 PD-2: outbound sub-dispatch authorization ────────────────────────

    # Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
    #
    # §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree`
    # and `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's
    # handler pattern to be the target uri's peer-relative path, because a grant names
    # HANDLERS and a handler pattern never carries a peer segment. Matching a grant
    # against the absolute or schemed form matches nothing, silently, which reads at the
    # wire as an authority refusal.
    #
    # The first segment is dropped ONLY when it is a peer_id. A peer-relative
    # `system/protocol/connect` must not lose `system` — the standing defect on
    # `smalltalk` and `forth`, where an unconditional strip made every self-minted grant
    # unusable while the handshake stayed green.
    def peer_relative_of(uri : String) : String
      p = normalize_uri(uri)
      return p unless p.starts_with?("/")
      body = p[1..]
      slash = body.index('/')
      first = slash ? body[0...slash] : body
      return peer_id?(first) ? (slash ? body[(slash + 1)..] : "") : body
    end

    # Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
    # tolerant of the pattern arriving absolute or peer-relative.
    #
    # §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
    # the grant path is built from the PEER-RELATIVE one. The two are one segment apart
    # and concatenating the wrong one yields a doubled peer segment whose lookup misses —
    # which fails closed as "no handler grant" and is indistinguishable, at the wire, from
    # a genuine authority refusal.
    def grant_path_for(local_peer : String, pattern : String) : String
      prefix = "/#{local_peer}/"
      rel = pattern.starts_with?(prefix) ? pattern[prefix.size..] : pattern
      "/#{local_peer}/system/capability/grants/#{rel}"
    end

    # Verify a presented reentry credential against §1.4's clauses. Answers
    # `{verified, scope}`: `verified` is "did every clause hold", `scope` is the `peers`
    # scope Dimension 4 relaxes to, or nil meaning "the target itself".
    #
    # THE PAIR IS THE POINT. A credential that verifies but carries NO `peers` dimension
    # relaxes to the TARGET — the ordinary reentry shape, "you may dispatch back to me" —
    # so a lone `Scope?` return collapses a legitimate RESULT into "relaxes nothing",
    # which is the absent-vs-present conflation §6.2's CAP-6a records for temporal
    # accessors, one layer up and in the direction that REFUSES a valid reentry.
    def target_minted_peers_relaxation(local_peer : String, target_peer : String,
                                       store : Store, cred : Entity,
                                       included : Array(Envelope::Included)) : {Bool, Scope?}
      # Nothing to relax — the default already covers this peer.
      return {false, nil} if target_peer == local_peer
      return {false, nil} unless verify_capability_chain_rooted_at(local_peer, target_peer,
        store, cred, included)
      return {false, nil} if revoked?(local_peer, store, cred, included)
      gh = cred.bytes("grantee")
      return {false, nil} if gh.nil?
      ge = cap_resolve(included, store, gh)
      return {false, nil} if ge.nil?
      pk = ge.bytes("public_key")
      return {false, nil} if pk.nil? || Identity.peer_id_of_public_key(pk) != local_peer
      gs = grants_of_token(cred)
      return {false, nil} if gs.empty?
      {true, gs[0].peers}
    end

    # §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
    # LEAVES the peer, with all four dimensions applied.
    #
    # ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
    # decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's
    # pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE
    # TARGET PEER naming this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY
    # DIMENSION 4.
    #
    # *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT
    # a grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
    # sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
    # BYPASS it is distinguished from is a peer that treats the credential as a standalone
    # authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
    # obvious vectors agree under either reading, so the only input that separates them is
    # a VALID credential presented to a handler whose own grant does NOT cover the request.
    #
    # `cred == nil` is the ambient arm: Dimension 4 is decided by the handler's grant alone.
    def check_outbound_sub_dispatch(local_peer : String, target_peer : String,
                                    handler_pattern : String, operation : String,
                                    store : Store, handler_grant : Entity, resource : EcMap,
                                    cred : Entity?,
                                    included : Array(Envelope::Included)) : Bool
      # Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
      have_relax = false
      relax_scope = nil.as(Scope?)
      if c = cred
        have_relax, relax_scope = target_minted_peers_relaxation(local_peer, target_peer, store, c, included)
      end
      grants_of_token(handler_grant).each do |g|
        next unless matches_scope(local_peer, handler_pattern, g.handlers, ScopeKind::Path)
        next unless matches_scope(local_peer, operation, g.operations, ScopeKind::Id)
        next unless check_resource_scope(local_peer, local_peer, resource, g.resources)
        # Dimension 4. §5.2's default for an absent `peers` scope is
        # {include: [local_peer_id]}, so a foreign target fails unless this grant names it
        # or a target-minted credential relaxes it.
        peers = g.peers || Scope.new([local_peer], [] of String)
        return true if matches_scope(local_peer, target_peer, peers, ScopeKind::Id)
        if have_relax
          if rs = relax_scope
            return true if matches_scope(local_peer, target_peer, rs, ScopeKind::Id)
          else
            return true # absent `peers` on the credential relaxes to the granter
          end
        end
      end
      false
    end

  end
end
