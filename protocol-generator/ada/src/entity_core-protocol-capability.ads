--  Entity_Core.Protocol.Capability — the §5 capability verdict core (L3).
--
--  The §5 verification surface: pattern matching (§5.4), request verification
--  (§5.2 Verify_Request / Check_Permission), delegation-chain verification
--  (§5.5), attenuation (§5.6), TTL (§5.7), revocation (§5.1). Derived from the
--  §5 pseudocode directly (spec-first).
--
--  §5.2 TRICHOTOMY (A-ADA-008): the request verdict is a DISCRIMINATED type
--  (Request_Verdict) with FOUR cases, mapped at the single dispatch site:
--     Allow            -> proceed
--     Authn_Fail       -> 401 authentication_failed
--     Authz_Deny       -> 403 capability_denied
--     Chain_Too_Deep   -> 400 chain_depth_exceeded  (§4.10 — structural excess,
--                          NOT a 403 authz denial)
--  The §5.5 unresolvable-grantee carve-out (401, not 403) is signalled by the
--  Errors.Unresolvable_Grantee exception, caught at the dispatcher.
--
--  DESIGN-BY-CONTRACT (the Ada rigor seam): Pre/Post aspects guard the verdict
--  logic where they earn it — the chain-depth helper's Max bound, the verdict
--  determinism (N8). Contracts are runtime-checked (SPARK proof out-of-scope
--  v0.1).

with Entity_Core.Bytes;
with Entity_Core.Codec.Value;
with Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Envelope;
with Entity_Core.Protocol.Store;

package Entity_Core.Protocol.Capability is

   use Entity_Core.Bytes;
   use Entity_Core.Protocol.Entity;

   --  §4.10(b) max capability-chain depth (informative default).
   Max_Chain_Depth : constant := 64;

   --  §5.10 Layer-1 binary verdict (crypto + structural linkage + attenuation).
   type Verdict is (Allow, Deny);

   --  §5.2 three-way (four-state) request verdict — the trichotomy + the §4.10
   --  structural-excess case at the single dispatch site.
   type Request_Verdict is (Allow, Authn_Fail, Authz_Deny, Chain_Too_Deep);

   --  §5.2 gate the wire request: signature (PoP) + cap chain + grantee binding
   --  + revocation. N8: a deterministic function of (Local_Peer, store state,
   --  envelope) — no nondeterminism in the Layer-1 verdict.
   function Verify_Request
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Env        : Entity_Core.Protocol.Envelope.Protocol_Envelope) return Request_Verdict;

   --  §4.10(b) structural pre-check: True iff the authority chain rooted at Cap
   --  exceeds Max_Chain_Depth. Walks PARENT pointers counting depth, doing NO
   --  signature work (depth is purely structural), gated BEFORE the per-link
   --  authz walk. An UNREACHABLE parent is NOT a depth problem — it returns
   --  False here and is left for the chain walk to deny (403). This is the one
   --  net-new peer code across the v7.75 cohort.
   function Chain_Exceeds_Depth
     (Store    : access Entity_Core.Protocol.Store.Safe_Store;
      Cap      : Materialized_Entity;
      Env      : Entity_Core.Protocol.Envelope.Protocol_Envelope) return Boolean;

   --  §3.2.3 dispatch authorization: does Token grant Exec on Handler_Pattern?
   --  Granter_Peer is the §PR-8 canonicalization frame for the cap's resource
   --  patterns; every other dimension stays on the local frame.
   function Check_Permission
     (Local_Peer      : String;
      Granter_Peer    : String;
      Exec            : Materialized_Entity;
      Token           : Materialized_Entity;
      Handler_Pattern : String) return Verdict;

   ---------------------------------------------------------------------------
   --  §5.4 pattern + path helpers (also used by the dispatcher).
   ---------------------------------------------------------------------------

   --  Resolve a peer-relative path to the absolute /{Local_Peer}/... form.
   function Canonicalize (Local_Peer : String; Path : String) return String;

   function Normalize_Uri (Uri : String) return String;

   --  True iff Seg looks like a Base58 peer_id (length + alphabet).
   function Is_Peer_Id (Seg : String) return Boolean;

   --  The peer segment that Uri targets (a leading peer_id seg, else Local_Peer).
   function Extract_Peer (Local_Peer : String; Uri : String) return String;

   --  §PR-8: the frame for canonicalizing a cap's resource patterns = its
   --  granter's peer_id. Single-sig granter → derive from public_key;
   --  unresolvable → "" (caller falls back to local).
   function Resolve_Granter_Peer_Id
     (Store : access Entity_Core.Protocol.Store.Safe_Store;
      Env   : Entity_Core.Protocol.Envelope.Protocol_Envelope;
      Cap   : Materialized_Entity) return String;

   --  Find a system/signature entity in Env.included whose target == H.
   function Find_Signature
     (Env : Entity_Core.Protocol.Envelope.Protocol_Envelope;
      H   : Byte_Array;
      Found : out Boolean) return Materialized_Entity;

   ---------------------------------------------------------------------------
   --  §5.2 effective targets and §6.3 check_path_permission.
   ---------------------------------------------------------------------------

   --  §5.2's effective target list (0.8.2.20): the caller's OWN resource.exclude
   --  removes entries from the request BEFORE anything else looks at it.
   --
   --  The survivors come back in the caller's OWN SPELLING, not canonicalized --
   --  0.8.2.21 is explicit that effective_targets yields raw survivors, and the
   --  distinction is load-bearing because the value flows on to the store lookup,
   --  which canonicalizes for itself.
   --
   --  Has_Resource says whether a `resource` was present AT ALL. An ABSENT
   --  resource and a resource whose every target was excluded are different inputs
   --  to §3.3, and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them
   --  DIFFERENT REQUESTS with different answers.
   --
   --  THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
   --  "that projection MUST NOT be lossy about its own emptiness -- narrow when
   --  narrowing leaves something, and retain the raw pair when narrowing would
   --  empty it." A function returning only a list cannot satisfy that: collapsing
   --  a one-target self-excluded request to an empty list deletes the two-empties
   --  discriminator before any handler can read it, and the handler's refusal arm
   --  becomes dead code only a WIRE drive can detect. The (vector, out Boolean)
   --  shape is this package's existing Text_List idiom, which already carries
   --  exactly that discriminator.
   function Effective_Targets
     (Local_Peer   : String;
      Exec         : Materialized_Entity;
      Has_Resource : out Boolean) return Entity_Core.Codec.Value.Value_Vector;

   --  §6.3's handler-level path check.
   --
   --  IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever
   --  the subject is derived after dispatch, and the dispatch-level check can be
   --  made VACUOUS by caller-controlled input: a caller who excludes the one target
   --  its capability does not cover removes that target from Check_Permission's
   --  view entirely, and a handler that then acts on it has authorized nothing.
   --
   --  THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here -- the path is
   --  local by construction at this point (§1.4's inbound rule refuses a foreign
   --  namespace at §6.5 step 3, before any handler runs), and §6.3's signature
   --  names only handlers, operations and resources.
   --
   --  THE FRAME IS Local_Peer, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN
   --  SIGNATURE RATHER THAN A CHOICE. §6.3's block reads
   --  matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)
   --  -- there is no granter parameter to pass. §5.5a governs chain ATTENUATION,
   --  where the subject is a pattern compared against a parent's pattern; this
   --  call site compares a CONCRETE local path the handler is about to touch.
   --
   --  An empty resources.include is a legal grant shape (§5.2: handlers that touch
   --  no tree paths) and DENIES every path here, which is what that note says it
   --  should.
   function Check_Path_Permission
     (Local_Peer      : String;
      Operation       : String;
      Path            : String;
      Token           : Materialized_Entity;
      Handler_Pattern : String) return Boolean;

   --  §6.2 / §5.6 mint-bound: True iff every grant in Requested (a grants
   --  ARRAY) is a subset of SOME grant in Authorized (a grants ARRAY). Used by
   --  the capability/request handler to refuse a grant exceeding the presented
   --  caller capability (scope-widening).
   function Grants_Are_Subset
     (Local_Peer : String;
      Requested, Authorized : Entity_Core.Codec.Value.Ecf_Value) return Boolean;

   ---------------------------------------------------------------------------
   --  §1.4 PD-2: authorizing a locally-originated sub-dispatch (0.8.2.31).
   ---------------------------------------------------------------------------

   --  §5.5 dispatch-time chain verification in the LOCAL frame: the root is a
   --  single-signature root whose `granter` resolves to this peer, or a §3.6
   --  quorum root this peer is a validated member of.
   --
   --  Exported for the PD-2 unit gate's ANTECEDENT assertion. §1.4's
   --  multi-signature clause is measured by a DENY, and a deny establishes
   --  nothing on its own -- a malformed quorum would be refused for reasons that
   --  have nothing to do with §1.4, which is F70 (our own ask against deny-only
   --  checks) and is exactly how the wire's own multisig row passes vacuously.
   --  The unit asserts the SAME quorum verifies here before asserting the foreign
   --  frame refuses it.
   --
   --  Raises Errors.Unresolvable_Grantee for the §5.5 401 carve-out.
   function Verify_Capability_Chain
     (Local_Peer : String;
      Store      : access Entity_Core.Protocol.Store.Safe_Store;
      Cap        : Materialized_Entity;
      Env        : Entity_Core.Protocol.Envelope.Protocol_Envelope) return Verdict;

   --  §1.4's three spellings of one address onto the single form a grant can
   --  match. `system/tree`, `/{peer}/system/tree` and `entity://{peer}/system/tree`
   --  all answer `system/tree`, because a grant names HANDLERS and a handler
   --  pattern never carries a peer segment -- matching a grant against the
   --  absolute or schemed form matches nothing, silently, which reads at the wire
   --  as an authority refusal rather than as a lookup miss.
   --
   --  ⛔ THE FIRST SEGMENT IS DROPPED ONLY WHEN IT IS A PEER_ID. An unconditional
   --  strip turns `system/protocol/connect` into `protocol/connect` -- the standing
   --  `smalltalk`/`forth` defect, where every self-minted grant became unusable
   --  while the handshake stayed green because its own grants are all `*`.
   function Peer_Relative_Of (Local_Peer : String; Uri : String) return String;

   --  Store key of a handler's OWN grant (§6.8: system/capability/grants/{pattern}),
   --  tolerant of Pattern arriving absolute or peer-relative.
   --
   --  §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute,
   --  while the grant path is built from the PEER-RELATIVE one. The two are one
   --  segment apart and concatenating the wrong one yields a doubled peer segment
   --  whose lookup misses -- which fails closed as "no handler grant" and is
   --  indistinguishable, at the wire, from a genuine authority verdict.
   function Grant_Path_For (Local_Peer : String; Pattern : String) return String;

   --  §1.4's PD-2 gate: check_permission run BEFORE a locally-originated
   --  sub-dispatch LEAVES the peer, with all four dimensions applied.
   --
   --  ONE GATE AND ONE EXEMPTION, in §1.4's own words:
   --    * the EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8),
   --      evaluated in the LOCAL frame, with Dimension 1's pattern the target
   --      uri's PEER-RELATIVE path;
   --    * a valid capability MINTED BY THE TARGET PEER naming this peer as
   --      `grantee` relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4, to the
   --      peers that capability covers, evaluated in the TARGET's frame.
   --
   --  "The target answers WHERE; the handler's grant answers WHAT." A credential
   --  is NOT a grant: with no handler grant there is nothing to supply Dimensions
   --  1-3, so the sub-dispatch is refused however good the credential is. That is
   --  the COMPOSE, and the BYPASS it is distinguished from is a peer that treats
   --  the credential as a standalone authorizer and steers past its own grant --
   --  §6.8's confused-deputy substitution. Both obvious vectors agree under either
   --  reading (sources agree -> allow, no source -> refuse), so the ONLY input that
   --  separates them is a VALID credential presented to a handler whose own grant
   --  does NOT cover the request, which MUST refuse.
   --
   --  A credential failing any verification clause relaxes NOTHING and the handler
   --  grant gates unrelaxed -- it does not turn the verdict into an error.
   --
   --  Target_Peer is supplied by the CALLER rather than derived here: on the §6.11
   --  reentry seam the uri may be peer-relative and the destination is the
   --  connection's remote, so Extract_Peer would answer the LOCAL peer and
   --  Dimension 4 would pass vacuously on §5.2's default {include:[local]} -- the
   --  exemption would never be exercised and a bypass would read as a compose.
   --
   --  HAS_CRED IS ITS OWN BIT, because a Materialized_Entity has no null: the
   --  AMBIENT arm (no credential at all) and a credential that happens to be an
   --  empty map are different inputs, and collapsing them would make the ambient
   --  arm look like a credential that relaxes nothing -- which is the same verdict
   --  today and the wrong reason for it.
   function Check_Outbound_Sub_Dispatch
     (Local_Peer      : String;
      Target_Peer     : String;
      Handler_Pattern : String;
      Operation       : String;
      Store           : access Entity_Core.Protocol.Store.Safe_Store;
      Handler_Grant   : Materialized_Entity;
      Resource        : Entity_Core.Codec.Value.Ecf_Value;
      Cred            : Materialized_Entity;
      Has_Cred        : Boolean;
      Env             : Entity_Core.Protocol.Envelope.Protocol_Envelope)
      return Boolean;

end Entity_Core.Protocol.Capability;
