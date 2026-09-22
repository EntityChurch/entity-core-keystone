(* Capability system (L3) — the §5 verification core: pattern matching (§5.4),
   request verification (§5.2 verify_request / check_permission), delegation-chain
   verification (§5.5), and attenuation (§5.6).

   Spec-first stance: derived from the §5 pseudocode directly. Verdict is a bare
   ALLOW/DENY (§5.10 Layer 1 determinism) — the dispatcher maps DENY→403 (with the
   unresolvable_grantee→401 carve-out surfaced via [Unresolvable_grantee]).

   Scopes/grants are parsed out of the token entity's CBOR on demand. *)

type verdict = Allow | Deny

(* unresolvable_grantee is the one §5.5 carve-out that maps to 401, not 403.
   Raised out of chain verification so the dispatcher can pick the status. *)
exception Unresolvable_grantee

type scope = { incl : string list; excl : string list }

type grant = {
  handlers : scope;
  resources : scope;
  operations : scope;
  peers : scope option;
}

(* ── parse helpers ────────────────────────────────────────────────────────── *)

let text_list = function
  | Cbor.Array l ->
      List.filter_map (function Cbor.Text s -> Some s | _ -> None) l
  | _ -> []

let parse_scope (c : Cbor.t) : scope =
  let incl = match Model.map_get c "include" with Some a -> text_list a | None -> [] in
  let excl = match Model.map_get c "exclude" with Some a -> text_list a | None -> [] in
  { incl; excl }

let parse_grant (c : Cbor.t) : grant =
  let sc key = match Model.map_get c key with Some s -> parse_scope s | None -> { incl = []; excl = [] } in
  { handlers = sc "handlers";
    resources = sc "resources";
    operations = sc "operations";
    peers = (match Model.map_get c "peers" with Some s -> Some (parse_scope s) | None -> None) }

let grants_of_token (token : Model.entity) : grant list =
  match Model.field token "grants" with
  | Some (Cbor.Array l) -> List.map parse_grant l
  | _ -> []

(* ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ────────────────── *)

(* [temporal_fields_representable tok] is [true] when every CAP-6a temporal field
   on a RECEIVED token is either ABSENT (legal) or a [Cbor.Uint].

   This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
   [Model.uint_field] collapses "absent" and "present but not a uint" into
   [None], so a token carrying [expires_at: -1] slipped past the expiry check and
   was honoured. §6.2 CAP-6a: such a token "is malformed. A verifier MUST refuse
   it and MUST NOT treat the unrepresentable field as absent."

   Refusal is the §5.2 capability_denied disposition — never a decode-layer
   silent drop, and never a transport close. *)
let temporal_fields_representable (tok : Model.entity) : bool =
  List.for_all
    (fun key ->
      match Model.field tok key with
      | None -> true                (* absent is legal *)
      | Some (Cbor.Uint _) -> true  (* representable *)
      | Some _ -> false)            (* present but undecodable as uint64 *)
    [ "expires_at"; "not_before"; "created_at" ]

(* ── §5.6 temporal ceiling (CAP-5 / CAP-6) ─────────────────────────────────── *)

(* [add_ttl created_at ttl] converts a DURATION term to an absolute timestamp,
   reporting [None] when the term contributes no ceiling.

   §5.6 rule 3: a term whose conversion overflows is treated as ABSENT, exactly
   as a null term is. It MUST NOT wrap and MUST NOT saturate — saturating encodes
   differently from absence and manufactures [expires_at = 2^64-1], a finite
   bound no reader can distinguish from a deliberate one.

   [ttl = 0] is deliberately NOT special-cased: §5.6 rule 2 makes it a DEFINED
   value yielding [created_at] (expire immediately), and letting it fall out of
   the arithmetic is what keeps it from ever collapsing into the absent/"no
   bound" spelling. Values are unsigned 64-bit carried in [int64]. *)
let add_ttl (created_at : int64) (ttl : int64) : int64 option =
  let sum = Int64.add created_at ttl in
  if Int64.unsigned_compare sum created_at < 0 then None (* wrapped => drop *)
  else Some sum

(* [min_defined terms] is §5.6's MIN_DEFINED: the minimum over the DEFINED terms
   only, and [None] when no term is defined (the token genuinely has no expiry).

   Callers pass terms already shaped: absolute timestamps (parent.expires_at,
   caller_capability.expires_at) enter directly; durations (ttl_ms) are converted
   with [add_ttl] first. Mixing a duration in unconverted yields a near-epoch
   timestamp and silently clamps every token to already-expired. *)
let min_defined (terms : int64 option list) : int64 option =
  List.fold_left
    (fun acc t ->
      match acc, t with
      | None, x -> x
      | x, None -> x
      | Some a, Some b -> Some (if Int64.unsigned_compare b a < 0 then b else a))
    None terms

(* ── §5.4 pattern matching ────────────────────────────────────────────────── *)

let starts_with ~prefix s =
  String.length s >= String.length prefix && String.sub s 0 (String.length prefix) = prefix

(* URI normalization (§1.4): strip the entity:// scheme and prepend "/" to
   produce an absolute path; peer-relative paths pass through to canonicalize. *)
let normalize_uri (uri : string) : string =
  if starts_with ~prefix:"entity://" uri then "/" ^ String.sub uri 9 (String.length uri - 9)
  else uri

(* The unmatchable value (0.8.2.20). Unreachable as a canonical path by
   CONSTRUCTION: its first segment cannot be a peer_id, since is_peer_id requires
   >= 46 Base58 characters and '-' is outside the Base58 alphabet. *)
let never_match = "/never-match"

(* Resolve peer-relative paths to absolute "/{local}/..." form.

   TOTAL (0.8.2.20): the return domain is "a canonical path OR never_match". This
   used to raise Invalid_argument, and the raise was reachable from the wire —
   every normative call site is a matcher with no error channel to consume one, so
   the exception escaped the matcher, the resilience frame caught it, and "../x" in
   a resource exclude answered 500 (measured 2026-09-14). The diagnostic belongs at
   admission (§6.5), which has a caller to answer. *)
let canonicalize ~local_peer (path : string) : string =
  if starts_with ~prefix:"./" path || starts_with ~prefix:"../" path then never_match
  else if starts_with ~prefix:"*/" path then never_match
  else if starts_with ~prefix:"/" path then path
  else "/" ^ local_peer ^ "/" ^ path

(* Both path and pattern MUST already be canonical (absolute). *)
let rec matches_pattern (path : string) (pattern : string) : bool =
  (* never_match never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
     rule rather than a property of the string: the arm below returns true for a
     bare "*", so safety must not rest on a value merely looking unmatchable. *)
  if String.equal path never_match || String.equal pattern never_match then false
  else if String.equal pattern "*" then true
  else if starts_with ~prefix:"/*/" pattern then begin
    let remainder = String.sub pattern 3 (String.length pattern - 3) in
    (* path is /{peer}/rest — strip the peer segment *)
    if String.length path < 1 then false
    else
      match String.index_from_opt path 1 '/' with
      | None -> false
      | Some i -> matches_pattern (String.sub path (i + 1) (String.length path - i - 1)) remainder
  end
  else if starts_with ~prefix:"" pattern && String.length pattern >= 2
          && String.sub pattern (String.length pattern - 2) 2 = "/*" then
    let prefix = String.sub pattern 0 (String.length pattern - 1) in (* keep trailing / *)
    starts_with ~prefix path
  else String.equal path pattern

(* Which §5.2 matcher a grant dimension uses (0.8.1, F40). Named at every call site --
   there is no default -- so a new one cannot inherit the wrong matcher silently, which
   is exactly the F40 defect. *)
type scope_kind =
  | Id_scope    (* operations, peers  -- system/capability/id-scope *)
  | Path_scope  (* handlers, resources -- system/capability/path-scope *)

(* §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
   -- bare "*" and a trailing slash-star segment-prefix. None of the §5.4 path
   transforms apply, so a pattern carrying path syntax is matched as a literal string:
   a non-match, never a fault. *)
let matches_id_pattern (value : string) (pattern : string) : bool =
  if String.equal pattern "*" then true
  else
    let plen = String.length pattern in
    if plen >= 2 && String.equal (String.sub pattern (plen - 2) 2) "/*" then
      let prefix = String.sub pattern 0 (plen - 1) in
      String.length value >= plen - 1
      && String.equal (String.sub value 0 (plen - 1)) prefix
    else String.equal value pattern

(* AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
   fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
   fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
   its author wrote): same value, same matcher, opposite safety direction, so the
   reading is chosen where the POSITION is known and matches_pattern stays uniform
   over its operands.

   EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
   asked of every dimension, transcribing §5.2's loop before that loop grew its
   type dispatch. [never_match] is a §5.4 PATH-canonicalization sentinel and has
   no meaning on an id-scope dimension, whose patterns are literal identifiers
   that §5.2's own id-scope arm forbids putting through the §5.4 transforms.
   Asking it outside the type dispatch ran an id pattern through those transforms
   purely to classify it and then DENIED THE WHOLE DIMENSION on a property
   unrelated to whether the exclude carves anything out: an [operations] exclude
   of "*/apply" -- an ordinary namespaced operation name, a literal matching
   nothing under the id-scope grammar -- canonicalized to the sentinel and denied
   every operation. Over-denial, and invisible on any well-formed grant. *)
let exclude_is_unmatchable ~frame (excl : string list) : bool =
  List.exists (fun p -> String.equal (canonicalize ~local_peer:frame p) never_match) excl

let matches_scope ~local_peer ~(kind : scope_kind) (value : string) (s : scope) : bool =
  (* SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
     [if dimension_type == "system/capability/path-scope"], and §5.4's rule is
     likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID
     ... It does NOT reach `operations` or `peers` [MUST]". The two id-scope
     dimensions reach the literal arm below unguarded, which is correct: under the
     id-scope grammar every non-"*" pattern is a literal, and a literal is never
     structurally unmatchable, so there is nothing here for the sentinel to detect.
     (§5.4 says so outright and leaves the id-scope form of the carves-out-nothing
     hazard deliberately open rather than minting a second sentinel for it -- so
     this is a scope boundary, not an omission.) *)
  if kind = Path_scope && exclude_is_unmatchable ~frame:local_peer s.excl then false
  else
  let covered =
    match kind with
    | Id_scope -> fun pats -> List.exists (fun p -> matches_id_pattern value p) pats
    | Path_scope ->
      let cv = canonicalize ~local_peer value in
      fun pats -> List.exists (fun p -> matches_pattern cv (canonicalize ~local_peer p)) pats
  in
  if not (covered s.incl) then false
  else not (covered s.excl)

(* ── §5.2 check_permission ────────────────────────────────────────────────── *)

let first_segment (uri : string) : string =
  let uri = if starts_with ~prefix:"/" uri then String.sub uri 1 (String.length uri - 1) else uri in
  match String.index_opt uri '/' with Some i -> String.sub uri 0 i | None -> uri

let is_peer_id seg =
  String.length seg >= 46
  && String.for_all (fun c -> String.contains Base58.alphabet c) seg

let extract_peer ~local_peer (uri : string) : string =
  let first = first_segment (normalize_uri uri) in
  if is_peer_id first then first else local_peer

(* check_resource_scope — concrete-target subset only (the core surface the
   oracle exercises: tree get/put carry concrete resource targets). Pattern
   targets fall back to include-coverage.

   §PR-8 frame discipline (v7.73): the GRANT's resource patterns (s.incl/s.excl)
   canonicalize against the GRANTER's peer_id [~granter_peer], NOT the verifier's.
   A bare "*" on a foreign-granted cap means "/{granter}/*" — the granter's own
   namespace — not the local peer's. The request TARGET and the caller's resource
   EXCLUDE stay on the local/request frame (§5.4). For the self-issued dominant
   path granter = local, so this is byte-identical to the pre-fix behavior; only
   the foreign-granter cross-peer case (V2(a)) flips from admit to deny. *)
let check_resource_scope ~local_peer ~granter_peer (resource : Cbor.t) (s : scope) : bool =
  let targets = match Model.map_get resource "targets" with Some a -> text_list a | None -> [] in
  let caller_excl = match Model.map_get resource "exclude" with Some a -> text_list a | None -> [] in
  (* local/request frame: request target + caller-supplied exclude (§5.4) *)
  let covered_local pats v = List.exists (fun p -> matches_pattern v (canonicalize ~local_peer p)) pats in
  (* granter frame: the grant's own resource patterns (§PR-8) *)
  let covered_grant pats v = List.exists (fun p -> matches_pattern v (canonicalize ~local_peer:granter_peer p)) pats in
  targets <> [] &&
  (* An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
     target: the coverage test below is correct in isolation and is simply never
     reached on a sentinel, because matches_pattern answers false.

     UNGUARDED ON PURPOSE, unlike [matches_scope]'s (0.8.2.24): [s] here is always
     the RESOURCES dimension, which §5.2 fixes as path-scope, so the type test this
     call site would perform is a constant. Naming the dimension in the signature is
     what makes that checkable -- a frame argument on an id-scope call site is the
     defect. Do NOT "fix" this by copying the [kind = Path_scope &&] guard across. *)
  not (exclude_is_unmatchable ~frame:granter_peer s.excl) &&
  List.for_all
    (fun tgt ->
      let ct = canonicalize ~local_peer tgt in
      if covered_local caller_excl ct then true          (* caller excluded it (local frame) *)
      else if not (covered_grant s.incl ct) then false   (* not in grant include (granter frame) *)
      else not (covered_grant s.excl ct))                (* in grant exclude → deny (granter frame) *)
    targets

(* resolve_granter_peer_id (§PR-8) — the frame for canonicalizing a cap's grant
   resource patterns is the GRANTER's peer_id. Resolve it from the leaf cap's
   granter identity: single-sig granter → derive peer_id from its public_key;
   multi-sig granter (a {signers, threshold} descriptor with no single public_key,
   or an unresolvable granter) → None, and the caller falls back to the local peer
   (M3 root-only — the local peer is the canonicalization frame for a root multisig
   granter). [resolve_fn] is the same included-then-store lookup the chain walk uses. *)
let resolve_granter_peer_id ~resolve_fn (cap : Model.entity) : string option =
  match Model.bytes_field cap "granter" with
  | None -> None
  | Some gh ->
      (match resolve_fn gh with
       | Some g ->
           (match Model.bytes_field g "public_key" with
            | Some pk -> Some (Identity.peer_id_of_pubkey pk)
            | None -> None)                                (* multisig / no single key → local *)
       | None -> None)                                     (* unresolvable granter → local *)

(* check_permission gates the wire request at the dispatch authorization boundary.
   [~granter_peer] is the §PR-8 canonicalization frame for the cap's grant resource
   patterns (resolved at the dispatch site via [resolve_granter_peer_id]); every
   other dimension — operation, handler, target peer scope — stays on the local
   frame. Per §3.2.3 the v7.73 gate is this dispatch boundary only. *)
let check_permission ~local_peer ~granter_peer (exec : Model.entity) (token : Model.entity)
    ~(handler_pattern : string) : verdict =
  let operation = Option.value ~default:"" (Model.text_field exec "operation") in
  let uri = Option.value ~default:"" (Model.text_field exec "uri") in
  let target_peer = extract_peer ~local_peer uri in
  let resource = Model.field exec "resource" in
  let grant_ok g =
    matches_scope ~local_peer ~kind:Id_scope operation g.operations
    && matches_scope ~local_peer ~kind:Path_scope handler_pattern g.handlers
    && (let peers = Option.value ~default:{ incl = [ local_peer ]; excl = [] } g.peers in
        matches_scope ~local_peer ~kind:Id_scope target_peer peers)
    && (match resource with
        | None -> true
        | Some r -> check_resource_scope ~local_peer ~granter_peer r g.resources)
  in
  if List.exists grant_ok (grants_of_token token) then Allow else Deny

(* ── §5.2 effective targets and §6.3 check_path_permission ─────────────────── *)

(* [effective_targets ~local_peer exec] derives §5.2's effective target list
   (0.8.2.20): the caller's OWN [resource.exclude] removes entries from the
   request BEFORE anything else looks at it.

   The survivors come back in the caller's OWN SPELLING, not canonicalized --
   0.8.2.21 is explicit that [effective_targets] yields raw survivors, and the
   distinction is load-bearing here because the value flows on to
   [Store.get_at], which canonicalizes for itself.

   The second component says whether a [resource] was present AT ALL. An ABSENT
   resource and a resource whose every target was excluded are different inputs
   to §3.3 -- the first is "no resource", the second is an empty effective list --
   and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT
   REQUESTS with different answers, not merely different inputs to one.

   THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
   "where an implementation projects resource.targets onto the effective set ahead
   of the handler, that projection MUST NOT be lossy about its own emptiness --
   narrow when narrowing leaves something, and retain the raw pair when narrowing
   would empty it." A function returning only a list cannot satisfy that:
   collapsing [qA] exclude [qA] to [] deletes the two-empties discriminator before
   any handler can read it, and the handler's refusal arm becomes dead code that
   only a WIRE drive can detect. Returning the flag beside the survivors keeps the
   discriminator by construction.

   This peer has exactly ONE narrowing seam -- this function, called by the tree
   handler -- and §6.5's dispatch chain does not project: [dispatch] passes [exec]
   through untouched and [check_permission] reads [resource] for itself. So there
   is no second door to keep in step, and adding a projection at dispatch would
   create one.

   PRESENT-BUT-ILL-TYPED [targets] IS **PRESENT**. [text_list] answers [] for a
   non-array, so [{targets: 42}] yields an EMPTY EFFECTIVE LIST rather than the
   absent case -- which on [get] is 400 path_required rather than the root listing.
   Reading it as absent would serve a PRESENT resource the wider absent-case
   answer §3.3 forbids: N11's own defect ("a projection lossy about its own
   emptiness") one field over. It is what separates the [None] arm below, which
   tests for the KEY, from the value's type. The two vanguards were on opposite
   sides of this cell until 0.8.2.25 and were corrected toward [go].

   OPEN, AND ALL THREE PEERS ANSWER IT THE SAME WAY WITH NO TEXT BEHIND THEM: a
   [resource] map carrying NO [targets] key at all is reported ABSENT here, so
   [get] serves it the root listing. §3.2 says "targets — Array of paths or
   patterns this operation accesses. MUST contain at least one entry", which makes
   that shape a MALFORMED resource rather than an absent one. Left as shipped
   rather than decided in a sweep (the F86 precedent): the disposition a malformed
   [resource] earns is not pinned anywhere and nothing in the 778-check set drives
   the shape. *)
let effective_targets ~local_peer (exec : Model.entity) : string list * bool =
  match Model.field exec "resource" with
  | Some (Cbor.Map _ as r) -> (
      match Model.map_get r "targets" with
      | None -> ([], false)
      | Some tv ->
          let targets = text_list tv in
          let caller_excl =
            match Model.map_get r "exclude" with Some a -> text_list a | None -> []
          in
          let survivors =
            List.filter
              (fun t ->
                let ct = canonicalize ~local_peer t in
                (* The caller-exclude arm is fail-OPEN on an unmatchable pattern
                   (§5.4's table rules it separately from the grant arm):
                   [canonicalize] answers [never_match] and [matches_pattern] then
                   answers false, so the target simply survives. That asymmetry is
                   0.8.2.21's whole point and it is INHERITED here rather than
                   restated. *)
                not (List.exists (fun x -> matches_pattern ct (canonicalize ~local_peer x)) caller_excl))
              targets
          in
          (survivors, true))
  | _ -> ([], false)

(* [check_path_permission] is §6.3's handler-level path check.

   IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever the
   subject is derived after dispatch, and the dispatch-level check can be made
   VACUOUS by caller-controlled input: a caller who excludes the one target its
   capability does not cover removes that target from [check_permission]'s view
   entirely, and a handler that then acts on it has authorized nothing.

   THREE DIMENSIONS, NOT FOUR. [peers] is not consulted here -- the path is local
   by construction at this point (§1.4's inbound rule refuses a foreign namespace
   at §6.5 step 3, before any handler runs), and §6.3's signature names only
   handlers, operations and resources.

   THE FRAME IS [local_peer], NOT THE GRANTER, AND THAT IS THE SPEC'S OWN SIGNATURE
   RATHER THAN A CHOICE. §6.3's block reads
   [matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)] --
   there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where
   the subject is a pattern being compared against a parent's pattern; this call
   site compares a CONCRETE LOCAL PATH the handler is about to touch. The first
   [go] cut threaded the per-link granter frame in by analogy with §5.5a and was
   wrong; the sibling [python] peer had it right and said so at the definition,
   which is what caught it.

   There is no caller-exclude set at this call site: the subject is a single
   concrete path, and the caller's exclusions have already been applied in deriving
   it. Every grant exclude covering the subject therefore denies -- which
   [matches_scope] already implements, including 0.8.2.21's sentinel rule, so this
   function is three calls to it and nothing else.

   An empty [resources.include] is a legal grant shape (§5.2: handlers that touch
   no tree paths) and DENIES every path here, which is what that note says it
   should -- coverage over an empty include list is false. And a MALFORMED path
   canonicalizes to [never_match], which matches no grant (§5.4), so it falls
   through to DENY rather than being matched against anything. *)
let check_path_permission ~local_peer ~(operation : string) ~(path : string)
    ~(token : Model.entity) ~(handler_pattern : string) : bool =
  let cp = canonicalize ~local_peer path in
  List.exists
    (fun g ->
      matches_scope ~local_peer ~kind:Path_scope handler_pattern g.handlers
      && matches_scope ~local_peer ~kind:Id_scope operation g.operations
      && matches_scope ~local_peer ~kind:Path_scope cp g.resources)
    (grants_of_token token)

(* ── §5.5 / §5.6 chain verification + attenuation ─────────────────────────── *)

let hash_equals = String.equal
let now_ms () = Int64.of_float (Unix.gettimeofday () *. 1000.)

let find_signature ~(target : string) (included : (string * Model.entity) list) : Model.entity option =
  List.find_map
    (fun (_, e) ->
      if String.equal e.Model.typ "system/signature"
         && (match Model.bytes_field e "target" with Some t -> hash_equals t target | None -> false)
      then Some e else None)
    included

let resolve included store h =
  match List.assoc_opt h (List.map (fun (k, e) -> (k, e)) included) with
  | Some e -> Some e
  | None -> Store.get_by_hash store h

(* link_granter_peer (§5.5a) — the per-link canonicalization frame for a chain
   link's resource patterns is its granter's peer_id.
     - single-sig granter (a system/hash) → derive peer_id from the resolved
       granter identity's public_key. Per the Amendment-1 §4 scrutiny item we
       adopt the PREFERRED HARD-FAIL shape: an unresolvable granter identity, or a
       resolved entity that yields no public_key, returns None and the caller
       DENIES the chain walk — never a silent fallback to the local frame (which
       would re-admit the V1' bug class for an attacker-crafted granter).
     - multi-sig granter (no single hash; root-only per M3) → Some local_peer:
       the M3 root canonicalizes against the local peer. *)
let link_granter_peer ~resolve_fn ~local_peer (cap : Model.entity) : string option =
  match Model.bytes_field cap "granter" with
  | None -> Some local_peer                          (* multi-sig root (M3) → local frame *)
  | Some gh ->
      (match resolve_fn gh with
       | Some g ->
           (match Model.bytes_field g "public_key" with
            | Some pk -> Some (Identity.peer_id_of_pubkey pk)
            | None -> None)                           (* present identity, no key → deny *)
       | None -> None)                                (* unresolvable granter → deny *)

(* scope_subset (§5.6): every child include covered by parent include; child
   inherits all parent excludes.

   TYPED BY SCOPE KIND, EXACTLY AS ITS SIBLING [matches_scope] IS (F50, ruled
   0.8.2.16). §3.6's grammar binds the SCOPE TYPE, not one function: "an
   implementation on the canonicalizing reading is non-conformant and MUST adopt
   the literal matcher." F40 fixed [matches_scope] and left this one behind, and
   the two readings AGREE on every well-formed grant -- which is why no hand-tried
   example found it. [entity-core-formalization] measured the disagreement on
   [lean]: 2 of 64 include pairs and 2 of 64 exclude pairs, fail-CLOSED
   ("/tree/get" vs "*", "*/apply" vs "*"), against 0 over a 16-pair control
   alphabet. Fail-closed here means an over-narrow delegation refusal, not an
   over-grant -- but the direction is not the point, the matcher is.

   [~kind] is named at every call site with NO DEFAULT, because a default is how
   the next dimension inherits the wrong matcher silently, which is the original
   F40 defect.

   §PR-8 / §5.5a (Amendment 1): on the PATH arm each side's patterns canonicalize
   against THAT side's granter peer_id -- [~child_peer] for the child grant's
   patterns, [~parent_peer] for the parent grant's. For the resource dimension
   these are the per-link granter frames; for handler/operation/peer dimensions
   both are the local frame (no §PR-8 there). The ID arm takes no frame at all:
   an id pattern is a literal, and there is nothing to canonicalize it against. *)
let scope_subset ~child_peer ~parent_peer ~(kind : scope_kind) (child : scope) (parent : scope) : bool =
  (match kind with
   | Id_scope ->
       List.for_all
         (fun cp -> List.exists (fun pp -> matches_id_pattern cp pp) parent.incl)
         child.incl
       && List.for_all
            (fun pe -> List.exists (fun ce -> matches_id_pattern pe ce) child.excl)
            parent.excl
   | Path_scope ->
       List.for_all
         (fun cp ->
           let cc = canonicalize ~local_peer:child_peer cp in
           List.exists (fun pp -> matches_pattern cc (canonicalize ~local_peer:parent_peer pp)) parent.incl)
         child.incl
       && List.for_all
            (fun pe ->
              let cpe = canonicalize ~local_peer:parent_peer pe in
              List.exists (fun ce -> matches_pattern cpe (canonicalize ~local_peer:child_peer ce)) child.excl)
            parent.excl)

(* [~child_peer]/[~parent_peer] are the §5.5a per-link granter frames applied to
   the RESOURCE dimension only; handlers/operations/peers stay on [~local_peer].
   [~kind] follows §5.2's dimension table, not the frame: handlers/resources are
   path-scope, operations/peers id-scope. *)
let grant_subset ~local_peer ~child_peer ~parent_peer (child : grant) (parent : grant) : bool =
  scope_subset ~child_peer:local_peer ~parent_peer:local_peer ~kind:Path_scope child.handlers parent.handlers
  && scope_subset ~child_peer:local_peer ~parent_peer:local_peer ~kind:Id_scope child.operations parent.operations
  && scope_subset ~child_peer ~parent_peer ~kind:Path_scope child.resources parent.resources
  && (let cp = Option.value ~default:{ incl = [ local_peer ]; excl = [] } child.peers in
      let pp = Option.value ~default:{ incl = [ local_peer ]; excl = [] } parent.peers in
      scope_subset ~child_peer:local_peer ~parent_peer:local_peer ~kind:Id_scope cp pp)

let is_attenuated ~local_peer ~child_peer ~parent_peer (child : Model.entity) (parent : Model.entity) : bool =
  let cg = grants_of_token child and pg = grants_of_token parent in
  List.for_all
    (fun c -> List.exists (fun p -> grant_subset ~local_peer ~child_peer ~parent_peer c p) pg)
    cg
  && (match Model.uint_field parent "expires_at", Model.uint_field child "expires_at" with
      | Some _, None -> false                                    (* child infinite, parent finite *)
      | Some pe, Some ce -> Int64.unsigned_compare ce pe <= 0
      | None, _ -> true)

(* check_delegation_caveats (§5.7) — parent's caveats constrain its direct child. *)
let check_delegation_caveats ~(parent : Model.entity) ~(child : Model.entity) ~(depth : int) : bool =
  match Model.field parent "delegation_caveats" with
  | None -> true
  | Some caveats ->
      let no_deleg = match Model.map_get caveats "no_delegation" with Some (Cbor.Bool b) -> b | _ -> false in
      if no_deleg then false
      else begin
        let depth_ok =
          match Model.map_get caveats "max_delegation_depth" with
          | Some (Cbor.Uint m) -> Int64.compare (Int64.of_int depth) m < 0
          | _ -> true
        in
        let ttl_ok =
          match Model.map_get caveats "max_delegation_ttl" with
          | Some (Cbor.Uint maxttl) -> (
              match Model.uint_field child "expires_at", Model.uint_field child "created_at" with
              | Some ex, Some cr -> Int64.unsigned_compare (Int64.sub ex cr) maxttl <= 0
              | Some _, None -> true
              | None, _ -> false)  (* infinite child lifetime exceeds any finite limit *)
          | _ -> true
        in
        depth_ok && ttl_ok
      end

(* collect_authority_chain (§5.5) — walk to root via parent hashes. *)
let collect_chain (cap : Model.entity) ~resolve_fn : (Model.entity list, string) result =
  let rec go current depth acc =
    if depth > 64 then Error "ChainTooDeep"
    else
      let acc = current :: acc in
      match Model.bytes_field current "parent" with
      | None -> Ok (List.rev acc)             (* root reached *)
      | Some ph ->
          (match resolve_fn ph with
           | Some parent -> go parent (depth + 1) acc
           | None -> Error "ChainUnreachable")
  in
  go cap 0 []

(* §4.10(b) structural-bound pre-check: true if the authority chain rooted at
   [capability] exceeds the max depth (64). Walks parent pointers without verifying
   signatures — depth is a purely structural property, gated BEFORE the per-link
   authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
   (structural excess), distinct from a 403 capability_denied authz failure (arch
   ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
   returns false here and is left for [verify_capability_chain] to deny (403). *)
let chain_exceeds_depth ~store (capability : Model.entity)
    (included : (string * Model.entity) list) : bool =
  let resolve_fn = resolve included store in
  let rec go current depth =
    if depth > 64 then true
    else
      match Model.bytes_field current "parent" with
      | None -> false                          (* root reached within bound *)
      | Some ph ->
          (match resolve_fn ph with
           | Some parent -> go parent (depth + 1)
           | None -> false)                    (* unreachable — not a depth problem *)
  in
  go capability 0

(* ── §3.6 M3 multi-signature granter ───────────────────────────────────────
   The capability `granter` field is a union (§3.6): a single system/hash
   (single-sig) or a {signers: [system/hash], threshold: uint} descriptor
   (multi-sig, root-only). A multi-sig root is verified by [verify_multisig_root]
   — M3 structure first, then §5.5 M6 root-at-local + M4 k-of-n quorum. *)
type multi_granter = { signers : string list; threshold : int64 }

let multi_granter_of_entity (cap : Model.entity) : multi_granter option =
  match Model.field cap "granter" with
  | Some (Cbor.Map _ as g) ->
      let signers =
        match Model.map_get g "signers" with
        | Some (Cbor.Array xs) ->
            List.filter_map (function Cbor.Bytes b -> Some b | _ -> None) xs
        | _ -> []
      in
      let threshold =
        match Model.map_get g "threshold" with Some (Cbor.Uint t) -> t | _ -> 0L
      in
      Some { signers; threshold }
  | _ -> None

let is_multisig (cap : Model.entity) : bool = multi_granter_of_entity cap <> None

let has_duplicate_signers (signers : string list) : bool =
  let rec go seen = function
    | [] -> false
    | s :: rest -> List.mem s seen || go (s :: seen) rest
  in
  go [] signers

let find_signatures_targeting ~(target : string) (included : (string * Model.entity) list) :
    Model.entity list =
  List.filter_map
    (fun (_, e) ->
      if String.equal e.Model.typ "system/signature"
         && (match Model.bytes_field e "target" with Some t -> hash_equals t target | None -> false)
      then Some e
      else None)
    included

(* verify_multisig_root (§3.6 M3 / §5.5 M4·M6). ALLOW only if the quorum is
   well-formed AND a threshold of DISTINCT signers signed the cap's content hash.
   Structural validation (M3) precedes signature counting (§3.6 precedence 25): a
   malformed quorum is denied on its structure, not on its signatures. Every path
   returns a bool → the dispatcher maps false to 403 capability_denied. *)
let verify_multisig_root ~local_peer ~resolve_fn (cap : Model.entity) (mg : multi_granter)
    (included : (string * Model.entity) list) : bool =
  let n = List.length mg.signers in
  let peer_id_of h =
    match resolve_fn h with
    | Some p -> (
        match Model.bytes_field p "public_key" with
        | Some pk -> Some (Identity.peer_id_of_pubkey pk)
        | None -> None)
    | None -> None
  in
  (* §3.6 M3 structure — root-only; real quorum (n ≥ 2); usable threshold
     (2 ≤ threshold ≤ n); distinct signers. *)
  Model.bytes_field cap "parent" = None
  && n >= 2
  && Int64.compare mg.threshold 2L >= 0
  && Int64.compare mg.threshold (Int64.of_int n) <= 0
  && not (has_duplicate_signers mg.signers)
  (* §5.5 M6 root-at-local — the local peer MUST be a quorum member. *)
  && List.exists (fun s -> peer_id_of s = Some local_peer) mg.signers
  (* temporal validity + grantee resolution (as for any root). *)
  && (let t = now_ms () in
      (match Model.uint_field cap "not_before" with
       | Some nb -> Int64.unsigned_compare t nb >= 0
       | None -> true)
      && (match Model.uint_field cap "expires_at" with
          | Some ex -> Int64.unsigned_compare ex t >= 0
          | None -> true))
  && (match Model.bytes_field cap "grantee" with Some gh -> resolve_fn gh <> None | None -> false)
  (* §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the
     cap's content hash; ≥ threshold ⇒ quorum. *)
  && (let sigs = find_signatures_targeting ~target:cap.Model.hash included in
      let valid =
        List.fold_left
          (fun acc s ->
            if List.mem s acc then acc
            else
              match resolve_fn s with
              | None -> acc
              | Some signer_peer ->
                  let signed =
                    List.exists
                      (fun sgn ->
                        (match Model.bytes_field sgn "signer" with
                         | Some sg -> hash_equals sg s
                         | None -> false)
                        && Identity.verify_signature sgn signer_peer)
                      sigs
                  in
                  if signed then s :: acc else acc)
          [] mg.signers
      in
      Int64.compare (Int64.of_int (List.length valid)) mg.threshold >= 0)

(* verify_capability_chain (§5.5). Single-sig root roots at the local peer; a
   §3.6 M3 multi-sig root (root-only) passes k-of-n quorum via
   [verify_multisig_root]. Returns Allow/Deny; raises Unresolvable_grantee for the
   §5.5 401 carve-out.

   [?root_peer] names the expected ROOT granter separately from the verifying peer,
   defaulting to [local_peer]. §1.4's PD-2 presented-authority arm needs it: the
   credential it evaluates is minted by the TARGET peer, so root-trust is relaxed
   away from the local peer — and every other clause (per-link signatures, grantee
   resolution, temporal validity, attenuation, caveats) is unchanged. Parameterized
   rather than forked because a second copy of a chain walk is a second copy that
   drifts, and the clauses below are where the authority decision actually lives.

   A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
   [root_peer <> local_peer] the quorum arm is REFUSED outright rather than verified:
   "minted by the target" means the target SOLELY minted it, and a K-of-N root is a
   GROUP's authority — its co-signers authorized it too. Verifying the quorum here
   and accepting it would let any one signer's target confer the whole group's grant,
   which is E3/F66's over-acceptance. §5.5's M6 also requires the LOCAL peer in the
   signer set, so the quorum arm has no meaning in a foreign frame even on its own
   terms. *)
let verify_capability_chain ?root_peer ~local_peer ~store (capability : Model.entity)
    (included : (string * Model.entity) list) : verdict =
  let root_peer = Option.value ~default:local_peer root_peer in
  let resolve_fn = resolve included store in
  match collect_chain capability ~resolve_fn with
  | Error _ -> Deny
  | Ok chain ->
      let root = List.nth chain (List.length chain - 1) in
      (* Root authority: a single-sig root must root at [root_peer]; a §3.6 M3
         multi-sig root (root-only) must pass k-of-n quorum validation, and only in
         the LOCAL frame. *)
      let root_ok =
        match multi_granter_of_entity root with
        | Some mg ->
            String.equal root_peer local_peer
            && verify_multisig_root ~local_peer ~resolve_fn root mg included
        | None ->
            (match Model.bytes_field root "granter" with
             | Some gh ->
                 (match resolve_fn gh with
                  | Some g ->
                      (* granter identity's derived peer_id must equal root_peer *)
                      (match Model.bytes_field g "public_key" with
                       | Some pk -> String.equal (Identity.peer_id_of_pubkey pk) root_peer
                       | None -> false)
                  | None -> false)
             | None -> false)
      in
      if not root_ok then Deny
      else begin
        let n = List.length chain in
        let ok = ref true in
        List.iteri
          (fun i current ->
            if !ok then begin
             if is_multisig current then begin
               (* §3.6 M3 multi-sig is root-only and is fully verified above
                  (structure, quorum signatures, temporal, grantee). A multi-sig
                  token anywhere but the chain root is rejected. *)
               if i <> n - 1 then ok := false
             end else begin
              (* signature: signer == granter, verify against granter identity *)
              (match Model.bytes_field current "granter" with
               | Some gh ->
                   (match find_signature ~target:current.Model.hash included, resolve_fn gh with
                    | Some sgn, Some granter ->
                        let signer_ok = match Model.bytes_field sgn "signer" with
                          | Some s -> hash_equals s gh | None -> false in
                        if not (signer_ok && Identity.verify_signature sgn granter) then ok := false
                    | _ -> ok := false)
               | None -> ok := false);
              (* grantee resolution → 401 carve-out *)
              (match Model.bytes_field current "grantee" with
               | Some gh -> if resolve_fn gh = None then raise Unresolvable_grantee
               | None -> raise Unresolvable_grantee);
              (* temporal validity.

                 CAP-6a FIRST (§6.2, 0.8.1): a PRESENT but unrepresentable
                 expires_at / not_before / created_at is malformed and MUST be
                 refused — "MUST NOT treat the unrepresentable field as absent".
                 This has to precede the two range checks below because
                 [Model.uint_field] answers [None] for BOTH an absent field and a
                 present non-uint one, so on its own it silently skips the check
                 and honours the token (fail-open). Absent stays legal. *)
              if not (temporal_fields_representable current) then ok := false;
              let t = now_ms () in
              (match Model.uint_field current "not_before" with
               | Some nb when Int64.unsigned_compare t nb < 0 -> ok := false | _ -> ());
              (match Model.uint_field current "expires_at" with
               | Some ex when Int64.unsigned_compare ex t < 0 -> ok := false | _ -> ());
              (* delegation: parent.grantee == current.granter, attenuation,
                 and §5.7 delegation caveats (checked per-link, depth = i). *)
              if i < n - 1 then begin
                let parent = List.nth chain (i + 1) in
                (* §5.5a: resolve each link's granter peer_id as the per-link frame
                   for its resource patterns. Hard-fail (deny) on an unresolvable
                   granter rather than fall back to the local frame (§4 scrutiny). *)
                match link_granter_peer ~resolve_fn ~local_peer current,
                      link_granter_peer ~resolve_fn ~local_peer parent with
                | Some child_peer, Some parent_peer ->
                    let link_ok =
                      (match Model.bytes_field parent "grantee", Model.bytes_field current "granter" with
                       | Some pg, Some cg -> hash_equals pg cg | _ -> false)
                      && is_attenuated ~local_peer ~child_peer ~parent_peer current parent
                      && check_delegation_caveats ~parent ~child:current ~depth:i in
                    if not link_ok then ok := false
                | _ -> ok := false                  (* unresolvable link granter → deny *)
              end
             end
            end)
          chain;
        if !ok then Allow else Deny
      end

(* is_revoked (§5.1) — marker check at system/capability/revocations/{hash_hex}.
   Covers wire-only caps (leaf) and the chain root. *)
let is_revoked ~local_peer ~store (capability : Model.entity)
    (included : (string * Model.entity) list) : bool =
  let resolve_fn = resolve included store in
  let root_hash =
    match collect_chain capability ~resolve_fn with
    | Ok chain -> (List.nth chain (List.length chain - 1)).Model.hash
    | Error _ -> capability.Model.hash
  in
  let check h =
    Store.get_at store ~path:("/" ^ local_peer ^ "/system/capability/revocations/" ^ Model.hex h) <> None
  in
  check capability.Model.hash || check root_hash

(* verify_request (§5.2) returns a 3-way verdict so the dispatcher can map the
   §4.6 / F20 authentication-vs-authorization status boundary:
     - authentication-class failures (signature / author cannot be established)
       → 401 (the request never proves who the caller is). This follows the live
       oracle / F20 ground truth; §5.2's "DENY → 403" text under-specifies the
       split that §4.6 draws — corroborated here from a third peer (A-OC-008).
     - authorization-class DENY (authenticated caller lacks authority) → 403.
   [Unresolvable_grantee] is raised through (→ 401 per §5.5 carve-out). *)
type req_verdict = Req_allow | Req_authn_fail | Req_authz_deny | Req_chain_too_deep

let verify_request ~local_peer ~store (env : Model.envelope) : req_verdict =
  let exec = env.root in
  let included = env.included in
  (* 1. content hash already validated on parse (Model.of_cbor). *)
  (* 2. signature / author — authentication class (§4.6 boundary → 401). *)
  match find_signature ~target:exec.hash included with
  | None -> Req_authn_fail
  | Some sgn ->
      let author_h = Model.bytes_field exec "author" in
      let signer_ok = match Model.bytes_field sgn "signer", author_h with
        | Some s, Some a -> hash_equals s a | _ -> false in
      if not signer_ok then Req_authn_fail
      else
        match Option.bind author_h (fun a -> Model.included_get env a) with
        | None -> Req_authn_fail
        | Some author ->
            if not (Identity.verify_signature sgn author) then Req_authn_fail
            else
              (* 3. capability / chain — authorization class (→ 403). *)
              match Option.bind (Model.bytes_field exec "capability")
                      (fun c -> Model.included_get env c) with
              | None -> Req_authz_deny
              | Some capability ->
                  (* §4.10(b) resource bound: a chain exceeding max depth is rejected
                     as 400 chain_depth_exceeded (structural excess) BEFORE the per-link
                     authz walk — distinct from 403 capability_denied. Arch v7.75 ruling:
                     400 lets the caller distinguish "shorten your chain" from "you lack
                     the capability". *)
                  if chain_exceeds_depth ~store capability included then Req_chain_too_deep
                  else
                  (* Run chain verification first: a per-link unresolvable grantee
                     (§5.5) raises Unresolvable_grantee → 401, which MUST take
                     precedence over the §5.2 grantee==author mismatch → 403
                     (AUTHZ-GRANTEE-1: the single 401 carve-out, not a 403). *)
                  (match verify_capability_chain ~local_peer ~store capability included with
                   | Deny -> Req_authz_deny
                   | Allow ->
                       let grantee_ok = match Model.bytes_field capability "grantee", author_h with
                         | Some g, Some a -> hash_equals g a | _ -> false in
                       if not grantee_ok then Req_authz_deny
                       else if is_revoked ~local_peer ~store capability included then Req_authz_deny
                       else Req_allow)

(* ── §1.4 PD-2: outbound sub-dispatch authorization ───────────────────────── *)

(* Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.

   §1.4 admits three spellings of one address -- "system/tree", "/{peer}/system/tree"
   and "entity://{peer}/system/tree" -- and §1.4's PD-2 block requires Dimension 1's
   handler pattern to be the target uri's peer-relative path, because a grant names
   HANDLERS and a handler pattern never carries a peer segment. Matching a grant
   against the absolute or schemed form matches nothing, silently, which reads at the
   wire as an authority refusal.

   The first segment is dropped ONLY when it is a peer_id. A peer-relative
   "system/protocol/connect" must not lose "system" -- the standing defect on
   [smalltalk] and [forth], where an unconditional strip made every self-minted grant
   unusable while the handshake stayed green. *)
let peer_relative_of (uri : string) : string =
  let p = normalize_uri uri in
  if String.length p = 0 || p.[0] <> '/' then p
  else
    match String.split_on_char '/' p with
    | "" :: seg :: rest when is_peer_id seg -> String.concat "/" rest
    | "" :: rest -> String.concat "/" rest
    | _ -> p

(* Store key of a handler's OWN grant (§6.8: system/capability/grants/{pattern}),
   tolerant of the pattern arriving absolute or peer-relative.

   §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
   the grant path is built from the PEER-RELATIVE one. The two are one segment apart
   and concatenating the wrong one yields a doubled peer segment whose lookup misses --
   which fails closed as "no handler grant" and is indistinguishable, at the wire, from
   a genuine authority refusal. *)
let grant_path_for ~(local_peer : string) (pattern : string) : string =
  let prefix = "/" ^ local_peer ^ "/" in
  let n = String.length prefix in
  let rel =
    if String.length pattern >= n && String.sub pattern 0 n = prefix
    then String.sub pattern n (String.length pattern - n)
    else pattern
  in
  "/" ^ local_peer ^ "/system/capability/grants/" ^ rel

(* Verify a presented reentry credential against §1.4's clauses and, where they all
   hold, answer the [peers] scope Dimension 4 relaxes to. [None] relaxes nothing.

   Every clause is required and failing any relaxes nothing:
     - the chain ROOT granter resolves to the TARGET peer, and is NOT a multi-signature
       root -- a K-of-N root is a GROUP's authority and never relaxes Dimension 4
       ([verify_capability_chain] refuses the quorum arm in a foreign frame, which is
       where that rule lands);
     - the LEAF grantee is the local peer;
     - valid (per-link signatures, temporal, attenuation, caveats) and not revoked. *)
let target_minted_peers_relaxation ~(local_peer : string) ~(target_peer : string) ~store
    (cred : Model.entity) (included : (string * Model.entity) list) : scope option =
  (* Nothing to relax -- the default already covers this peer. Treating a
     self-targeted credential as a relaxation would make the exemption reachable with
     no foreign mint at all. *)
  if String.equal target_peer local_peer then None
  else
    let verdict =
      (* An unresolvable grantee inside the credential raises rather than denying; a
         credential we cannot fully verify relaxes NOTHING, and it must not turn the
         sub-dispatch into a 401 about someone else's chain. *)
      try verify_capability_chain ~root_peer:target_peer ~local_peer ~store cred included
      with _ -> Deny
    in
    if verdict <> Allow then None
    else if is_revoked ~local_peer ~store cred included then None
    else
      let resolve_fn = resolve included store in
      let grantee_is_local =
        match Model.bytes_field cred "grantee" with
        | Some gh -> (
            match resolve_fn gh with
            | Some ge -> (
                match Model.bytes_field ge "public_key" with
                | Some pk -> String.equal (Identity.peer_id_of_pubkey pk) local_peer
                | None -> false)
            | None -> false)
        | None -> false
      in
      if not grantee_is_local then None
      else
        (* The credential's own [peers] scope is what Dimension 4 relaxes TO. Absent
           means the granter -- the target peer -- which is the ordinary reentry
           shape: "you may dispatch back to me". *)
        match grants_of_token cred with
        | g :: _ -> Some (Option.value ~default:{ incl = [ target_peer ]; excl = [] } g.peers)
        | [] -> None

(* §1.4's PD-2 gate: check_permission run BEFORE a locally-originated sub-dispatch
   LEAVES the peer, with all four dimensions applied.

   ONE GATE AND ONE EXEMPTION, in §1.4's own words:
     - the EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8), evaluated in
       the LOCAL frame, with Dimension 1's pattern the target uri's PEER-RELATIVE path;
     - a valid capability MINTED BY THE TARGET PEER naming this peer as grantee relaxes
       Dimension 4 (peers) AND ONLY DIMENSION 4, to the peers that capability covers,
       evaluated in the TARGET's frame.

   "The target answers WHERE; the handler's grant answers WHAT." A credential is NOT a
   grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
   sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
   BYPASS it is distinguished from is a peer that treats the credential as a standalone
   authorizer and steers past its own grant -- §6.8's confused-deputy substitution. Both
   obvious vectors agree under either reading (sources agree -> allow, no source ->
   refuse), so the only input that separates them is a VALID credential presented to a
   handler whose own grant does NOT cover the request, which MUST refuse.

   A credential failing any verification clause relaxes NOTHING and the handler grant
   gates unrelaxed -- it does not turn the verdict into an error.

   [target_peer] is supplied by the caller rather than derived here: on the §6.11
   reentry seam the uri may be PEER-RELATIVE and the destination is the connection's
   remote, so [extract_peer uri local] would answer the LOCAL peer and Dimension 4 would
   pass vacuously on the default {include: [local]} -- the exemption would then never be
   exercised and a bypass would read as a compose.

   [cred = None] is the ambient arm: Dimension 4 is decided by the handler's grant
   alone. *)
let check_outbound_sub_dispatch ~(local_peer : string) ~(target_peer : string)
    ~(handler_pattern : string) ~(operation : string) ~store ~(handler_grant : Model.entity)
    ~(resource : Cbor.t) ~(cred : Model.entity option)
    (included : (string * Model.entity) list) : bool =
  (* Computed FIRST and consulted LAST, so no credential can stand in for 1-3. *)
  let relax_to =
    match cred with
    | None -> None
    | Some c -> target_minted_peers_relaxation ~local_peer ~target_peer ~store c included
  in
  let grant_ok (g : grant) =
    matches_scope ~local_peer ~kind:Path_scope handler_pattern g.handlers
    && matches_scope ~local_peer ~kind:Id_scope operation g.operations
    && check_resource_scope ~local_peer ~granter_peer:local_peer resource g.resources
    (* Dimension 4. §5.2's default for an absent [peers] scope is
       {include: [local_peer_id]}, so a foreign target fails unless this grant names it
       or a target-minted credential relaxes it. *)
    && (matches_scope ~local_peer ~kind:Id_scope target_peer
          (Option.value ~default:{ incl = [ local_peer ]; excl = [] } g.peers)
        || (match relax_to with
            | Some s -> matches_scope ~local_peer ~kind:Id_scope target_peer s
            | None -> false))
  in
  List.exists grant_ok (grants_of_token handler_grant)
