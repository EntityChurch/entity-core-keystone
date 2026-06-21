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

(* ── §5.4 pattern matching ────────────────────────────────────────────────── *)

let starts_with ~prefix s =
  String.length s >= String.length prefix && String.sub s 0 (String.length prefix) = prefix

(* URI normalization (§1.4): strip the entity:// scheme and prepend "/" to
   produce an absolute path; peer-relative paths pass through to canonicalize. *)
let normalize_uri (uri : string) : string =
  if starts_with ~prefix:"entity://" uri then "/" ^ String.sub uri 9 (String.length uri - 9)
  else uri

(* Resolve peer-relative paths to absolute "/{local}/..." form. *)
let canonicalize ~local_peer (path : string) : string =
  if starts_with ~prefix:"./" path || starts_with ~prefix:"../" path then
    invalid_arg "canonicalize: reserved directory-relative path";
  if starts_with ~prefix:"*/" path then
    invalid_arg "canonicalize: ambiguous bare peer wildcard";
  if starts_with ~prefix:"/" path then path
  else "/" ^ local_peer ^ "/" ^ path

(* Both path and pattern MUST already be canonical (absolute). *)
let rec matches_pattern (path : string) (pattern : string) : bool =
  if String.equal pattern "*" then true
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

let matches_scope ~local_peer (value : string) (s : scope) : bool =
  let cv = canonicalize ~local_peer value in
  let covered pats = List.exists (fun p -> matches_pattern cv (canonicalize ~local_peer p)) pats in
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
    matches_scope ~local_peer operation g.operations
    && matches_scope ~local_peer handler_pattern g.handlers
    && (let peers = Option.value ~default:{ incl = [ local_peer ]; excl = [] } g.peers in
        matches_scope ~local_peer target_peer peers)
    && (match resource with
        | None -> true
        | Some r -> check_resource_scope ~local_peer ~granter_peer r g.resources)
  in
  if List.exists grant_ok (grants_of_token token) then Allow else Deny

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

   §PR-8 / §5.5a (Amendment 1): each side's patterns canonicalize against THAT
   side's granter peer_id — [~child_peer] for the child grant's patterns, and
   [~parent_peer] for the parent grant's. For the resource dimension these are the
   per-link granter frames; for handler/operation/peer dimensions both are the
   local frame (no §PR-8 there). When the two frames are equal (same-peer chain)
   this is byte-identical to the pre-Amendment behavior. *)
let scope_subset ~child_peer ~parent_peer (child : scope) (parent : scope) : bool =
  List.for_all
    (fun cp ->
      let cc = canonicalize ~local_peer:child_peer cp in
      List.exists (fun pp -> matches_pattern cc (canonicalize ~local_peer:parent_peer pp)) parent.incl)
    child.incl
  && List.for_all
       (fun pe ->
         let cpe = canonicalize ~local_peer:parent_peer pe in
         List.exists (fun ce -> matches_pattern cpe (canonicalize ~local_peer:child_peer ce)) child.excl)
       parent.excl

(* [~child_peer]/[~parent_peer] are the §5.5a per-link granter frames applied to
   the RESOURCE dimension only; handlers/operations/peers stay on [~local_peer]. *)
let grant_subset ~local_peer ~child_peer ~parent_peer (child : grant) (parent : grant) : bool =
  scope_subset ~child_peer:local_peer ~parent_peer:local_peer child.handlers parent.handlers
  && scope_subset ~child_peer:local_peer ~parent_peer:local_peer child.operations parent.operations
  && scope_subset ~child_peer ~parent_peer child.resources parent.resources
  && (let cp = Option.value ~default:{ incl = [ local_peer ]; excl = [] } child.peers in
      let pp = Option.value ~default:{ incl = [ local_peer ]; excl = [] } parent.peers in
      scope_subset ~child_peer:local_peer ~parent_peer:local_peer cp pp)

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
   §5.5 401 carve-out. *)
let verify_capability_chain ~local_peer ~store (capability : Model.entity)
    (included : (string * Model.entity) list) : verdict =
  let resolve_fn = resolve included store in
  match collect_chain capability ~resolve_fn with
  | Error _ -> Deny
  | Ok chain ->
      let root = List.nth chain (List.length chain - 1) in
      (* Root authority: a single-sig root must root at the local peer; a §3.6 M3
         multi-sig root (root-only) must pass k-of-n quorum validation. *)
      let root_ok =
        match multi_granter_of_entity root with
        | Some mg -> verify_multisig_root ~local_peer ~resolve_fn root mg included
        | None ->
            (match Model.bytes_field root "granter" with
             | Some gh ->
                 (match resolve_fn gh with
                  | Some g ->
                      (* granter identity's derived peer_id must equal local_peer *)
                      (match Model.bytes_field g "public_key" with
                       | Some pk -> String.equal (Identity.peer_id_of_pubkey pk) local_peer
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
              (* temporal validity *)
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
