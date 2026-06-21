(* Peer assembly — bootstrap, the four MUST system handlers (§6.2: tree, handler,
   capability, connect), the dispatch chain (§6.5), and per-connection state.

   Spec-first: the handshake (§4.1/§4.6 three-check proof-of-possession), the
   dispatch chain order (verify → resolve → check_permission → handler), and the
   §4.4 initial-grant delivery are derived directly from V7. Transport lives in
   [Transport]; this module is the pure protocol brain (one connection's state +
   a function from inbound envelope to outbound response envelope). *)

type t = {
  identity : Identity.t;
  store : Store.t;
  local_peer : string;
  open_grants : bool;      (* --debug-open-grants: mint a wide admin cap (§ test harness) *)
  conformance : bool;      (* --validate: register the system/validate/* conformance handlers (§7a) *)
}

(* Per-connection state (§4.2 connection state is per-connection). *)
type conn = {
  mutable established : bool;
  mutable issued_nonce : string option;     (* nonce we issued in our hello response *)
  mutable hello_peer_id : string option;    (* initiator's claimed peer_id from hello *)
  (* §6.13(b) handler-facing outbound seam: send an EXECUTE envelope over this
     connection and await its correlated EXECUTE_RESPONSE (§6.11 reentry). Set by the
     transport; None when the request did not arrive over a reentrant connection. *)
  mutable outbound : (Model.envelope -> Model.envelope option) option;
  mutable out_counter : int;                (* connection-scoped outbound request_id counter *)
}

let new_conn () =
  { established = false; issued_nonce = None; hello_peer_id = None;
    outbound = None; out_counter = 0 }

(* A handler outcome: status, result entity, and any protocol entities to bundle. *)
type outcome = { status : int; result : Model.entity; included : (string * Model.entity) list }

let ok ?(included = []) result = { status = 200; result; included }
let err ?message status code = { status; result = Wire.error_result ?message code; included = [] }

(* ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ──────────────────────── *)

let random_bytes (n : int) : string =
  let fd = Unix.openfile "/dev/urandom" [ Unix.O_RDONLY ] 0 in
  Fun.protect ~finally:(fun () -> Unix.close fd) (fun () -> Wire.read_exact fd n)

(* ── grant construction (§4.4 / §5.4) ─────────────────────────────────────── *)

let scope incl excl =
  Cbor.Map
    ((Cbor.Text "include", Cbor.Array (List.map (fun s -> Cbor.Text s) incl))
     :: (match excl with [] -> [] | _ -> [ (Cbor.Text "exclude", Cbor.Array (List.map (fun s -> Cbor.Text s) excl)) ]))

let grant ~handlers ~resources ~operations ?peers () =
  Cbor.Map
    ([ (Cbor.Text "handlers", scope handlers []);
       (Cbor.Text "resources", scope resources []);
       (Cbor.Text "operations", scope operations []) ]
     @ (match peers with Some p -> [ (Cbor.Text "peers", scope p []) ] | None -> []))

(* ── §6.9a seed policy ─────────────────────────────────────────────────────

   The declared identity → capability seed policy. Materialized into the tree at
   [system/capability/policy/{key}] at bootstrap (L0); §4.6 authenticate reads it
   back via the v7.64 dual-form lookup (hex → Base58 → default) and UNIONs the
   matched scope with the §4.4 discovery floor. Replaces the hardcoded
   initialGrants/openGrants fork that §6.9a declares non-conformant. *)

(* The §4.4 discovery floor: every authenticated identity gets at least this. *)
let discovery_floor () : Cbor.t list =
  [ grant ~handlers:[ "system/tree" ] ~resources:[ "system/type/*"; "system/handler/*" ] ~operations:[ "get" ] ();
    grant ~handlers:[ "system/capability" ] ~resources:[] ~operations:[ "request" ] () ]

(* A wide-open admin scope — the degenerate [default → *] (= retired --debug-open-grants). *)
let open_grants_scope () : Cbor.t list =
  [ grant ~handlers:[ "*" ] ~resources:[ "*"; "/*/*" ] ~operations:[ "*" ] ~peers:[ "*" ] () ]

(* Full owner authority over the local namespace [/{peer_id}/*] (§6.9a). *)
let owner_grants (t : t) : Cbor.t list =
  [ grant ~handlers:[ "*" ] ~resources:[ "*" ] ~operations:[ "*" ] ~peers:[ t.local_peer ] () ]

(* Raw grants Cbor list from a seed-policy entry, handling both §6.9a.0 shapes: a
   capability token (detached-signature shape — verify the sig at the §3.5 pointer
   before trusting) or a policy-entry (scope template). *)
let seed_entry_grants (t : t) (e : Model.entity) : Cbor.t list =
  let grants_of () = match Model.field e "grants" with Some (Cbor.Array l) -> l | _ -> [] in
  if String.equal e.typ "system/capability/token" then begin
    let sig_path = "/" ^ t.local_peer ^ "/system/signature/" ^ Model.hex e.hash in
    match Store.get_at t.store ~path:sig_path with
    | Some sgn when Identity.verify_signature sgn t.identity.peer_entity -> grants_of ()
    | _ -> []   (* unverifiable seed cap → no authority *)
  end
  else if String.equal e.typ "system/capability/policy-entry" then grants_of ()
  else []

(* §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
   then UNION the matched scope with the §4.4 discovery floor (v7.62 §8). *)
let derive_seed_grants (t : t) ~(remote_peer : Model.entity) ~(remote_peer_id : string) : Cbor.t list =
  let base = "/" ^ t.local_peer ^ "/system/capability/policy/" in
  let entry =
    match Store.get_at t.store ~path:(base ^ Model.hex remote_peer.hash) with
    | Some e -> Some e
    | None -> (
        match Store.get_at t.store ~path:(base ^ remote_peer_id) with
        | Some e -> Some e
        | None -> Store.get_at t.store ~path:(base ^ "default"))
  in
  let floor = discovery_floor () in
  let policy_grants = match entry with None -> [] | Some e -> seed_entry_grants t e in
  if policy_grants = [] then floor else floor @ policy_grants

let now_ms () = Int64.of_float (Unix.gettimeofday () *. 1000.)

(* Mint a root capability token granted by us to [grantee_hash]. Signs it and
   returns (token, signature). *)
let mint_token (t : t) ~grantee_hash ?parent ~(grants : Cbor.t list) () : Model.entity * Model.entity =
  let data =
    (Cbor.Text "granter", Cbor.Bytes t.identity.identity_hash)
    :: (Cbor.Text "grantee", Cbor.Bytes grantee_hash)
    :: (Cbor.Text "grants", Cbor.Array grants)
    :: (Cbor.Text "created_at", Cbor.Uint (now_ms ()))
    :: (match parent with Some p -> [ (Cbor.Text "parent", Cbor.Bytes p) ] | None -> [])
  in
  let token = Model.make ~typ:"system/capability/token" (Cbor.Map data) in
  (token, Identity.sign_entity t.identity token)

(* ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────

   Build, sign (as the local peer), and send an outbound EXECUTE through the §6.11
   reentry seam on the serving connection ([conn.outbound], set by the transport),
   returning the correlated EXECUTE_RESPONSE envelope. Present on every peer even
   though no core handler originates — a handler registered at runtime (§6.13(a))
   may. The handler dispatches under its own authority (§6.8): it supplies the
   capability the target accepts plus the §5.8 chain bundle. *)
let outbound_dispatch (t : t) (conn : conn) ~(uri : string) ~(operation : string)
    ~(params : Model.entity) ?(resource : Cbor.t option) ~(capability : Model.entity)
    ~(granter_peer : Model.entity) ~(capability_signature : Model.entity) () : Model.envelope option =
  match conn.outbound with
  | None -> None   (* no reentrant connection → seam unavailable *)
  | Some send ->
      conn.out_counter <- conn.out_counter + 1;
      let request_id = "out-" ^ string_of_int conn.out_counter in
      let exec =
        Wire.make_execute ~request_id ~uri ~operation ~params ?resource
          ~author:t.identity.identity_hash ~capability:capability.hash ()
      in
      let exec_sig = Identity.sign_entity t.identity exec in
      let included =
        [ (capability.hash, capability);
          (granter_peer.hash, granter_peer);      (* capability granter (the target peer) *)
          (t.identity.identity_hash, t.identity.peer_entity);   (* grantee + author (us) *)
          (capability_signature.hash, capability_signature);
          (exec_sig.hash, exec_sig) ]
      in
      send { Model.root = exec; included }

(* ── connect handler (§4.1, §4.6) ─────────────────────────────────────────── *)

let entity_field (e : Model.entity) (key : string) : Model.entity option =
  Option.map Model.of_cbor (Model.field e key)

let connect_handler (t : t) (conn : conn) (exec : Model.entity) ~(included : (string * Model.entity) list) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  match op with
  | "hello" ->
      if conn.established then err 409 "connection_already_established"
      else begin
        let params = entity_field exec "params" in
        (* §4.5 negotiation: reject disjoint hash_formats / key_types up front. *)
        let str_array key = match Option.bind params (fun p -> Model.field p key) with
          | Some (Cbor.Array l) -> Some (List.filter_map (function Cbor.Text s -> Some s | _ -> None) l)
          | _ -> None in
        let hash_ok = match str_array "hash_formats" with
          | Some fmts -> List.mem "ecfv1-sha256" fmts | None -> true in
        let key_ok = match str_array "key_types" with
          | Some kts -> List.mem "ed25519" kts | None -> true in
        if not hash_ok then err 400 "incompatible_hash_format"
        else if not key_ok then err 400 "unsupported_key_type"
        else begin
        let initiator_peer = Option.bind params (fun p -> Model.text_field p "peer_id") in
        conn.hello_peer_id <- initiator_peer;
        let nonce = random_bytes 32 in
        conn.issued_nonce <- Some nonce;
        let hello =
          Model.make ~typ:"system/protocol/connect/hello"
            (Cbor.Map
               [ (Cbor.Text "peer_id", Cbor.Text t.local_peer);
                 (Cbor.Text "nonce", Cbor.Bytes nonce);
                 (Cbor.Text "protocols", Cbor.Array [ Cbor.Text "entity-core/1.0" ]);
                 (Cbor.Text "timestamp", Cbor.Uint (now_ms ()));
                 (Cbor.Text "hash_formats", Cbor.Array [ Cbor.Text "ecfv1-sha256" ]);
                 (Cbor.Text "key_types", Cbor.Array [ Cbor.Text "ed25519" ]) ])
        in
        ok hello
        end
      end
  | "authenticate" -> (
      if conn.established then err 409 "connection_already_established"
      else
        match conn.issued_nonce with
        | None -> err 401 "invalid_nonce"     (* authenticate before hello (§4.6 step 1) *)
        | Some issued -> (
            match entity_field exec "params" with
            | None -> err 401 "authentication_failed"
            | Some auth when
                (* §4.6 hardening / AGILITY-UNKNOWN-1: reject an unsupported key_type.
                   The unsupported code can ride in the key_type field, in a non-32-byte
                   public_key, or in the claimed peer_id's leading key_type byte (the
                   0xfd case — the field still says "ed25519"). Reject all three. *)
                (Model.text_field auth "key_type" <> None
                 && Model.text_field auth "key_type" <> Some "ed25519")
                || (match Model.bytes_field auth "public_key" with Some p -> String.length p <> 32 | None -> false)
                || (match Model.text_field auth "peer_id" with
                    | Some pid -> (try (Peer_id.parse pid).key_type <> 0x01 with _ -> false)
                    | None -> false) ->
                err 400 "unsupported_key_type"
            | Some auth ->
                let pub = Model.bytes_field auth "public_key" in
                let echoed = Model.bytes_field auth "nonce" in
                let claimed_peer = Model.text_field auth "peer_id" in
                (if Sys.getenv_opt "EC_DEBUG" <> None then
                   match pub, claimed_peer with
                   | Some p, Some c ->
                       Printf.eprintf "AUTH dbg: pubkey=%s sha256(pub)=%s claimed_decoded=%s peer_entity_hash=%s\n%!"
                         (Model.hex p) (Model.hex (Hash.sha256 p))
                         (Model.hex (Base58.decode c))
                         (Model.hex (Identity.peer_entity_of_pubkey p).Model.hash)
                   | _ -> ());
                (* step 1: nonce-echo *)
                if echoed <> Some issued then err 401 "invalid_nonce"
                else
                  match pub with
                  | None -> err 401 "authentication_failed"
                  | Some public_key -> (
                      (* step 2: proof of possession *)
                      let sig_ok =
                        match Capability.find_signature ~target:auth.hash included with
                        | Some sgn -> (
                            match Model.bytes_field sgn "signature" with
                            | Some sb -> Sign.verify ~pub:public_key ~signature:sb ~msg:auth.hash
                            | None -> false)
                        | None -> false
                      in
                      if not sig_ok then err 401 "authentication_failed"
                      (* step 3: identity binding *)
                      else if claimed_peer <> Some (Identity.peer_id_of_pubkey public_key) then
                        err 401 "identity_mismatch"
                      else if conn.hello_peer_id <> None && conn.hello_peer_id <> claimed_peer then
                        err 401 "identity_mismatch"
                      else begin
                        (* success: mint the initial capability for the remote (§4.4 /
                           §6.9a). Scope derived from the declared seed policy read from
                           the tree — NOT a hardcoded initialGrants/openGrants fork
                           (§6.9a declares that non-conformant) — UNION'd with the §4.4
                           discovery floor (v7.62 §8). *)
                        let remote_peer = Identity.peer_entity_of_pubkey public_key in
                        let grants =
                          derive_seed_grants t ~remote_peer
                            ~remote_peer_id:(Option.value ~default:"" claimed_peer)
                        in
                        let token, sgn =
                          mint_token t ~grantee_hash:remote_peer.hash ~grants ()
                        in
                        conn.established <- true;
                        let grant_result =
                          Model.make ~typ:"system/capability/grant"
                            (Cbor.Map [ (Cbor.Text "token", Cbor.Bytes token.hash) ])
                        in
                        ok grant_result
                          ~included:
                            [ (token.hash, token);
                              (t.identity.identity_hash, t.identity.peer_entity);
                              (sgn.hash, sgn) ]
                      end)))
  | other -> err 501 "unsupported_operation" ~message:("connect: " ^ other)

(* ── tree handler (§6.3) ──────────────────────────────────────────────────── *)

let resource_target (exec : Model.entity) : string option =
  match Model.field exec "resource" with
  | Some r -> ( match Model.map_get r "targets" with
      | Some (Cbor.Array (Cbor.Text t :: _)) -> Some t | _ -> None )
  | None -> None

(* §1.4 / §5.4 / CORE-TREE-PATH-FLEX-1: validate a caller-supplied resource
   target before canonicalize. Reject null byte, caller leading slash, ./ ../ and
   interior empty segments (// ). A single trailing "/" is the listing marker. *)
let path_flex_ok (target : string) : bool =
  if String.contains target '\000' then false
  else
    (* An absolute path "/{peer_id}/rest" is valid (universal address space, §1.4);
       a leading slash whose first segment is NOT a peer_id is rejected. *)
    let segs0 = String.split_on_char '/' target in
    let abs_ok, body =
      if Capability.starts_with ~prefix:"/" target then
        (match segs0 with "" :: first :: _ -> (Capability.is_peer_id first, List.tl segs0) | _ -> (false, segs0))
      else (true, segs0)
    in
    if not abs_ok then false
    else
      let body = match List.rev body with "" :: rest -> List.rev rest | _ -> body in
      List.for_all (fun s -> not (String.equal s "") && not (String.equal s ".") && not (String.equal s "..")) body

let is_deletion_marker (t : t) (h : string) : bool =
  match Store.get_by_hash t.store h with
  | Some e -> String.equal e.Model.typ "system/deletion-marker"
  | None -> false

(* Build a system/tree/listing (§3.9), omitting deletion-marker-bound leaves
   (CORE-TREE-DELETE-1 / §6.3 filter). Entries keyed by child segment. *)
let build_listing (t : t) ~(path : string) : outcome =
  let entries = Store.listing t.store ~prefix:path in
  let entries =
    List.filter
      (fun (_, hash, has_children) ->
        match hash with Some h when (not has_children) && is_deletion_marker t h -> false | _ -> true)
      entries
  in
  let entry_map =
    List.map
      (fun (seg, hash, has_children) ->
        ( Cbor.Text seg,
          Model.to_cbor
            (Model.make ~typ:"system/tree/listing-entry"
               (Cbor.Map
                  ((Cbor.Text "has_children", Cbor.Bool has_children)
                   :: (match hash with Some h -> [ (Cbor.Text "hash", Cbor.Bytes h) ] | None -> []))))))
      entries
  in
  ok (Model.make ~typ:"system/tree/listing"
        (Cbor.Map
           [ (Cbor.Text "path", Cbor.Text path);
             (Cbor.Text "entries", Cbor.Map entry_map);
             (Cbor.Text "count", Cbor.Uint (Int64.of_int (List.length entries)));
             (Cbor.Text "offset", Cbor.Uint 0L) ]))

let tree_handler (t : t) (exec : Model.entity) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  match op, resource_target exec with
  | ("get" | "put"), Some target when not (path_flex_ok target) ->
      err 400 "invalid_path" ~message:target
  | "get", None ->
      (* §6.3: empty resource → list the local peer root. *)
      build_listing t ~path:("/" ^ t.local_peer ^ "/")
  | "get", Some target when target = "" || target.[String.length target - 1] = '/' ->
      build_listing t ~path:(Capability.canonicalize ~local_peer:t.local_peer target)
  | "get", Some target -> (
      let path = Capability.canonicalize ~local_peer:t.local_peer target in
      match Store.get_at t.store ~path with
      | Some e ->
          let mode = Option.bind (entity_field exec "params") (fun p -> Model.text_field p "mode") in
          if mode = Some "hash" then ok (Model.make ~typ:"system/hash" (Cbor.Bytes e.hash))
          else ok e
      | None -> err 404 "not_found" ~message:path)
  | "put", Some target ->
      let path = Capability.canonicalize ~local_peer:t.local_peer target in
      let params = entity_field exec "params" in
      let entity = Option.bind params (fun p -> entity_field p "entity") in
      let expected = Option.bind params (fun p -> Model.bytes_field p "expected_hash") in
      (* §3.9 CAS: zero-hash = create-only; non-zero must match current binding. *)
      let current = Store.hash_at t.store ~path in
      let zero33 = String.make 33 '\000' in
      let cas_ok =
        match expected with
        | None -> true
        | Some h when String.equal h zero33 -> current = None
        | Some h -> current = Some h
      in
      if not cas_ok then err 409 "hash_mismatch" ~message:path
      else (
        match entity with
        | Some e -> Store.bind t.store ~path e; ok (Model.make ~typ:"system/hash" (Cbor.Bytes e.hash))
        | None -> err 400 "unexpected_params" ~message:"put: missing entity")
  | _, None -> err 400 "ambiguous_resource" ~message:"tree: missing resource target"
  | other, _ -> err 501 "unsupported_operation" ~message:("tree: " ^ other)

(* ── capability handler (§6.2) ────────────────────────────────────────────── *)

let is_zero_hash (h : string) : bool = String.for_all (fun c -> c = '\000') h

(* mint a token for [grantee_hash], bounded as a subset of the caller's
   authenticated cap (§6.2 subset-validation), returning the grant result. *)
let mint_bounded (t : t) ~(caller_cap : Model.entity option) ~(req_grants : Cbor.t list)
    ~(grantee_hash : string) ?parent () : outcome =
  let bounded =
    match caller_cap with
    | None -> false
    | Some cap ->
        let parent_grants = Capability.grants_of_token cap in
        List.for_all
          (fun cg ->
            let c = Capability.parse_grant cg in
            (* §6.2 mint-time subset check — the capability-handler surface, not the
               dispatch chain walk. No V1'-family vector gates it; kept on the local
               frame (child=parent=local) to preserve current behavior. *)
            List.exists (fun pg -> Capability.grant_subset ~local_peer:t.local_peer ~child_peer:t.local_peer ~parent_peer:t.local_peer c pg) parent_grants)
          req_grants
  in
  if not bounded then err 403 "scope_exceeds_authority"
  else begin
    let token, sgn = mint_token t ~grantee_hash ?parent ~grants:req_grants () in
    let grant_result =
      Model.make ~typ:"system/capability/grant" (Cbor.Map [ (Cbor.Text "token", Cbor.Bytes token.hash) ])
    in
    ok grant_result
      ~included:[ (token.hash, token); (t.identity.identity_hash, t.identity.peer_entity); (sgn.hash, sgn) ]
  end

let req_grants_of params =
  match Option.bind params (fun p -> Model.field p "grants") with Some (Cbor.Array l) -> l | _ -> []

let capability_handler (t : t) (exec : Model.entity) ~(caller_cap : Model.entity option) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  let params = entity_field exec "params" in
  let author = Model.bytes_field exec "author" in
  match op with
  | "request" -> (
      match author with
      | None -> err 403 "capability_denied"
      | Some grantee_hash -> mint_bounded t ~caller_cap ~req_grants:(req_grants_of params) ~grantee_hash ())
  | "delegate" -> (
      (* parent MUST be present and non-zero (v7.62 §9), checked before the
         same-peer gate so a malformed delegate is a 400 not a 501. *)
      match Option.bind params (fun p -> Model.bytes_field p "parent") with
      | None -> err 400 "unexpected_params" ~message:"delegate: parent required"
      | Some ph when is_zero_hash ph -> err 400 "unexpected_params" ~message:"delegate: zero parent"
      | Some ph ->
          (* delegate is same-peer-only in v1 (closeout F1) — a remote caller
             (author != local identity) MUST receive 501, not 403. *)
          if author <> Some t.identity.identity_hash then
            err 501 "unsupported_operation" ~message:"delegate: same-peer-only in v1"
          else (
            match author with
            | None -> err 403 "capability_denied"
            | Some grantee_hash ->
                mint_bounded t ~caller_cap ~req_grants:(req_grants_of params) ~grantee_hash ~parent:ph ()))
  | "revoke" -> (
      match Option.bind params (fun p -> Model.bytes_field p "token") with
      | None -> err 400 "unexpected_params" ~message:"revoke: missing token"
      | Some token_h when is_zero_hash token_h -> err 400 "unexpected_params" ~message:"revoke: zero token"
      | Some token_h ->
          let marker =
            Model.make ~typ:"system/capability/revocation"
              (Cbor.Map [ (Cbor.Text "token", Cbor.Bytes token_h); (Cbor.Text "revoked_at", Cbor.Uint (now_ms ())) ])
          in
          Store.bind t.store ~path:("/" ^ t.local_peer ^ "/system/capability/revocations/" ^ Model.hex token_h) marker;
          ok Wire.empty_params)
  | "configure" -> (
      (* peer_pattern MUST be either a full hex hash (66 hex chars incl. format
         byte) or the literal "default"; partial prefixes are rejected (§6.2/F8). *)
      match Option.bind params (fun p -> Model.text_field p "peer_pattern") with
      | None -> err 400 "unexpected_params" ~message:"configure: missing peer_pattern"
      | Some pp ->
          let is_hex = String.length pp = 66 && String.for_all (fun c ->
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) pp in
          (* v7.65 rule 3 lazy-canon: a full Base58 peer_id for an unknown peer is
             accepted (pending canonicalization). Partial prefixes are still rejected. *)
          if not (String.equal pp "default" || is_hex || Capability.is_peer_id pp) then
            err 400 "invalid_peer_pattern" ~message:pp
          else (
            match params with
            | Some p ->
                Store.bind t.store ~path:("/" ^ t.local_peer ^ "/system/capability/policy/" ^ pp) p;
                ok Wire.empty_params
            | None -> err 400 "unexpected_params"))
  | other -> err 501 "unsupported_operation" ~message:("capability: " ^ other)

(* ── handlers handler (§6.2 / §6.13(a)) — register/unregister ──────────────── *)

(* Derive the install pattern from EXECUTE.resource.targets[0] (system/handler/{pattern}).
   Exactly one target is required — else 400 ambiguous_resource (§6.2). *)
let register_pattern (exec : Model.entity) : (string, outcome) result =
  match resource_target exec with
  | None -> Error (err 400 "ambiguous_resource" ~message:"register/unregister require exactly one resource target")
  | Some target ->
      let prefix = "system/handler/" in
      if not (Capability.starts_with ~prefix target) || String.length target = String.length prefix then
        Error (err 400 "invalid_resource" ~message:"resource target MUST be system/handler/{pattern}")
      else Ok (String.sub target (String.length prefix) (String.length target - String.length prefix))

(* register (§6.2 / §6.13(a)): the five normative writes. A 501 stub is non-conformant. *)
let register (t : t) (exec : Model.entity) : outcome =
  match register_pattern exec with
  | Error e -> e
  | Ok pattern -> (
      match entity_field exec "params" with
      | None -> err 400 "unexpected_params" ~message:"register: missing params"
      | Some req when not (String.equal req.typ "system/handler/register-request") ->
          err 400 "unexpected_params" ~message:("register expects register-request, got " ^ req.typ)
      | Some req ->
          let manifest = match Model.field req "manifest" with Some m -> m | None -> Cbor.Map [] in
          let name = match Model.map_get manifest "name" with Some (Cbor.Text s) -> s | _ -> pattern in
          let operations = match Model.map_get manifest "operations" with Some o -> o | None -> Cbor.Map [] in
          let expression_path = match Model.map_get manifest "expression_path" with Some (Cbor.Text s) -> Some s | _ -> None in
          let internal_scope = Model.map_get manifest "internal_scope" in
          (* Grant scope = requested_scope ?? internal_scope ?? [] (§6.2 grant issuance). *)
          let grant_scope =
            match Model.field req "requested_scope", internal_scope with
            | Some (Cbor.Array l), _ -> l
            | _, Some (Cbor.Array l) -> l
            | _ -> []
          in
          let interface_rel = "system/handler/" ^ pattern in
          let abs rel = "/" ^ t.local_peer ^ "/" ^ rel in
          (* (1) handler manifest (dispatch target) at the pattern path. *)
          let handler_e =
            Model.make ~typ:"system/handler"
              (Cbor.Map
                 ((Cbor.Text "interface", Cbor.Text interface_rel)
                  :: (match expression_path with Some p -> [ (Cbor.Text "expression_path", Cbor.Text p) ] | None -> [])
                  @ (match internal_scope with Some s -> [ (Cbor.Text "internal_scope", s) ] | None -> [])))
          in
          Store.bind t.store ~path:(abs pattern) handler_e;
          (* (2) associated types at system/type/{type_name}. *)
          (match Model.field req "types" with
           | Some (Cbor.Map kvs) ->
               List.iter
                 (fun (k, v) -> match k with
                   | Cbor.Text tn -> Store.bind t.store ~path:(abs ("system/type/" ^ tn)) (Model.make ~typ:"system/type" v)
                   | _ -> ())
                 kvs
           | _ -> ());
          (* (3) self-issued, signed handler grant + (4) grant-signature at the §3.5 pointer. *)
          let token, sgn = mint_token t ~grantee_hash:t.identity.identity_hash ~grants:grant_scope () in
          Store.bind t.store ~path:(abs ("system/capability/grants/" ^ pattern)) token;
          Store.bind t.store ~path:(abs ("system/signature/" ^ Model.hex token.hash)) sgn;
          (* (5) handler interface entity (discovery index). *)
          let iface_e =
            Model.make ~typ:"system/handler/interface"
              (Cbor.Map [ (Cbor.Text "pattern", Cbor.Text pattern); (Cbor.Text "name", Cbor.Text name); (Cbor.Text "operations", operations) ])
          in
          Store.bind t.store ~path:(abs interface_rel) iface_e;
          let result =
            Model.make ~typ:"system/handler/register-result"
              (Cbor.Map [ (Cbor.Text "pattern", Cbor.Text pattern); (Cbor.Text "grant", token.data) ])
          in
          ok result)

(* unregister (§6.2): reverse all five writes; the grant-signature is removed alongside
   the grant (writer/unregister symmetry). Installed types are left in place (A-OC-009). *)
let unregister (t : t) (exec : Model.entity) : outcome =
  match register_pattern exec with
  | Error e -> e
  | Ok pattern ->
      let abs rel = "/" ^ t.local_peer ^ "/" ^ rel in
      (match Store.get_at t.store ~path:(abs ("system/capability/grants/" ^ pattern)) with
       | Some g ->
           Store.unbind t.store ~path:(abs ("system/signature/" ^ Model.hex g.hash));
           Store.unbind t.store ~path:(abs ("system/capability/grants/" ^ pattern))
       | None -> ());
      Store.unbind t.store ~path:(abs pattern);
      Store.unbind t.store ~path:(abs ("system/handler/" ^ pattern));
      ok Wire.empty_params

let handlers_handler (t : t) (exec : Model.entity) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  match op with
  | "register" -> register t exec
  | "unregister" -> unregister t exec
  | other -> err 501 "unsupported_operation" ~message:("handler: " ^ other)

(* Entity-native dispatch (v7.74 §6.13(a)): a dynamically-registered handler has no
   in-process body; evaluate the body at its expression_path. The core peer's
   body-binding seam (impl-private §9.4) evaluates the minimal compute/literal shape and
   returns a compute/result — the §10.1 register round-trip shape. Richer bodies → 501.
   See A-OC-010. [handler_path] is the absolute handler-entity path. *)
let entity_native_dispatch (t : t) (handler_path : string) : outcome =
  match Store.get_at t.store ~path:handler_path with
  | None -> err 404 "handler_not_found" ~message:handler_path
  | Some he -> (
      match Model.text_field he "expression_path" with
      | None -> err 501 "no_handler_body" ~message:handler_path
      | Some expr_path -> (
          let abs = Capability.canonicalize ~local_peer:t.local_peer expr_path in
          match Store.get_at t.store ~path:abs with
          | None -> err 404 "expression_not_found" ~message:abs
          | Some expr when String.equal expr.typ "compute/literal" -> (
              match Model.field expr "value" with
              | Some value ->
                  ok (Model.make ~typ:"compute/result"
                        (Cbor.Map [ (Cbor.Text "value", value); (Cbor.Text "expression", Cbor.Bytes expr.hash) ]))
              | None -> err 400 "unexpected_params" ~message:"compute/literal missing value")
          | Some expr -> err 501 "unsupported_expression" ~message:expr.typ))

let types_handler (_t : t) (exec : Model.entity) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  err 501 "unsupported_operation" ~message:("type: " ^ op)

(* ── dispatcher-level signature ingestion (§6.5) ──────────────────────────── *)

let ingest_signatures (t : t) (env : Model.envelope) : unit =
  List.iter
    (fun (_, e) ->
      if String.equal e.Model.typ "system/signature" then begin
        Store.put_entity t.store e;
        match Model.bytes_field e "signer" with
        | Some signer_h ->
            (match Model.included_get env signer_h with
             | Some signer_peer ->
                 Store.put_entity t.store signer_peer;
                 (match Model.text_field signer_peer "peer_id", Model.bytes_field e "target" with
                  | _, Some target ->
                      (* signer peer_id derived from its public_key (v7.65 peer has no peer_id field) *)
                      (match Model.bytes_field signer_peer "public_key" with
                       | Some pk ->
                           let pid = Identity.peer_id_of_pubkey pk in
                           Store.bind t.store
                             ~path:("/" ^ pid ^ "/system/signature/" ^ Model.hex target) e
                       | None -> ())
                  | _ -> ())
             | None -> ())
        | None -> ()
      end)
    env.included

(* ── handler resolution (§6.6) — backward tree-walk ───────────────────────── *)

let resolve_handler (t : t) (path : string) : (string * string) option =
  let segs = String.split_on_char '/' path in
  let n = List.length segs in
  let rec try_len i =
    if i < 1 then None
    else
      let prefix = String.concat "/" (List.filteri (fun j _ -> j < i) segs) in
      match Store.get_at t.store ~path:prefix with
      | Some e when String.equal e.Model.typ "system/handler" ->
          Some (prefix, String.sub path (String.length prefix) (String.length path - String.length prefix))
      | _ -> try_len (i - 1)
  in
  try_len n

let strip_local (t : t) (pattern : string) : string =
  let prefix = "/" ^ t.local_peer ^ "/" in
  if Capability.starts_with ~prefix pattern then
    String.sub pattern (String.length prefix) (String.length pattern - String.length prefix)
  else pattern

(* ── §7a conformance test-handlers (the system/validate namespace) ────────────
   NOT core protocol — conformance scaffolding (GUIDE-CONFORMANCE §7a), present only
   under the [conformance] opt-in (--validate), off by default. They give a black-box
   validator a native, compute-free way to drive the two extensibility hooks with no
   other wire-reachable trigger in a core peer: echo (the §6.13(a) resolve→dispatch
   half, closes A-011) and dispatch-outbound (the §6.13(b)/§6.11 outbound seam via
   reentry, closes A-013). *)

(* system/validate/echo — return the params entity verbatim (no compute). *)
let echo_handler (_t : t) (exec : Model.entity) : outcome =
  match entity_field exec "params" with
  | Some p -> ok p
  | None -> err 400 "invalid_params" ~message:"echo requires a params entity"

(* system/validate/dispatch-outbound — originate exactly one outbound EXECUTE via the
   §6.11 reentry seam back to the caller (target/operation/value in params), return the
   downstream response. The reentry direction can only be authorized by the caller, so
   the caller carries the cap it minted for this peer in-band (three nested entities). *)
let dispatch_outbound_handler (t : t) (conn : conn) (exec : Model.entity) : outcome =
  match entity_field exec "params" with
  | None -> err 400 "invalid_params" ~message:"dispatch-outbound requires a params entity"
  | Some p -> (
      let target = Option.value ~default:"" (Model.text_field p "target") in
      let operation = Option.value ~default:"" (Model.text_field p "operation") in
      match
        ( Model.field p "value",
          entity_field p "reentry_capability",
          entity_field p "reentry_granter",
          entity_field p "reentry_cap_signature" )
      with
      | Some value, Some capability, Some granter_peer, Some capability_signature -> (
          (* §7a.1: the [value] field IS the outbound params entity data — pass it
             through (the reference uses it directly). Re-wrapping as {value: value}
             double-wraps, so the echo's result.value returns a map (keystone §7b t1_2). *)
          let inner = Model.make ~typ:"primitive/any" value in
          let resource =
            Cbor.Map [ (Cbor.Text "targets", Cbor.Array [ Cbor.Text ("system/handler/" ^ target) ]) ]
          in
          match
            outbound_dispatch t conn ~uri:target ~operation ~params:inner ~resource ~capability
              ~granter_peer ~capability_signature ()
          with
          | None -> err 503 "no_outbound_seam" ~message:"no live §6.11 reentry connection"
          | Some env ->
              let status = Option.value ~default:0L (Model.uint_field env.Model.root "status") in
              let result_cbor = Option.value ~default:(Cbor.Map []) (Model.field env.Model.root "result") in
              ok
                (Model.make ~typ:"primitive/any"
                   (Cbor.Map [ (Cbor.Text "status", Cbor.Uint status); (Cbor.Text "result", result_cbor) ])))
      | _ -> err 400 "invalid_params" ~message:"dispatch-outbound requires value + reentry authority")

(* ── dispatch chain (§6.5) ────────────────────────────────────────────────── *)

(* A 500 response for an envelope whose dispatch raised unexpectedly — keeps the
   connection alive (§3.3 every EXECUTE gets a response) instead of closing it. *)
let internal_error_response (env : Model.envelope) : Model.envelope option =
  let request_id = Option.value ~default:"" (Model.text_field env.root "request_id") in
  Some
    { Model.root = Wire.make_response ~request_id ~status:500 ~result:(Wire.error_result "internal_error");
      included = [] }

let dispatch (t : t) (conn : conn) (env : Model.envelope) : Model.envelope option =
  let exec = env.root in
  if not (String.equal exec.typ "system/protocol/execute") then None  (* §3.3: server side ignores non-EXECUTE *)
  else begin
    let request_id = Option.value ~default:"" (Model.text_field exec "request_id") in
    let uri = Option.value ~default:"" (Model.text_field exec "uri") in
    let outcome =
      try
      if String.equal uri "system/protocol/connect" then
        connect_handler t conn exec ~included:env.included
      else begin
        ingest_signatures t env;
        match Capability.verify_request ~local_peer:t.local_peer ~store:t.store env with
        | exception Capability.Unresolvable_grantee -> err 401 "unresolvable_grantee"
        | Capability.Req_authn_fail -> err 401 "authentication_failed"
        | Capability.Req_authz_deny -> err 403 "capability_denied"
        | Capability.Req_chain_too_deep -> err 400 "chain_depth_exceeded"
        | Capability.Req_allow -> (
            let path = Capability.canonicalize ~local_peer:t.local_peer (Capability.normalize_uri uri) in
            (* §1.4: inbound dispatch must target the local peer *)
            if not (String.equal (Capability.extract_peer ~local_peer:t.local_peer path) t.local_peer) then
              err 404 "handler_not_found" ~message:"not local peer"
            else
              match resolve_handler t path with
              | None -> err 404 "handler_not_found" ~message:path
              | Some (pattern, _suffix) -> (
                  let caller_cap =
                    Option.bind (Model.bytes_field exec "capability") (fun c -> Model.included_get env c)
                  in
                  match caller_cap with
                  | None -> err 403 "capability_denied"
                  | Some cap -> (
                      (* §PR-8: resolve the cap's granter once at the dispatch
                         site; the grant resource patterns canonicalize against
                         it. Unresolvable / multisig granter → local frame. *)
                      let granter_peer =
                        let resolve_fn = Capability.resolve env.included t.store in
                        match Capability.resolve_granter_peer_id ~resolve_fn cap with
                        | Some p -> p
                        | None -> t.local_peer
                      in
                      match Capability.check_permission ~local_peer:t.local_peer ~granter_peer exec cap ~handler_pattern:pattern with
                      | Capability.Deny -> err 403 "capability_denied"
                      | Capability.Allow -> (
                          match strip_local t pattern with
                          | "system/tree" -> tree_handler t exec
                          | "system/capability" -> capability_handler t exec ~caller_cap
                          | "system/handler" -> handlers_handler t exec
                          | "system/type" -> types_handler t exec
                          (* §7a conformance handlers — only resolvable when bootstrapped
                             under --validate (off by default → resolve_handler 404s). *)
                          | "system/validate/echo" -> echo_handler t exec
                          | "system/validate/dispatch-outbound" -> dispatch_outbound_handler t conn exec
                          (* A dynamically-registered handler (§6.13(a)): no in-process
                             body — dispatch its entity-native body at [pattern]. *)
                          | _ -> entity_native_dispatch t pattern))))
      end
      with
      | Capability.Unresolvable_grantee -> err 401 "unresolvable_grantee"
      | _ -> err 500 "internal_error"
    in
    let response = Wire.make_response ~request_id ~status:outcome.status ~result:outcome.result in
    Some { Model.root = response; included = outcome.included }
  end

(* ── bootstrap (§6.9) ─────────────────────────────────────────────────────── *)

let op_spec input output =
  let f k v = match v with Some s -> [ (Cbor.Text k, Cbor.Text s) ] | None -> [] in
  Cbor.Map (f "input_type" input @ f "output_type" output)

let bootstrap_handlers =
  [ ("system/tree", "Tree", [ ("get", (None, None)); ("put", (None, None)) ]);
    ("system/handler", "Handlers",
     [ ("register", (Some "system/handler/register-request", Some "system/handler/register-result"));
       ("unregister", (Some "system/handler/unregister-request", None)) ]);
    ("system/type", "Types",
     [ ("validate", (Some "system/type/validate-request", Some "system/type/validate-result")) ]);
    ("system/capability", "Capability",
     [ ("request", (Some "system/capability/request", Some "system/capability/grant"));
       ("revoke", (Some "system/capability/revoke-request", None));
       ("configure", (Some "system/capability/policy-entry", None));
       ("delegate", (Some "system/capability/delegate-request", Some "system/capability/grant")) ]);
    ("system/protocol/connect", "Connect", [ ("hello", (None, None)); ("authenticate", (None, None)) ]) ]

let create ~(seed : string) ~(open_grants : bool) ?(conformance = false) () : t =
  let identity = Identity.of_seed seed in
  let store = Store.create () in
  let local_peer = identity.peer_id in
  let t = { identity; store; local_peer; open_grants; conformance } in
  (* local identity entity is in the store (root-granter resolution) *)
  Store.put_entity store identity.peer_entity;
  (* publish the 53 core types (§9.5) *)
  Type_defs.publish store ~local_peer;
  (* bootstrap handlers: handler entity at pattern, interface at index, grant *)
  List.iter
    (fun (pattern, name, ops) ->
      let operations = Cbor.Map (List.map (fun (o, (i, ou)) -> (Cbor.Text o, op_spec i ou)) ops) in
      let handler_e =
        Model.make ~typ:"system/handler"
          (Cbor.Map [ (Cbor.Text "interface", Cbor.Text ("system/handler/" ^ pattern)) ])
      in
      Store.bind store ~path:("/" ^ local_peer ^ "/" ^ pattern) handler_e;
      let interface_e =
        Model.make ~typ:"system/handler/interface"
          (Cbor.Map
             [ (Cbor.Text "pattern", Cbor.Text pattern);
               (Cbor.Text "name", Cbor.Text name);
               (Cbor.Text "operations", operations) ])
      in
      Store.bind store ~path:("/" ^ local_peer ^ "/system/handler/" ^ pattern) interface_e;
      let token, _ = mint_token t ~grantee_hash:identity.identity_hash ~grants:[] () in
      Store.bind store ~path:("/" ^ local_peer ^ "/system/capability/grants/" ^ pattern) token)
    bootstrap_handlers;
  (* §6.9a Peer Authority Bootstrap (L0 write-set): the self-owner capability (a root
     cap, full scope over /{peer_id}/*, grantee = own identity, §6.9a.0 detached-sig
     shape: cap token at the hex policy path + its self-signature at the §3.5 pointer)
     and the default scope-template entry. Read back by authenticate (dual-form lookup).
     [open_grants] selects the degenerate [default → *] (= retired --debug-open-grants). *)
  let policy_base = "/" ^ local_peer ^ "/system/capability/policy/" in
  let owner_token, owner_sig =
    mint_token t ~grantee_hash:identity.identity_hash ~grants:(owner_grants t) ()
  in
  Store.bind store ~path:(policy_base ^ Model.hex identity.identity_hash) owner_token;
  Store.bind store ~path:("/" ^ local_peer ^ "/system/signature/" ^ Model.hex owner_token.hash) owner_sig;
  let default_grants = if open_grants then open_grants_scope () else discovery_floor () in
  let default_entry =
    Model.make ~typ:"system/capability/policy-entry"
      (Cbor.Map [ (Cbor.Text "peer_pattern", Cbor.Text "default"); (Cbor.Text "grants", Cbor.Array default_grants) ])
  in
  Store.bind store ~path:(policy_base ^ "default") default_entry;
  (* §7a conformance handlers — bootstrap the two test-handlers' tree entities (handler
     entity at pattern, interface at index, grant) ONLY under --validate, so resolve_handler
     finds them. Off by default: not bootstrapped → unreachable (404). dispatch-outbound is a
     standing outbound originator and must never ship live in a production peer. *)
  if conformance then
    List.iter
      (fun (pattern, name, ops) ->
        let operations = Cbor.Map (List.map (fun (o, (i, ou)) -> (Cbor.Text o, op_spec i ou)) ops) in
        let handler_e =
          Model.make ~typ:"system/handler"
            (Cbor.Map [ (Cbor.Text "interface", Cbor.Text ("system/handler/" ^ pattern)) ])
        in
        Store.bind store ~path:("/" ^ local_peer ^ "/" ^ pattern) handler_e;
        let interface_e =
          Model.make ~typ:"system/handler/interface"
            (Cbor.Map
               [ (Cbor.Text "pattern", Cbor.Text pattern);
                 (Cbor.Text "name", Cbor.Text name);
                 (Cbor.Text "operations", operations) ])
        in
        Store.bind store ~path:("/" ^ local_peer ^ "/system/handler/" ^ pattern) interface_e;
        let token, _ = mint_token t ~grantee_hash:identity.identity_hash ~grants:[] () in
        Store.bind store ~path:("/" ^ local_peer ^ "/system/capability/grants/" ^ pattern) token)
      [ ("system/validate/echo", "validate-echo", [ ("echo", (None, None)) ]);
        ("system/validate/dispatch-outbound", "validate-dispatch-outbound", [ ("dispatch", (None, None)) ]) ];
  t
