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
(* [mint_token] mints + signs a capability token granted by us to [grantee_hash].

   [?created_at] lets the caller pin the instant so a computed [?expires_at] is
   guaranteed relative to the SAME created_at that lands in the token (§5.10 also
   wants the evaluation timestamp sampled once, not re-read per term).

   [?expires_at] carries §5.6's MIN_DEFINED ceiling: [None] means no term was
   defined and the token genuinely has no expiry (the ONLY "no bound" spelling),
   while [Some v] is emitted verbatim — including [v = created_at], which §5.6
   rule 2 requires for [ttl_ms = 0] and which means "already expired at every
   observable instant", not "unbounded". *)
let mint_token (t : t) ~grantee_hash ?parent ?created_at ?expires_at
    ~(grants : Cbor.t list) () : Model.entity * Model.entity =
  let created = match created_at with Some c -> c | None -> now_ms () in
  let data =
    (Cbor.Text "granter", Cbor.Bytes t.identity.identity_hash)
    :: (Cbor.Text "grantee", Cbor.Bytes grantee_hash)
    :: (Cbor.Text "grants", Cbor.Array grants)
    :: (Cbor.Text "created_at", Cbor.Uint created)
    :: (match expires_at with Some e -> [ (Cbor.Text "expires_at", Cbor.Uint e) ] | None -> [])
    @ (match parent with Some p -> [ (Cbor.Text "parent", Cbor.Bytes p) ] | None -> [])
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
(* [granter_peers] and [capability_signatures] are PLURAL (GUIDE-CONFORMANCE §7a.1,
   0.8.2.19) so a K-of-N root can present every granter identity and every link
   signature; the ordinary single-granter case is a list of one. Every member goes
   into [included] because §5.5's chain walk resolves granters and signers BY HASH out
   of that map -- a granter left out is a link the verifier cannot reach, which fails
   closed and reads as the peer refusing the credential form rather than as a carrier
   we truncated.

   The AMBIENT arm carries no credential ([capability = None] selects it), so the
   EXECUTE carries no [capability] field and the bundle carries no cap, granter or
   cap-signature. It still authenticates as this peer -- §5.2a's auth class is a
   separate question from whether any capability covers the request. *)
let outbound_dispatch (t : t) (conn : conn) ~(uri : string) ~(operation : string)
    ~(params : Model.entity) ?(resource : Cbor.t option) ~(capability : Model.entity option)
    ~(granter_peers : Model.entity list) ~(capability_signatures : Model.entity list) () : Model.envelope option =
  match conn.outbound with
  | None -> None   (* no reentrant connection → seam unavailable *)
  | Some send ->
      conn.out_counter <- conn.out_counter + 1;
      let request_id = "out-" ^ string_of_int conn.out_counter in
      let exec =
        Wire.make_execute ~request_id ~uri ~operation ~params ?resource
          ~author:t.identity.identity_hash
          ?capability:(Option.map (fun (c : Model.entity) -> c.Model.hash) capability) ()
      in
      let exec_sig = Identity.sign_entity t.identity exec in
      let cred_carried =
        match capability with
        | None -> []
        | Some cap ->
            (cap.Model.hash, cap)
            :: List.map (fun (e : Model.entity) -> (e.Model.hash, e))
                 (granter_peers @ capability_signatures)
      in
      let included =
        cred_carried
        @ [ (t.identity.identity_hash, t.identity.peer_entity);   (* grantee + author (us) *)
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
        let initiator_peer = Option.bind params (fun p -> Model.text_field p "peer_id") in
        (* §4.5 mutual verifiability, the direction that is NOT the array.
           key_types is an ACCEPT-SET; the initiator's OWN key_type is not in it —
           it rides in its peer_id — so a hello may advertise a perfectly good
           accept-set and still name an identity we cannot verify. Checking only
           the array leaves that MUST unenforced at hello, which is where §4.5
           wants it (the "symmetric earliest-reject guarantee"); authenticate
           catches it one leg later, which is conformant but non-canonical.

           An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
           field, not a key_type we lack, and authenticate already refuses it.
           Peer_id.parse raises on a bad Base58 body, so the failure is caught
           and read as "not our question" rather than as a refusal. *)
        let initiator_key_ok = match initiator_peer with
          | None -> true
          | Some pid -> (try (Peer_id.parse pid).key_type = 0x01 with _ -> true) in
        (* §4.5 `protocols` — the one negotiated field Required with NO default,
           so there is no floor to fall back to, and its two failure modes carry
           different codes on purpose (§4.5 table row / §4.7 row 1):

             absent or empty     -> 400 invalid_request       (a malformed hello)
             non-empty, disjoint -> 400 incompatible_protocol (we compared)

           "a caller that named no version cannot be told the comparison failed" —
           the remedies differ (send the field vs change the version) and §4.7
           exists so the code selects the remedy. The vocabulary is §8.4's
           protocol version identifiers, today the single entity-core/1.0. *)
        let protos = str_array "protocols" in
        (* §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
           HALF-OPEN connection (hello done, authenticate not yet) is an operation
           we implement arriving in a state that forbids it — the same class as
           connection_already_established above, taking the same 409. A half-open
           connection is NOT established, so the guard above cannot reach it; §4.7
           names this gap explicitly because two adjacent rules each look like they
           cover it and neither does. *)
        if conn.issued_nonce <> None then err 409 "connection_sequence_error"
        else if not hash_ok then err 400 "incompatible_hash_format"
        else if not key_ok then err 400 "unsupported_key_type"
        else if not initiator_key_ok then err 400 "unsupported_key_type"
        (* ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
           precedence between the three, so a hello disjoint in more than one
           dimension may be refused on any of them — but the choice is OBSERVABLE,
           and the reference peer refuses key_types first. Checking protocols first
           is equally spec-legal and makes AGILITY-UNKNOWN-1 answer
           incompatible_protocol, because that probe's own hello carries protocols
           ["entity-core/v7"] — a spec-line name, not a §8.4 identifier. Matching
           the reference's precedence is the interoperable choice; the probe's
           identifier is routed as F56. *)
        else if (match protos with None -> true | Some l -> l = []) then
          err 400 "invalid_request" ~message:"hello: protocols absent or empty"
        else if not (List.mem "entity-core/1.0" (Option.value ~default:[] protos)) then
          err 400 "incompatible_protocol"
        else begin
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
      (* RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
         single-use nonce — pinned to 401 invalid_nonce, not a 409 state-conflict
         which under-signals the replay. *)
      if conn.established then err 401 "invalid_nonce"
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
  (* §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
     400 invalid_request, not the 501 every other handler answers. The table
     separates a STATE conflict from an UNKNOWN operation because they select
     different remedies — "an unknown connect operation is not out of order at
     all; it exists in no state", so connection_sequence_error would point the
     caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
     scoped "in any state", so this arm covers pre-handshake AND established;
     the genuine sequence cases are refused above, with 409.

     SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
     (§3.3's 501 row, §6.2) is a different contract and is separately gated;
     moving the shared 501 would trade one green check for another. *)
  | other -> err 400 "invalid_request" ~message:("connect: unknown operation " ^ other)

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

(* [resolve_token t h] finds a token entity by content hash in the local store.
   Used for the §5.6 parent.expires_at term on the delegate path; an unresolvable
   parent simply contributes no term (MIN_DEFINED is over DEFINED terms only). *)
let resolve_token (t : t) (h : string) : Model.entity option = Store.get_by_hash t.store h

let is_deletion_marker (t : t) (h : string) : bool =
  match Store.get_by_hash t.store h with
  | Some e -> String.equal e.Model.typ "system/deletion-marker"
  | None -> false

(* [entry_visible] answers §6.3's per-entry listing check for ONE child segment.

   An UNAUTHENTICATED context ([~caller_cap = None]) is the bootstrap / internal
   path and is NOT filtered -- the filter's subject is "the caller's verified
   capability", and where there is none there is no caller to narrow. *)
let entry_visible (t : t) ~(caller_cap : Model.entity option) ~(pattern : string)
    ~(dir : string) ~(segment : string) : bool =
  match caller_cap with
  | None -> true
  | Some cap ->
      let dir = if String.length dir > 0 && dir.[String.length dir - 1] = '/' then dir else dir ^ "/" in
      Capability.check_path_permission ~local_peer:t.local_peer ~operation:"get"
        ~path:(dir ^ segment) ~token:cap ~handler_pattern:pattern

(* Build a system/tree/listing (§3.9), omitting deletion-marker-bound leaves
   (CORE-TREE-DELETE-1 / §6.3 filter), and FILTERED PER-ENTRY against the caller's
   own capability (§6.3, 0.8.2.21/.22):

     "When any handler returns a multi-entry result whose entries are tree paths,
      each entry MUST be individually checked using check_path_permission. Entries
      for which check_path_permission returns DENY MUST be omitted. The result's
      `count` field MUST reflect the filtered entry count, not the source tree's
      total count."

   This is the read path at its highest volume and it is the reason 0.8.2.21
   refused to carve reads out of the caller-specified-path rule: an unfiltered
   listing discloses the EXISTENCE of every binding under a prefix to a caller
   whose capability covers none of them. [count] follows the FILTERED total below
   -- a count that still reports the source total is the disclosure the rule
   exists to prevent.

   THE DIRECTORY ITSELF IS DELIBERATELY NOT CHECKED. §6.3 makes each ENTRY the
   subject, and testing the prefix would deny a listing to a caller whose grant
   covers children but not the node above them, which is the ordinary shape of a
   narrowed grant. *)
let build_listing (t : t) ~(caller_cap : Model.entity option) ~(pattern : string) ~(path : string) : outcome =
  let entries = Store.listing t.store ~prefix:path in
  let entries =
    List.filter
      (fun (_, hash, has_children) ->
        match hash with Some h when (not has_children) && is_deletion_marker t h -> false | _ -> true)
      entries
  in
  let entries =
    List.filter (fun (seg, _, _) -> entry_visible t ~caller_cap ~pattern ~dir:path ~segment:seg) entries
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

(* Digest byte length for a content_hash_format code per the §1.2 seed table,
   or None when this peer cannot VERIFY that code. The total wire length is
   this plus the varint prefix, which is not a constant of the code (§7.3):
   codes >= 0x80 occupy more than one byte. This peer computes sha256 and
   sha384 only, so 0x02 is honestly unsupported. *)
let hash_digest_len (code : int) : int option =
  match code with 0x00 -> Some 32 | 0x01 -> Some 48 | _ -> None

(* §6.3's [put] admission ladder (normative, 0.8.2.11).

   [put] is a RECEIPT path: the submitter authors the entity, the peer
   validates what it received (§1.8 item 1) and MUST NOT author a submitted
   entity's content_hash on the submitter's behalf. Two ordered steps:

   1. STRUCTURE — a map carrying a non-empty text [type], a PRESENT [data]
      (any CBOR value; null is a legal payload), and a [content_hash] that is a
      well-formed system/hash whose total byte length matches its format code
      (§1.2). Any failure -> 400 invalid_request. A well-formed hash naming a
      format code this peer cannot verify is the separate §1.2 ingest-dispatch
      case -> 400 unsupported_content_hash_format.
   2. HASH — carried content_hash vs content_hash({type, data}). Disagreement
      -> 400 hash_mismatch.

   Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
   inputs are exactly what step 1 establishes, so a submission that is both
   malformed and mis-hashed is step 1's and answers invalid_request.

   Structural admission is not semantic validation: [data] is never checked
   against the type named by [type]. *)
let admit_put (v : Cbor.t) : (Model.entity, outcome) result =
  let refuse code message = Error (err 400 code ~message) in
  match v with
  | Cbor.Map _ -> (
      let get key = Model.map_get v key in
      match get "type" with
      | Some (Cbor.Text typ) when String.length typ > 0 -> (
          match get "data" with
          | None -> refuse "invalid_request" "put: entity.data absent"
          | Some data -> (
              match get "content_hash" with
              | Some (Cbor.Bytes carried) when String.length carried > 0 -> (
                  match Varint.decode carried 0 with
                  | exception _ ->
                      refuse "invalid_request"
                        "put: entity.content_hash is not a well-formed system/hash"
                  | code, n -> (
                      match hash_digest_len code with
                      (* §1.2 / §4.7 row 5 — well-formed, but this peer cannot
                         interpret it. NOT invalid_request: the shape is fine,
                         the algorithm is what we lack. *)
                      | None ->
                          refuse "unsupported_content_hash_format"
                            "put: unsupported content_hash_format"
                      | Some digest_len ->
                          if String.length carried <> n + digest_len then
                            refuse "invalid_request"
                              "put: content_hash length does not match its format code"
                          else if
                            String.equal carried
                              (Hash.content_hash ~format_code:code ~typ ~data ())
                          then
                            (* The carried hash IS the entity's address;
                               recomputing it into the store would be the
                               authoring arm §6.3 forbids. *)
                            Ok { Model.typ; data; hash = carried }
                          else
                            refuse "hash_mismatch"
                              "put: content_hash does not match content_hash({type, data})"))
              | _ ->
                  refuse "invalid_request"
                    "put: entity.content_hash absent or not a byte string"))
      | _ ->
          refuse "invalid_request"
            "put: entity.type absent, empty or not a text string")
  | _ -> refuse "invalid_request" "put: entity is not a map"

(* [is_pattern_path] reports whether a resource target is a §5.4 PATTERN rather
   than a concrete path. A resource-requiring operation takes a concrete path
   (0.8.2.20), and a trailing "/" is a LISTING request rather than a pattern --
   only a "*" makes it one. *)
let is_pattern_path (target : string) : bool = String.contains target '*'

(* THE OPERATION IS RESOLVED FIRST, AND THE §3.3 RESOURCE LADDER IS REACHABLE ONLY
   FROM A KNOWN OPERATION (RULE G / F52).

   This match used to dispatch on the PAIR [op, resource_target exec], with an
   [| _, None -> 400 ambiguous_resource] arm sitting ABOVE [| other, _ -> 501].
   OCaml's match is first-fit, so the any-operation/no-resource arm captured every
   UNKNOWN operation that arrived without a resource, and the peer answered a
   RESOURCE fault for an OPERATION fault. Measured on the wire before the change:

     system/tree:bogusop, no resource   -> 400 ambiguous_resource   (wrong)
     system/tree:bogusop, WITH resource -> 501 unsupported_operation (right)

   -- the same operation, two answers, decided by a field that has nothing to do
   with whether the operation exists. The second row is the control that makes the
   first attributable to ORDERING rather than to a missing 501 arm.

   §4.7's reasoning for the connect handler's row 10 is the general principle and
   it applies here: the code selects the caller's REMEDY. "Disambiguate your
   request" is useless advice about an operation this handler does not implement.
   [entity-system-conformance] measured the same defect independently (X9/F52) and
   names [elixir] and [haskell] as carrying the same shape. *)
let tree_handler (t : t) ~(caller_cap : Model.entity option) ~(pattern : string)
    (exec : Model.entity) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  (* §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
     [resource.targets]: a handler that counts the effective list and then takes
     targets[0] has implemented the arithmetic completely and is still reading a
     path no authorization covered. *)
  let eff, has_resource = Capability.effective_targets ~local_peer:t.local_peer exec in
  (* §6.3: the handler MUST verify the CALLER's capability covers the path it is
     about to touch. NOT a secondary check -- the dispatch-level check never saw
     this path if the caller excluded it. An unauthenticated context (bootstrap /
     internal) has no caller to narrow and is not filtered. *)
  let path_permitted operation path =
    match caller_cap with
    | None -> true
    | Some cap ->
        Capability.check_path_permission ~local_peer:t.local_peer ~operation ~path ~token:cap
          ~handler_pattern:pattern
  in
  match op with
  | "get" -> (
      if not has_resource then
        (* THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
           IS WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is
           scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); [get]
           does not. For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
           present-but-empty case by whether the absent case is WIDER than the
           request -- BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty --
           and requires the operation to declare which it is.

           EXTENSION-TREE §2.2a (v4.11) is that declaration: [get] is
           resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
           listing", self-excluded case "400 path_required". Both arms are pinned
           by text and neither is this peer's choice. *)
        build_listing t ~caller_cap ~pattern ~path:("/" ^ t.local_peer ^ "/")
      else if eff = [] then
        (* The self-excluded request: [resource] PRESENT, every target carved out by
           the caller's own exclude. Serving it the absent case "answers a request
           for one excluded path with a listing of the tree" (EXTENSION-TREE §2.2a)
           -- the root listing is wider than what was asked for, which is what
           BROAD-RESULT means. *)
        err 400 "path_required" ~message:"tree: effective target list is empty"
      else if List.length eff > 1 then
        err 400 "ambiguous_resource" ~message:"tree: more than one effective target"
      else
        let target = List.hd eff in
        if not (path_flex_ok target) then err 400 "invalid_path" ~message:target
        else if target = "" || target.[String.length target - 1] = '/' then
          build_listing t ~caller_cap ~pattern
            ~path:(Capability.canonicalize ~local_peer:t.local_peer target)
        else if is_pattern_path target then err 400 "malformed_resource" ~message:target
        else
          let path = Capability.canonicalize ~local_peer:t.local_peer target in
          if not (path_permitted "get" path) then err 403 "capability_denied" ~message:path
          else
            match Store.get_at t.store ~path with
            | Some e ->
                let mode = Option.bind (entity_field exec "params") (fun p -> Model.text_field p "mode") in
                if mode = Some "hash" then ok (Model.make ~typ:"system/hash" (Cbor.Bytes e.hash))
                else ok e
            | None -> err 404 "not_found" ~message:path)
  | "put" ->
      (* Same ladder as [get], with the two empties COLLAPSED rather than split:
         EXTENSION-TREE §2.2a (v4.11) declares [put] resource-REQUIRED, so §3.3's
         "an empty effective list IS the absent case" applies in its unscoped form
         and both empties answer [path_required]. That is the same table [get]'s
         branch cites, read one row down -- the field is per-operation and neither
         answer is derivable from the handler's source.

         NOTE THE CODE CHANGE 0.8.2.20 FORCED: this arm answered [ambiguous_resource]
         for a MISSING target, which 0.8.2.20 names as the exact inversion it forbids
         ("answering ambiguous_resource for an absent resource inverts them"). The
         remedies differ -- *supply a resource* is not *disambiguate your request* --
         and the code is what selects between them. Measured on the wire before the
         change: put with no resource answered 400 ambiguous_resource. *)
      if (not has_resource) || eff = [] then
        err 400 "path_required" ~message:"tree: put requires a resource target"
      else if List.length eff > 1 then
        err 400 "ambiguous_resource" ~message:"tree: more than one effective target"
      else
        let target = List.hd eff in
        if not (path_flex_ok target) then err 400 "invalid_path" ~message:target
        else if is_pattern_path target then err 400 "malformed_resource" ~message:target
        else
          let path = Capability.canonicalize ~local_peer:t.local_peer target in
          if not (path_permitted "put" path) then err 403 "capability_denied" ~message:path
          else
            let params = entity_field exec "params" in
            let entity = Option.bind params (fun p -> Model.field p "entity") in
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
              | Some raw -> (
                  match admit_put raw with
                  | Error refusal -> refusal
                  | Ok e ->
                      Store.bind t.store ~path e;
                      ok (Model.make ~typ:"system/hash" (Cbor.Bytes e.hash)))
              | None -> err 400 "unexpected_params" ~message:"put: missing entity")
  | other -> err 501 "unsupported_operation" ~message:("tree: " ^ other)

(* ── capability handler (§6.2) ────────────────────────────────────────────── *)

let is_zero_hash (h : string) : bool = String.for_all (fun c -> c = '\000') h

(* mint a token for [grantee_hash], bounded as a subset of the caller's
   authenticated cap (§6.2 subset-validation), returning the grant result. *)
let mint_bounded (t : t) ~(caller_cap : Model.entity option) ~(req_grants : Cbor.t list)
    ?(req_ttl_ms : int64 option) ~(grantee_hash : string) ?parent () : outcome =
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
    (* §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE
       and convert the duration terms against that same instant.

       This is NOT an authorization decision: an over-long ttl_ms from a bounded
       caller MINTS a clamped token and returns 200 — "rejecting it is
       non-conformant" (§5.6). The bound exists because [request] mints a ROOT
       token (parent: null), so §5.6's parent-child attenuation never reaches it;
       without the clamp, temporal attenuation is the one dimension a requester
       could escape and policy withdrawal would have no bounded latency. *)
    let created = now_ms () in
    let parent_expiry =
      match parent with
      | None -> None
      | Some ph -> Option.bind (resolve_token t ph) (fun pe -> Model.uint_field pe "expires_at")
    in
    let caller_expiry = Option.bind caller_cap (fun c -> Model.uint_field c "expires_at") in
    let req_expiry = Option.bind req_ttl_ms (fun ttl -> Capability.add_ttl created ttl) in
    let expires_at = Capability.min_defined [ parent_expiry; caller_expiry; req_expiry ] in
    let token, sgn = mint_token t ~grantee_hash ?parent ~created_at:created ?expires_at ~grants:req_grants () in
    let grant_result =
      Model.make ~typ:"system/capability/grant" (Cbor.Map [ (Cbor.Text "token", Cbor.Bytes token.hash) ])
    in
    ok grant_result
      ~included:[ (token.hash, token); (t.identity.identity_hash, t.identity.peer_entity); (sgn.hash, sgn) ]
  end

let req_grants_of params =
  match Option.bind params (fun p -> Model.field p "grants") with Some (Cbor.Array l) -> l | _ -> []

(* §5.6: request.ttl_ms is a DURATION term. Absent => no term. A present but
   non-uint value is likewise no term (and the frame carrying it is rejected at
   decode by §6.3 long before here). *)
let req_ttl_of (params : Model.entity option) : int64 option =
  Option.bind params (fun p -> Model.uint_field p "ttl_ms")

let capability_handler (t : t) (exec : Model.entity) ~(caller_cap : Model.entity option) : outcome =
  let op = Option.value ~default:"" (Model.text_field exec "operation") in
  let params = entity_field exec "params" in
  let author = Model.bytes_field exec "author" in
  match op with
  | "request" -> (
      match author with
      | None -> err 403 "capability_denied"
      | Some grantee_hash ->
          mint_bounded t ~caller_cap ~req_grants:(req_grants_of params)
            ?req_ttl_ms:(req_ttl_of params) ~grantee_hash ())
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
                mint_bounded t ~caller_cap ~req_grants:(req_grants_of params)
                  ?req_ttl_ms:(req_ttl_of params) ~grantee_hash ~parent:ph ()))
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

(* §6.2: user-installed handlers MUST NOT register at system/* paths. *)
let is_reserved_system_pattern (pattern : string) : bool =
  String.equal pattern "system" || Capability.starts_with ~prefix:"system/" pattern

(* register (§6.2 / §6.13(a)): the five normative writes. A 501 stub is non-conformant. *)
let register (t : t) (exec : Model.entity) : outcome =
  match register_pattern exec with
  | Error e -> e
  | Ok pattern when is_reserved_system_pattern pattern ->
      err 403 "forbidden_pattern"
        (* ASCII-ONLY IN A WIRE-VISIBLE STRING (AGENTS.md, ratified on two
           independent crashes). A "§" in an error `message` is CBOR-text-encoded
           and sent; Oz's compiled string constant was corrupted by one and Io's
           own UTF-8 validator rejected byte-correct UTF-8, killing the process
           and cascading 104 FAILs. The citation stays, spelled "section", and
           "§" stays in comments, which are never encoded. *)
        ~message:("section 6.2: user-installed handlers MUST NOT register at system/* paths: " ^ pattern)
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

(* Scoped to HANDLER-DISCOVERABLE signatures. The EXECUTE's own request signature — the one
   whose `target` is the root EXECUTE's content hash — is consumed inline by verify_request and
   is never looked up after dispatch, so binding one per request grows this peer's in-memory
   store by a unique entity PER REQUEST. Third occurrence of the class in this cohort (Io
   A-IO-022, Rexx A-RX-014; the rule is in AGENTS.md).

   HERE IT IS A CORRECTNESS DEFECT AND NOT ONLY GROWTH, which is why the scoping is load-bearing
   rather than tidiness. `Store` is a plain `Hashtbl` with no mutex and `transport.ml` spawns a
   thread per inbound EXECUTE. OCaml 5.2.1's `Hashtbl.resize` assigns the new, EMPTY bucket array
   into `h.data` BEFORE repopulating it (verified in the pinned toolchain, not inferred from
   another version), and `insert_all_buckets`' first act is another large allocation — a poll
   point, i.e. a preemption opportunity at the instant the table reads as empty. A concurrent
   `find_opt` in that window misses a key that is present, and a `tree get` answers 404. Unscoped
   ingestion is what drove the table across those thresholds: t2_1 alone inserts 10 000 unique
   keys. Measured: 2 of 40 `--profile core` runs failed concurrency/t2_1_sustained_load before
   this change.

   Cap / identity / handshake signatures are still ingested — they are reused, so their insertion
   is idempotent and does not track request volume. Signatures that are legitimately PUBLISHED
   still arrive via tree.put. *)
let ingest_signatures (t : t) (env : Model.envelope) : unit =
  let exec_hash = env.Model.root.Model.hash in
  List.iter
    (fun (_, e) ->
      (* target == the root EXECUTE hash ⇒ the transient per-request signature *)
      let transient_request_sig =
        match Model.bytes_field e "target" with
        | Some target -> String.equal target exec_hash
        | None -> false
      in
      if String.equal e.Model.typ "system/signature" && not transient_request_sig then begin
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
let dispatch_outbound_handler (t : t) (conn : conn) (exec : Model.entity)
    ~(handler_pattern : string) ~(included : (string * Model.entity) list) : outcome =
  match entity_field exec "params" with
  | None -> err 400 "invalid_params" ~message:"dispatch-outbound requires a params entity"
  | Some p -> (
      let target = Option.value ~default:"" (Model.text_field p "target") in
      let operation = Option.value ~default:"" (Model.text_field p "operation") in
      (* GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
         single-granter case is an array of ONE. They were singular, which made §1.4's
         multi-signature-root rule ungateable on the wire: driving it needs two granter
         identities and two signatures, and a single-credential carrier cannot express
         that input.

         TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
         because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is
         what all 46 tracked reports are measured against and it sends the SINGULAR
         names; a plural-only peer reads the triple as absent there, takes the ambient
         arm and refuses -- measured on the [go] vanguard as 2 of 778 severities moving
         PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at BOTH check sets.
         REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before: the exit condition
         is that tools/oracle-pin.env's [ref] names an oracle whose dispatch-outbound
         probe sends the plural carriers. *)
      let entity_list key =
        match Model.field p key with
        | Some (Cbor.Array l) -> (
            (* An array whose members do not all decode is a MALFORMED carrier and is
               [None], never a silently shorter list -- the all-or-none test below
               would otherwise read a partial credential as a complete one. *)
            try Some (List.map Model.of_cbor l) with _ -> None)
        | _ -> None
      in
      let capability = entity_field p "reentry_capability" in
      let granter_peers =
        match entity_list "reentry_granters" with
        | Some gs -> Some gs
        | None -> Option.map (fun g -> [ g ]) (entity_field p "reentry_granter")
      in
      let cap_signatures =
        match entity_list "reentry_cap_signatures" with
        | Some ss -> Some ss
        | None -> Option.map (fun s -> [ s ]) (entity_field p "reentry_cap_signature")
      in
      (* The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm,
         all three absent selects the AMBIENT arm, and a PARTIAL set is 400
         invalid_params -- a partial credential is malformed, not ambient. An empty
         array is partial, not present: it carries no credential. *)
      let non_empty = function Some (_ :: _) -> true | _ -> false in
      let n_present =
        List.length (List.filter (fun b -> b)
          [ capability <> None; non_empty granter_peers; non_empty cap_signatures ])
      in
      match Model.field p "value" with
      | None -> err 400 "invalid_params" ~message:"dispatch-outbound requires value"
      | Some value when n_present <> 0 && n_present <> 3 ->
          ignore value;
          err 400 "invalid_params" ~message:"dispatch-outbound reentry authority is all-or-none"
      | Some value -> (
          let has_cred = n_present = 3 in
          let granter_peers = if has_cred then Option.value ~default:[] granter_peers else [] in
          let cap_signatures = if has_cred then Option.value ~default:[] cap_signatures else [] in
          let cred = if has_cred then capability else None in
          (* §7a.1: the [value] field IS the outbound params entity data — pass it
             through (the reference uses it directly). Re-wrapping as {value: value}
             double-wraps, so the echo's result.value returns a map (keystone §7b t1_2). *)
          let inner = Model.make ~typ:"primitive/any" value in
          (* [target] arrives as any of §1.4's three spellings and the validator sends
             the SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the
             resource target want the PEER-RELATIVE path — §1.4's PD-2 block says so
             for Dimension 1, and a resource target carrying a scheme is not a path at
             all. Latent while nothing consulted it. *)
          let rel_target = Capability.peer_relative_of target in
          let resource =
            Cbor.Map [ (Cbor.Text "targets", Cbor.Array [ Cbor.Text ("system/handler/" ^ rel_target) ]) ]
          in
          (* §7a.2a: the presented arm verifies against a BUNDLE MERGED FROM THE PARENT
             ENVELOPE'S [included]. The credential, its granters and its signatures
             arrive NESTED IN PARAMS (ratified shape (a), in-band), so they are not in
             the parent's included and a verifier handed that alone cannot resolve a
             single link — every credential then reads as invalid and the legitimate
             reentry is refused. *)
          let bundle =
            (if has_cred then
               List.map (fun (e : Model.entity) -> (e.Model.hash, e))
                 (Option.to_list capability @ granter_peers @ cap_signatures)
             else [])
            @ included
          in
          (* §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends
             the absolute form, so the URI names the target. Where the uri is
             PEER-RELATIVE there is no peer in it and the §6.11 seam's destination is
             the connection's remote, so that is the fallback — without it Dimension 4
             passes vacuously. *)
          let uri_peer = Capability.extract_peer ~local_peer:t.local_peer target in
          let target_peer =
            if String.equal uri_peer t.local_peer then
              Option.value ~default:uri_peer conn.hello_peer_id
            else uri_peer
          in
          (* §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer,
             all four dimensions, on THIS handler's own grant — with a target-minted
             credential relaxing Dimension 4 and nothing else. Consulting only the
             presented credential here is the §6.8 confused-deputy bypass. *)
          match Store.get_at t.store ~path:(Capability.grant_path_for ~local_peer:t.local_peer handler_pattern) with
          (* §6.8: a handler with no valid grant does not run. Fail closed rather than
             falling back to the credential, which is the substitution §6.8 forbids. *)
          | None -> err 403 "capability_denied" ~message:("no handler grant for " ^ handler_pattern)
          | Some own_grant ->
              if not (Capability.check_outbound_sub_dispatch ~local_peer:t.local_peer ~target_peer
                        ~handler_pattern:rel_target ~operation ~store:t.store ~handler_grant:own_grant
                        ~resource ~cred bundle)
              then
                (* §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A
                   generic transport- or gateway-class code would launder an
                   authorization verdict into a route fault, and the ambient and
                   presented branches would then disagree about what the same gate
                   decided. *)
                err 403 "capability_denied"
                  ~message:"outbound sub-dispatch not authorized by the handler grant"
              else
                match
                  outbound_dispatch t conn ~uri:target ~operation ~params:inner ~resource
                    ~capability:cred ~granter_peers ~capability_signatures:cap_signatures ()
                with
                (* ASCII-only wire message (AGENTS.md) — see the forbidden_pattern arm. *)
                | None -> err 503 "no_outbound_seam" ~message:"no live section 6.11 reentry connection"
                | Some env ->
                    let status = Option.value ~default:0L (Model.uint_field env.Model.root "status") in
                    let result_cbor = Option.value ~default:(Cbor.Map []) (Model.field env.Model.root "result") in
                    ok
                      (Model.make ~typ:"primitive/any"
                         (Cbor.Map [ (Cbor.Text "status", Cbor.Uint status); (Cbor.Text "result", result_cbor) ]))))

(* ── dispatch chain (§6.5) ────────────────────────────────────────────────── *)

(* A 500 response for an envelope whose dispatch raised unexpectedly — keeps the
   connection alive (§3.3 every EXECUTE gets a response) instead of closing it. *)
let internal_error_response (env : Model.envelope) : Model.envelope option =
  let request_id = Option.value ~default:"" (Model.text_field env.root "request_id") in
  Some
    { Model.root = Wire.make_response ~request_id ~status:500 ~result:(Wire.error_result "internal_error");
      included = [] }

(* [dispatch] runs the §6.5 dispatch chain. The [option] is kept for the caller's
   write decision and is now always [Some]: every inbound root reaching here is
   ANSWERED. *)
(* A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward,
   as distinct from any capability a caller presents. §6.8 row 1: an access in service
   of a caller's request needs the caller's verified capability AND this grant, and
   BOTH must pass. Narrow for dispatch-outbound; empty for everything else. *)
let own_grants_for (pattern : string) : Cbor.t list =
  if String.equal pattern "system/validate/dispatch-outbound" then
    [ Cbor.Map
        [ (Cbor.Text "handlers", Cbor.Map [ (Cbor.Text "include", Cbor.Array [ Cbor.Text "system/validate/echo" ]) ]);
          (Cbor.Text "operations", Cbor.Map [ (Cbor.Text "include", Cbor.Array [ Cbor.Text "echo" ]) ]);
          (Cbor.Text "resources", Cbor.Map [ (Cbor.Text "include", Cbor.Array [ Cbor.Text "system/handler/system/validate/echo" ]) ]) ] ]
  else []

let dispatch (t : t) (conn : conn) (env : Model.envelope) : Model.envelope option =
  let exec = env.root in
  if not (String.equal exec.typ "system/protocol/execute") then begin
    (* §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
       invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
       close -- that is indistinguishable from a network fault."

       §3.3 used to read "the connection MUST be closed", assigning no code and
       requiring no frame, and §9.1's floor row MANDATED it; N18 replaced that
       row. This peer did something weaker still: it returned [None], the
       transport wrote NOTHING and the connection stayed open -- §4.11's OTHER
       non-conformant behaviour, the silent drop, "the weaker of the two
       precisely because nothing surfaces it".

       This is a PRE-ADMISSION refusal: the root is not an EXECUTE, so nothing was
       ever admitted and §4.9(c) -- scoped to "every request the peer ADMITS" --
       does not reach it. That is why §4.11 exists.

       [request_id] is read BEST-EFFORT. An arbitrary root type is under no
       obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
       there. We do NOT close: on a multiplexed connection that would cost every
       ADMITTED in-flight request its response, and §4.11 leaves the close to us. *)
    let request_id = Option.value ~default:"" (Model.text_field exec "request_id") in
    Some
      { Model.root =
          Wire.make_response ~request_id ~status:400
            ~result:
              (Wire.error_result "invalid_request"
                 ~message:"root entity is neither EXECUTE nor EXECUTE_RESPONSE");
        included = [] }
  end
  else begin
    let request_id = Option.value ~default:"" (Model.text_field exec "request_id") in
    let uri = Option.value ~default:"" (Model.text_field exec "uri") in
    let outcome =
      try
      if String.equal uri "system/protocol/connect" then
        connect_handler t conn exec ~included:env.included
      else begin
        ingest_signatures t env;
        (* §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used
           to sit inside the Req_allow arm, so a pre-establishment EXECUTE naming a FOREIGN
           namespace took the 401 an unauthenticated request takes. §4.7's own reason: "a
           401 directs the caller to authenticate and retry, and for a foreign-namespace
           address that retry cannot succeed at any authentication state — so the 401 names
           a remedy that does not exist." §6.5 step 3 calls it "a gate, not an ordering
           preference" and §1.4 makes the downstream permission check unreachable here. *)
        let addr_path = Capability.canonicalize ~local_peer:t.local_peer (Capability.normalize_uri uri) in
        if not (String.equal (Capability.extract_peer ~local_peer:t.local_peer addr_path) t.local_peer) then
          err 400 "invalid_request" ~message:"not local peer"
        else
        match Capability.verify_request ~local_peer:t.local_peer ~store:t.store env with
        | exception Capability.Unresolvable_grantee -> err 401 "unresolvable_grantee"
        | Capability.Req_authn_fail -> err 401 "authentication_failed"
        | Capability.Req_authz_deny -> err 403 "capability_denied"
        | Capability.Req_chain_too_deep -> err 400 "chain_depth_exceeded"
        | Capability.Req_allow -> (
            (* The §1.4 address gate that used to sit here has moved ABOVE the verdict —
               §4.7 0.8.2.6 orders it before authentication. Reaching this arm at all now
               means the path is local. *)
            let path = addr_path in
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
                          (* §6.3 needs the caller's capability and the OWNING
                             handler's pattern, and BOTH are CARRIED from here
                             rather than recomputed: the handler-level check MUST
                             run against the same authority the dispatch check
                             resolved, and recomputing invites the two to drift
                             (§6.8 -- the authority is selected by who named the
                             path). [pattern] is the owner's (§6.3, 0.8.2.23); for
                             the tree handler owner and runner coincide, so the
                             distinction is not observable here, but the argument
                             is named for the owner because that is what the
                             parameter means. *)
                          | "system/tree" -> tree_handler t ~caller_cap ~pattern exec
                          | "system/capability" -> capability_handler t exec ~caller_cap
                          | "system/handler" -> handlers_handler t exec
                          | "system/type" -> types_handler t exec
                          (* §7a conformance handlers — only resolvable when bootstrapped
                             under --validate (off by default → resolve_handler 404s). *)
                          | "system/validate/echo" -> echo_handler t exec
                          (* §1.4 PD-2 needs the OWNING handler's peer-relative pattern
                             (Dimension 1 is matched peer-relative) and the parent
                             [included] (the §7a.2a bundle base). Both were computed
                             above, so they are CARRIED rather than recomputed. *)
                          | "system/validate/dispatch-outbound" ->
                              dispatch_outbound_handler t conn exec
                                ~handler_pattern:(strip_local t pattern) ~included:env.Model.included
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
        (* §6.8: the grant MUST exist at system/capability/grants/{pattern} and a
           handler with no valid grant does not run — so this bind is the ceiling row 1
           intersects against, not bookkeeping. An empty grants list is the right
           default for a handler that never dispatches onward and the WRONG one for a
           handler that does, which is why dispatch-outbound gets a NARROW one: with a
           wide grant, consulting it and skipping it give the same answer on every
           input, so the confused-deputy discriminator cannot fire and a bypass reads as
           conformant (GUIDE-CONFORMANCE §7a.1 makes the narrowness a scaffold-contract
           requirement). *)
        let token, _ = mint_token t ~grantee_hash:identity.identity_hash ~grants:(own_grants_for pattern) () in
        Store.bind store ~path:("/" ^ local_peer ^ "/system/capability/grants/" ^ pattern) token)
      [ ("system/validate/echo", "validate-echo", [ ("echo", (None, None)) ]);
        ("system/validate/dispatch-outbound", "validate-dispatch-outbound", [ ("dispatch", (None, None)) ]) ];
  t
