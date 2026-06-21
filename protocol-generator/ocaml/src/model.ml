(* Entity model — the materialized {type, data, content_hash} form (V7 §1.1,
   §3.4) and the protocol envelope (§3.1). Sits directly on the S2 codec:
   [content_hash] is [Hash.content_hash] (varint(0x00) ‖ SHA256(ECF{type,data}))
   and entities serialize through [Cbor].

   Spec-first note: an entity's content_hash covers only {type, data} (§1.1);
   the wire form additionally carries [content_hash] as a field so entities are
   self-describing across serialization (§3.1 included-map redundancy). We keep
   the two forms distinct: [hash_of] never sees the content_hash field. *)

type entity = {
  typ : string;
  data : Cbor.t;
  hash : string;        (* 33 bytes: format byte 0x00 ‖ 32-byte SHA-256 digest *)
}

(* Construct a materialized entity, computing its content_hash under the
   ecfv1-sha256 floor (format_code 0). *)
let make ~typ (data : Cbor.t) : entity =
  { typ; data; hash = Hash.content_hash ~typ ~data () }

(* ── CBOR field helpers (data is a Map) ───────────────────────────────────── *)

let map_get (c : Cbor.t) (key : string) : Cbor.t option =
  match c with
  | Cbor.Map kvs ->
      List.find_map
        (fun (k, v) -> match k with Cbor.Text t when String.equal t key -> Some v | _ -> None)
        kvs
  | _ -> None

let field e key = map_get e.data key

let text_field e key =
  match field e key with Some (Cbor.Text s) -> Some s | _ -> None

let bytes_field e key =
  match field e key with Some (Cbor.Bytes s) -> Some s | _ -> None

let uint_field e key =
  match field e key with Some (Cbor.Uint n) -> Some n | _ -> None

(* ── wire form: entity carries its content_hash ───────────────────────────── *)

let to_cbor (e : entity) : Cbor.t =
  Cbor.Map
    [ (Cbor.Text "type", Cbor.Text e.typ);
      (Cbor.Text "data", e.data);
      (Cbor.Text "content_hash", Cbor.Bytes e.hash) ]

(* Parse a wire entity, recomputing the hash from {type,data} and validating it
   against the carried content_hash per entity fidelity (§1.8). Returns the
   recomputed-canonical entity (we trust our hash, not the wire bytes — §5.2
   validate-before-trust). *)
exception Bad_entity of string

let of_cbor (c : Cbor.t) : entity =
  let typ = match map_get c "type" with
    | Some (Cbor.Text s) -> s
    | _ -> raise (Bad_entity "entity: missing/invalid type") in
  let data = match map_get c "data" with
    | Some d -> d
    | None -> raise (Bad_entity "entity: missing data") in
  let e = make ~typ data in
  (match map_get c "content_hash" with
   | Some (Cbor.Bytes h) when not (String.equal h e.hash) ->
       raise (Bad_entity "entity: content_hash mismatch (§1.8 fidelity)")
   | _ -> ());
  e

let hex (s : string) : string =
  let b = Buffer.create (String.length s * 2) in
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents b

(* ── envelope (§3.1) ──────────────────────────────────────────────────────── *)

type envelope = {
  root : entity;
  included : (string * entity) list;   (* key = entity content_hash bytes *)
}

let included_get (env : envelope) (h : string) : entity option =
  List.find_map (fun (k, e) -> if String.equal k h then Some e else None) env.included

let envelope_to_cbor (env : envelope) : Cbor.t =
  let inc =
    List.map (fun (k, e) -> (Cbor.Bytes k, to_cbor e)) env.included in
  Cbor.Map
    [ (Cbor.Text "root", to_cbor env.root);
      (Cbor.Text "included", Cbor.Map inc) ]

let envelope_of_cbor (c : Cbor.t) : envelope =
  let root = match map_get c "root" with
    | Some r -> of_cbor r
    | None -> raise (Bad_entity "envelope: missing root") in
  let included = match map_get c "included" with
    | Some (Cbor.Map kvs) ->
        List.map
          (fun (k, v) ->
            match k with
            | Cbor.Bytes h ->
                let e = of_cbor v in
                (* §3.1: included content_hash MUST match the map key. *)
                if not (String.equal h e.hash) then
                  raise (Bad_entity "envelope: included key != entity content_hash");
                (h, e)
            | _ -> raise (Bad_entity "envelope: included key not a byte string"))
          kvs
    | None -> []
    | Some _ -> raise (Bad_entity "envelope: included not a map") in
  { root; included }
