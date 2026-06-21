(* Wire framing (§1.6) and the two message builders (§3.2 EXECUTE, §3.3
   EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]. The payload is a
   CBOR-encoded system/protocol/envelope (§3.1). *)

let max_frame = 16 * 1024 * 1024   (* §1.6 SHOULD bound — 16 MiB *)

(* ── fd read/write of a full frame ────────────────────────────────────────── *)

exception Closed

let read_exact (fd : Unix.file_descr) (n : int) : string =
  let buf = Bytes.create n in
  let rec loop off =
    if off = n then Bytes.unsafe_to_string buf
    else
      let r = Unix.read fd buf off (n - off) in
      if r = 0 then raise Closed else loop (off + r)
  in
  loop 0

let read_frame (fd : Unix.file_descr) : string =
  let hdr = read_exact fd 4 in
  let len =
    (Char.code hdr.[0] lsl 24) lor (Char.code hdr.[1] lsl 16)
    lor (Char.code hdr.[2] lsl 8) lor Char.code hdr.[3]
  in
  if len < 0 || len > max_frame then raise (Failure "frame too large");
  read_exact fd len

let write_frame (fd : Unix.file_descr) (payload : string) : unit =
  let len = String.length payload in
  let hdr = Bytes.create 4 in
  Bytes.set hdr 0 (Char.chr ((len lsr 24) land 0xff));
  Bytes.set hdr 1 (Char.chr ((len lsr 16) land 0xff));
  Bytes.set hdr 2 (Char.chr ((len lsr 8) land 0xff));
  Bytes.set hdr 3 (Char.chr (len land 0xff));
  let full = Bytes.to_string hdr ^ payload in
  let total = String.length full in
  let rec loop off =
    if off < total then
      let w = Unix.write_substring fd full off (total - off) in
      loop (off + w)
  in
  loop 0

(* ── envelope <-> frame ───────────────────────────────────────────────────── *)

let envelope_of_frame (payload : string) : Model.envelope =
  Model.envelope_of_cbor (Cbor.decode payload)

let frame_of_envelope (env : Model.envelope) : string =
  Cbor.encode (Model.envelope_to_cbor env)

(* ── EXECUTE_RESPONSE builder (§3.3) ──────────────────────────────────────── *)

let make_response ~(request_id : string) ~(status : int) ~(result : Model.entity) : Model.entity =
  Model.make ~typ:"system/protocol/execute/response"
    (Cbor.Map
       [ (Cbor.Text "request_id", Cbor.Text request_id);
         (Cbor.Text "status", Cbor.Uint (Int64.of_int status));
         (Cbor.Text "result", Model.to_cbor result) ])

(* ── EXECUTE builder (§3.2) — used by the §6.13(b) handler outbound seam ──── *)

let make_execute ~(request_id : string) ~(uri : string) ~(operation : string)
    ~(params : Model.entity) ?(resource : Cbor.t option) ~(author : string) ~(capability : string) () : Model.entity =
  Model.make ~typ:"system/protocol/execute"
    (Cbor.Map
       ([ (Cbor.Text "request_id", Cbor.Text request_id);
          (Cbor.Text "uri", Cbor.Text uri);
          (Cbor.Text "operation", Cbor.Text operation);
          (Cbor.Text "params", Model.to_cbor params);
          (Cbor.Text "author", Cbor.Bytes author);
          (Cbor.Text "capability", Cbor.Bytes capability) ]
        @ (match resource with Some r -> [ (Cbor.Text "resource", r) ] | None -> [])))

(* system/protocol/error result entity (§3.3). *)
let error_result ?message (code : string) : Model.entity =
  let fields =
    (Cbor.Text "code", Cbor.Text code)
    :: (match message with Some m -> [ (Cbor.Text "message", Cbor.Text m) ] | None -> [])
  in
  Model.make ~typ:"system/protocol/error" (Cbor.Map fields)

(* Empty-params shape (§3.2): primitive/any whose data is the canonical empty map. *)
let empty_params : Model.entity = Model.make ~typ:"primitive/any" (Cbor.Map [])
