(* Wire framing (§1.6) and the two message builders (§3.2 EXECUTE, §3.3
   EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR payload]. The payload is a
   CBOR-encoded system/protocol/envelope (§3.1). *)

let max_frame = 16 * 1024 * 1024   (* §1.6 SHOULD bound — 16 MiB *)

(* ── fd read/write of a full frame ────────────────────────────────────────── *)

exception Closed

(* [Frame_too_large] — the length prefix declares more than [max_frame], detected
   BEFORE the body is buffered (§4.10(a)). Since 0.8.2.25 (N14) the 413 MUST be
   EMITTED: §4.10(a)'s "SHOULD ... and otherwise MAY close after a best-effort
   coded frame" became a MUST, because the condition is detected at the prefix with
   the connection intact and nothing spent. Close-without-frame is no longer
   licensed. *)
exception Frame_too_large

(* [Truncated_frame] — the stream ended MID-FRAME: a partial length prefix, or a
   prefix declaring N bytes followed by fewer. §4.11's framing arm names this input
   explicitly ("un-parseable, truncated or non-canonical CBOR, or a length prefix
   that never completes") and answers [400 invalid_request].

   IT IS A SEPARATE VALUE FROM [Closed] BECAUSE THE TWO ARE DIFFERENT EVENTS AND
   [read_exact] COLLAPSED THEM. A clean close at a frame BOUNDARY is an ordinary
   hangup and is owed nothing; a stream that ends mid-frame is a REFUSAL and is
   owed a coded frame. Without the distinction, a prefix declaring 100 bytes
   followed by an immediate close is indistinguishable from an idle disconnect --
   and it can only be made HERE, where the frame boundary is known. *)
exception Truncated_frame

(* [~at_boundary] says whether a zero-byte read at offset 0 is a CLEAN close or a
   truncation. It is true only for the length prefix: once the prefix has been
   consumed the peer has committed to a frame, so a body that never arrives is a
   truncation even if not one byte of it was read.

   Passing it explicitly rather than inferring from [off = 0] is the whole point:
   the inference is right for the prefix and wrong for the body, and getting it
   wrong reports a mid-frame hangup as an ordinary disconnect. *)
let read_exact ?(at_boundary = false) (fd : Unix.file_descr) (n : int) : string =
  let buf = Bytes.create n in
  let rec loop off =
    if off = n then Bytes.unsafe_to_string buf
    else
      let r = Unix.read fd buf off (n - off) in
      if r = 0 then (if at_boundary && off = 0 then raise Closed else raise Truncated_frame)
      else loop (off + r)
  in
  loop 0

let read_frame (fd : Unix.file_descr) : string =
  let hdr = read_exact ~at_boundary:true fd 4 in
  let len =
    (Char.code hdr.[0] lsl 24) lor (Char.code hdr.[1] lsl 16)
    lor (Char.code hdr.[2] lsl 8) lor Char.code hdr.[3]
  in
  if len < 0 || len > max_frame then raise Frame_too_large;
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

(* [pre_admission_refusal exn] maps a pre-admission failure to the (status, code)
   §4.11 (0.8.2.25) assigns its CAUSE. "The frame obligation belongs to the class;
   the CODE belongs to the cause [MUST]" -- a single code for the whole class
   answers an honest caller under the wrong reason and sends them to the wrong
   layer.

     connect-auth proof-of-possession   401 authentication_failed  (§4.6/§4.7 -- the
                                                                    connect handler's,
                                                                    not this function's)
     envelope over the configured max    413 payload_too_large      (§4.10(a), N14)
     resolution integrity (mis-keyed)    400 hash_mismatch          (§5.2a, §1.8)
     framing / never becomes an Envelope 400 invalid_request        (§4.7, §4.11)
     root neither EXECUTE nor
       EXECUTE_RESPONSE                  400 invalid_request        (§3.3, §4.11 -- in
                                                                    dispatch, not here)

   The CBOR tag-policy arm keeps [non_canonical_ecf] and that is deliberate. §4.11
   rules the code non-conformant "on the framing arm" and gives its reason in the
   same sentence: ENTITY-CBOR-ENCODING §5.4 "defines that code for CBOR tag-policy
   violations specifically", which that document still MUSTs at decode time. The
   two texts are compatible only if the tag case is not read as part of the framing
   arm, even though §4.11's row says "non-canonical CBOR" and a tagged frame is
   literally that. Reported as an ambiguity rather than resolved here; this branch
   takes the reading that keeps BOTH MUSTs satisfiable and preserves the behaviour
   the tag_reject vectors were written against. *)
let pre_admission_refusal (e : exn) : int * string =
  match e with
  | Frame_too_large -> (413, "payload_too_large")
  | Model.Hash_mismatch _ -> (400, "hash_mismatch")
  | Cbor.Tag_rejected -> (400, "non_canonical_ecf")
  | _ -> (400, "invalid_request")

(* [is_framing_refusal exn] reports whether a [read_frame] failure is a REFUSAL
   owed a coded frame (§4.11) rather than an ordinary end of connection. A closed
   or reset socket is not a refusal of anything and there is nobody left to
   answer. *)
let is_framing_refusal (e : exn) : bool =
  match e with Frame_too_large | Truncated_frame -> true | _ -> false

(* [salvage_request_id payload] recovers ONLY the [request_id] from a frame the
   strict decoder rejected, so the rejection can be delivered as a CORRELATED
   response rather than as the uncorrelated best-effort frame §4.11 falls back to.

   The frame stays rejected. Nothing else is read out of it: no entity is built,
   nothing is stored, and the offending tag is discarded rather than interpreted.
   The envelope and entity-wrapper shapes are fixed maps with no legal tag
   position (§6.3), so a frame whose only defect is a tag inside some entity's
   [data] still has a structurally sound root — which is exactly the case this
   recovers. Returns [None] when even the request_id is unreachable; the caller
   then emits the UNCORRELATED best-effort frame §4.11 prescribes, NOT silence. *)
let salvage_request_id (payload : string) : string option =
  match Cbor.decode ~keep_tags:true payload with
  | exception _ -> None
  | c -> (
      match Model.map_get c "root" with
      | Some r -> (
          match Model.map_get r "data" with
          | Some d -> (
              match Model.map_get d "request_id" with
              | Some (Cbor.Text rid) -> Some rid
              | _ -> None)
          | None -> None)
      | None -> None)

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

(* [capability] is OPTIONAL because §1.4's PD-2 AMBIENT arm carries no credential at
   all: the sub-dispatch is authorized by the executing handler's own grant and there
   is nothing to name. An empty string would NOT do — that is a present field holding
   a hash that resolves to nothing, which §5.2 reads as an unresolvable capability
   rather than as its absence. *)
let make_execute ~(request_id : string) ~(uri : string) ~(operation : string)
    ~(params : Model.entity) ?(resource : Cbor.t option) ~(author : string) ?(capability : string option) () : Model.entity =
  Model.make ~typ:"system/protocol/execute"
    (Cbor.Map
       ([ (Cbor.Text "request_id", Cbor.Text request_id);
          (Cbor.Text "uri", Cbor.Text uri);
          (Cbor.Text "operation", Cbor.Text operation);
          (Cbor.Text "params", Model.to_cbor params);
          (Cbor.Text "author", Cbor.Bytes author) ]
        @ (match capability with Some c -> [ (Cbor.Text "capability", Cbor.Bytes c) ] | None -> [])
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
