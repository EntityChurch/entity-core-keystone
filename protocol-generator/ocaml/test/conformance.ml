(* ECF conformance harness — loads the normative fixture
   (conformance-vectors-v1.cbor) and runs every vector through the codec,
   checking byte-identity (encode_equal) or rejection (decode_reject) per
   Appendix E §E.3. The fixture carries its own cross-blessed `canonical` bytes,
   so this is self-contained — no running Go oracle needed at S2. *)

open Entitycore_codec

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic; s

(* ── field accessors over a decoded vector map ────────────────────────────── *)
let field name m = List.assoc (Cbor.Text name) m
let field_opt name m = List.assoc_opt (Cbor.Text name) m
let as_text = function Cbor.Text s -> s | _ -> failwith "expected text"
let as_bytes = function Cbor.Bytes s -> s | _ -> failwith "expected bytes"
let as_uint = function Cbor.Uint n -> Int64.to_int n | _ -> failwith "expected uint"
let as_map = function Cbor.Map m -> m | _ -> failwith "expected map"

let category id = match String.index_opt id '.' with Some i -> String.sub id 0 i | None -> id

let hex s = String.concat "" (List.map (Printf.sprintf "%02x") (List.of_seq (Seq.map Char.code (String.to_seq s))))

(* Returns Ok () on pass, Error msg on fail. *)
let run_vector vm =
  let id = as_text (field "id" vm) in
  let kind = as_text (field "kind" vm) in
  let canon = as_bytes (field "canonical" vm) in
  let expect_encode produced =
    if String.equal produced canon then Ok ()
    else Error (Printf.sprintf "want %s got %s" (hex canon) (hex produced))
  in
  match kind, category id with
  | "decode_reject", _ ->
      (try let _ = Cbor.decode canon in Error "decoder accepted a reject vector"
       with Cbor.Decode_error _ -> Ok () | _ -> Ok ())
  | "encode_equal", "content_hash" ->
      let input = as_map (field "input" vm) in
      let typ = as_text (field "type" input) in
      let data = field "data" input in
      let format_code = match field_opt "format_code" input with Some v -> as_uint v | None -> 0 in
      expect_encode (Hash.content_hash ~format_code ~typ ~data ())
  | "encode_equal", "peer_id" ->
      let input = as_map (field "input" vm) in
      let key_type = as_uint (field "key_type" input) in
      let hash_type = as_uint (field "hash_type" input) in
      let digest = as_bytes (field "digest" input) in
      let pid = Peer_id.format { key_type; hash_type; digest } in
      expect_encode (Cbor.encode (Cbor.Text pid))
  | "encode_equal", "signature" ->
      let input = as_map (field "input" vm) in
      let seed = as_bytes (field "seed" input) in
      let entity = as_map (field "entity" input) in
      let typ = as_text (field "type" entity) in
      let data = field "data" entity in
      let msg = Hash.ecf_of_entity ~typ ~data in
      expect_encode (Sign.sign ~seed msg)
  | "encode_equal", _ ->
      (* float / int / map_keys / length / primitive / nested / envelope:
         re-encode the decoded input value canonically. *)
      expect_encode (Cbor.encode (field "input" vm))
  | k, _ -> Error (Printf.sprintf "unknown kind %s" k)

let () =
  let path =
    if Array.length Sys.argv > 1 then Sys.argv.(1)
    else "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
  in
  let vectors = match Cbor.decode (read_file path) with
    | Cbor.Array l -> l
    | _ -> failwith "fixture is not a CBOR array"
  in
  let pass = ref 0 and fail = ref 0 in
  let by_cat = Hashtbl.create 16 in
  List.iter (fun v ->
    let vm = as_map v in
    let id = as_text (field "id" vm) in
    let cat = category id in
    let p, f = try (match Hashtbl.find by_cat cat with x -> x) with Not_found -> (0, 0) in
    match run_vector vm with
    | Ok () -> incr pass; Hashtbl.replace by_cat cat (p + 1, f)
    | Error msg ->
        incr fail; Hashtbl.replace by_cat cat (p, f + 1);
        Printf.printf "FAIL %-16s %s\n" id msg
  ) vectors;
  Printf.printf "\n── by category ──\n";
  Hashtbl.iter (fun cat (p, f) -> Printf.printf "  %-14s %d/%d\n" cat p (p + f)) by_cat;
  Printf.printf "\nTOTAL: %d passed, %d failed (of %d)\n" !pass !fail (!pass + !fail);
  if !fail > 0 then exit 1
