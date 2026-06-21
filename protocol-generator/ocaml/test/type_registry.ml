(* A-OC-006 — type-registry byte-diff. Renders all 53 core types (§9.5) from the
   in-code model and diffs each content_hash against the canonical
   type-registry-vectors-v1 (.diag source-of-truth). The peer-side dual of the
   S2 codec corpus: proves the render-from-model output is byte-identical to the
   cross-impl Go-rendered registry. Argv: path to type-registry-vectors-v1.diag. *)

open Entitycore_codec

(* Parse name → expected content_hash hex (64 chars, digest only) from the .diag.
   Lines look like: { "name": "X", "tree_path": "...", "content_hash":
   "ecf-sha256:<64hex>", "data": h'...' }. *)
let parse_diag (path : string) : (string, string) Hashtbl.t =
  let tbl = Hashtbl.create 256 in
  let ic = open_in path in
  (try
     while true do
       let line = input_line ic in
       match
         ( Str.string_match (Str.regexp {|.*"name": "\([^"]*\)".*"content_hash": "ecf-sha256:\([0-9a-f]+\)"|}) line 0 )
       with
       | true -> Hashtbl.replace tbl (Str.matched_group 1 line) (Str.matched_group 2 line)
       | false -> ()
     done
   with End_of_file -> ());
  close_in ic;
  tbl

let () =
  let diag = Sys.argv.(1) in
  let expected = parse_diag diag in
  let pass = ref 0 and fail = ref 0 in
  List.iter
    (fun (name, e) ->
      (* our hash is 33 bytes: format byte 0x00 ‖ 32-byte digest. Compare digest. *)
      let digest_hex = Model.hex (String.sub e.Model.hash 1 (String.length e.Model.hash - 1)) in
      match Hashtbl.find_opt expected name with
      | Some exp when String.equal exp digest_hex -> incr pass
      | Some exp ->
          incr fail;
          Printf.printf "FAIL %s\n  expected %s\n  got      %s\n" name exp digest_hex
      | None ->
          incr fail;
          Printf.printf "FAIL %s — not found in vectors\n" name)
    Type_defs.all;
  Printf.printf "type-registry: %d/%d byte-identical\n" !pass (!pass + !fail);
  if !fail > 0 then exit 1
