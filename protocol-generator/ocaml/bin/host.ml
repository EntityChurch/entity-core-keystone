(* Standalone peer host — the runnable target for S4 conformance. Boots one
   Peer listener on a TCP port and blocks until signalled, so the entity-core-go
   `validate-peer` oracle can drive the live wire surface against it. Twin of the
   C# `EntityCore.Protocol.Host` and the TS `host.ts`.

     --port N               listen port (default 7777; 0 = auto-assign)
     --debug-open-grants    mint a wide-open admin capability on authenticate
                            instead of the §4.4 restricted standard grant, so
                            the validator can reach grant-gated paths.
     --validate             conformance build (GUIDE-CONFORMANCE §7a): register the
                            system/validate/* test-handlers (echo + dispatch-outbound)
                            so a black-box validator can drive the §6.13(a)/(b) hooks.
                            NOT core protocol; OFF by default (dispatch-outbound is an
                            outbound originator that must never ship live in production).
     --name NAME            load a persistent Ed25519 identity from the standard
                            on-disk location ~/.entity/peers/NAME/keypair (the
                            entity-core PEM keypair: a base64-encoded 32-byte seed
                            between BEGIN/END ENTITY PRIVATE KEY lines — the same
                            convention the Go entity-peer --name and peer-manager use).
                            Without --name a fixed test seed is used (stable peer_id).

   Binds loopback; run validate-peer in the same network namespace. A single
   `LISTENING …` line on stdout signals readiness. *)

open Entitycore_codec

(* Fixed 32-byte Ed25519 seed → stable peer identity across runs (no --name). *)
let default_seed = String.make 32 '\x11'

(* Decode standard-alphabet base64, ignoring whitespace and padding. *)
let b64_decode (s : string) : string =
  let tbl c =
    if c >= 'A' && c <= 'Z' then Char.code c - 65
    else if c >= 'a' && c <= 'z' then Char.code c - 71
    else if c >= '0' && c <= '9' then Char.code c + 4
    else if c = '+' then 62
    else if c = '/' then 63
    else -1
  in
  let buf = Buffer.create (String.length s) and acc = ref 0 and bits = ref 0 in
  String.iter
    (fun c ->
      let v = tbl c in
      if v >= 0 then begin
        acc := (!acc lsl 6) lor v;
        bits := !bits + 6;
        if !bits >= 8 then begin
          bits := !bits - 8;
          Buffer.add_char buf (Char.chr ((!acc lsr !bits) land 0xff))
        end
      end)
    s;
  Buffer.contents buf

(* Load the 32-byte Ed25519 seed from the standard on-disk keypair (§ EXTENSION-
   IDENTITY / Go entity-peer --name): ~/.entity/peers/NAME/keypair, a PEM whose
   body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines. *)
let load_seed_from_name (name : string) : string =
  let home = try Sys.getenv "HOME" with Not_found -> "/root" in
  let path =
    List.fold_left Filename.concat home [ ".entity"; "peers"; name; "keypair" ]
  in
  let ic =
    try open_in path
    with Sys_error e -> Printf.eprintf "error: --name %s: %s\n" name e; exit 2
  in
  let lines = ref [] in
  (try while true do lines := input_line ic :: !lines done with End_of_file -> ());
  close_in ic;
  let body =
    String.concat ""
      (List.filter (fun l -> not (String.length l > 0 && l.[0] = '-')) (List.rev !lines))
  in
  let seed = b64_decode (String.trim body) in
  if String.length seed <> 32 then begin
    Printf.eprintf "error: --name %s: expected a 32-byte seed, got %d bytes\n" name
      (String.length seed);
    exit 2
  end;
  seed

let () =
  let port = ref 7777 and open_grants = ref false and validate = ref false in
  let seed = ref default_seed in
  let rec parse = function
    | "--port" :: n :: rest -> port := int_of_string n; parse rest
    | "--name" :: n :: rest -> seed := load_seed_from_name n; parse rest
    | "--debug-open-grants" :: rest ->
        open_grants := true;
        Printf.eprintf
          "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — it now selects the degenerate `default -> *` seed policy. Prefer --seed-policy.\n%!";
        parse rest
    | "--validate" :: rest -> validate := true; parse rest
    | ("-h" | "--help") :: _ ->
        print_string "usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]\n"; exit 0
    | [] -> ()
    | arg :: _ -> Printf.eprintf "error: unknown argument '%s'\n" arg; exit 2
  in
  parse (List.tl (Array.to_list Sys.argv));
  let peer = Peer.create ~seed:!seed ~open_grants:!open_grants ~conformance:!validate () in
  let sock, bound = Transport.listen ~port:!port in
  Printf.printf "LISTENING 127.0.0.1:%d peer_id=%s open_grants=%b validate=%b\n%!"
    bound peer.Peer.local_peer !open_grants !validate;
  Transport.accept_loop peer sock
