(* entity-core-protocol-ocaml — crypto-agility byte-verification harness
   (v7.67 corpus, vendored protocol-generator/shared/test-vectors/v0.8.0/
   agility-vectors-v1).

   Derives every value from the pinned seeds through the hybrid agility seam —
   Ed25519 + SHA-256 + SHA-384 native (Entitycore_codec / digestif), Ed448
   (key_type 0x02) from libentitycore_codec over the C-ABI (Entitycore_agility.
   Ec_ffi) — and asserts byte-equality against the .diag / SEEDS.md ground truth.
   Per S5/S7: byte-identical or the generated code is wrong (S8 the peer must be
   byte-equal to the Go/Rust/Py/C#/TS cohort). Pins are transcribed from
   agility-vectors-v1.diag (the spec-derived source of truth). *)

open Entitycore_codec
open Entitycore_agility

let pass = ref 0
let fail = ref 0

let check name expected actual =
  if String.equal expected actual then begin
    Printf.printf "  [PASS] %s\n" name;
    incr pass
  end else begin
    Printf.printf "  [FAIL] %s\n        expected %s\n        actual   %s\n"
      name expected actual;
    incr fail
  end

let check_bool name ok =
  if ok then (Printf.printf "  [PASS] %s\n" name; incr pass)
  else (Printf.printf "  [FAIL] %s\n" name; incr fail)

(* A reject probe: the registry lookup MUST return Error. *)
let check_rejects name = function
  | Error _ -> Printf.printf "  [PASS] %s\n" name; incr pass
  | Ok _ -> Printf.printf "  [FAIL] %s (accepted)\n" name; incr fail

let ok = function Ok x -> x | Error e -> failwith e
let seed b n = String.make n (Char.chr b)
let hex = Model.hex

let () =
  Printf.printf
    "entity-core-protocol-ocaml — crypto-agility byte verification (v7.67 corpus)\n";
  Printf.printf "  C-ABI %s / %s\n\n" (Ec_ffi.abi_version ()) (Ec_ffi.impl_info ());

  (* ── Phase 1: KEY-TYPE-ED448-1 (Ed448 via FFI / SHA-256-form) ───────────── *)
  Printf.printf "KEY-TYPE-ED448-1 (Ed448 via C-ABI / SHA-256-form):\n";
  let ed448_seed = seed 0x42 57 in
  let ed448_pub = ok (Key_types.public_key_from_seed Ed448 ed448_seed) in
  check "public_key (57B)"
    "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00"
    (hex ed448_pub);
  check "peer_id (SHA-256-form, key_type=0x02 hash_type=0x01)"
    "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4"
    (Peer_identity.derive_peer_id Ed448 ed448_pub);
  check "system/peer content_hash (SHA-256 home)"
    "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748"
    (hex (Peer_identity.build_peer Ed448 ed448_pub ~home:Sha256));
  let fixture_msg = "v7.67 Phase 1 cohort cross-impl Ed448 fixture" in
  let ed448_sig = ok (Key_types.sign Ed448 ~seed:ed448_seed fixture_msg) in
  check "Ed448 signature (114B, RFC 8032 deterministic)"
    "0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400"
    (hex ed448_sig);
  check_bool "Ed448 sign→verify round-trip"
    (Key_types.verify Ed448 ~pub:ed448_pub ~signature:ed448_sig ~msg:fixture_msg);

  (* ── Phase 1: HASH-FORMAT-SHA-384-1 (experimental-test 0xFE, 0xAA×64) ───── *)
  Printf.printf "\nHASH-FORMAT-SHA-384-1 (experimental-test 0xFE, 0xAA×64):\n";
  let exp_pub = seed 0xAA 64 in
  check "content_hash under SHA-256 (0x00)"
    "003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45"
    (hex (Peer_identity.build_peer Experimental_test exp_pub ~home:Sha256));
  check "content_hash under SHA-384 (0x01)"
    "012e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01c059c1ed5775824bcffc50df0f3eef5a69"
    (hex (Peer_identity.build_peer Experimental_test exp_pub ~home:Sha384));
  (* Differential: the FFI ec_sha384 must agree byte-for-byte with the native
     digestif SHA-384 used by the live hashing path. Proves the C-ABI digest is
     interchangeable with the native one (the agility hashing path is native;
     this guards the seam itself). *)
  let ecf = Hash.ecf_of_entity ~typ:"system/peer"
      ~data:(Cbor.Map [ (Cbor.Text "key_type", Cbor.Text "experimental-test");
                        (Cbor.Text "public_key", Cbor.Bytes exp_pub) ]) in
  check "FFI ec_sha384 == native digestif sha384 (differential)"
    (hex (Hash.sha384 ecf)) (hex (ok (Ec_ffi.sha384 ecf)));

  (* ── Phase 2: matrix peer identities (M2 / M3 / M6, peers A & B) ────────── *)
  (* peer_id is home-format-independent; content_hash tracks the home format. *)
  let matrix : (string * Key_types.algo * int * int * Hash_formats.fmt * string * string) list =
    [ ("M2.A ed448/sha256",  Ed448,   0x42, 57, Sha256, "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4", "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748");
      ("M2.B ed25519/sha256", Ed25519, 0x43, 32, Sha256, "2K68ekpdm3sTCUfTs39tpNxowivTsXpRsukodvtqwZmudX", "00f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b");
      ("M3.A ed25519/sha384", Ed25519, 0x44, 32, Sha384, "2KJGifeh6LynPNnmyQqHrugjm7iW8YPQ4VpWSGgYvHp2VM", "0166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c59");
      ("M3.B ed25519/sha256", Ed25519, 0x45, 32, Sha256, "2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5", "00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040");
      ("M6.A ed448/sha384",  Ed448,   0x46, 57, Sha384, "3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD", "01ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd");
      ("M6.B ed25519/sha256", Ed25519, 0x47, 32, Sha256, "2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye", "0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335") ]
  in
  Printf.printf "\nMATRIX peer identities (peer_id + home-format content_hash):\n";
  List.iter
    (fun (label, algo, b, n, home, peer_id, ch) ->
      let pub = ok (Key_types.public_key_from_seed algo (seed b n)) in
      check (label ^ " peer_id") peer_id (Peer_identity.derive_peer_id algo pub);
      check (label ^ " content_hash") ch (hex (Peer_identity.build_peer algo pub ~home)))
    matrix;

  (* ── Reject paths (VARINT / FORMAT-CODE probes) ────────────────────────── *)
  Printf.printf "\nReject paths (agility probes):\n";
  check_rejects "key_type 255 reserved (VARINT-RESERVED-FF-1.key_type)"
    (Key_types.by_code Key_types.reserved);
  check_rejects "content_hash_format 255 reserved (VARINT-RESERVED-FF-1.format)"
    (Hash_formats.by_code Hash_formats.reserved);
  check_rejects "unallocated format-code 0x42 (FORMAT-CODE-INTERPRETATION-1)"
    (Hash_formats.by_code 0x42);
  check_rejects "unknown key_type name" (Key_types.by_name "blake-fake");
  (* VARINT-MULTIBYTE-1: 0x80 0x01 decodes to 128 (multi-byte LEB128), which is
     not a supported format → unsupported (the decoder exists; the error fires
     from interpretation, not a single-byte short-circuit). *)
  let code = Hash_formats.read_format_code "\x80\x01" in
  check_bool "VARINT-MULTIBYTE-1 (0x80 0x01 → 128, unsupported)"
    (code = 128 && not (Hash_formats.is_supported code));

  Printf.printf "\n# RESULT: %s (%d/%d)\n"
    (if !fail = 0 then "PASS" else "FAIL") !pass (!pass + !fail);
  exit (if !fail = 0 then 0 else 1)
