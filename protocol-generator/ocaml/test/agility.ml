(* entity-core-protocol-ocaml — crypto-agility byte-verification harness
   (v7.67 corpus, vendored protocol-generator/shared/test-vectors/crypto-agility/
   agility-vectors).

   Derives every value from the pinned seeds through the hybrid agility seam —
   Ed25519 + SHA-256 + SHA-384 native (Entitycore_codec / digestif), Ed448
   (key_type 0x02) from libentitycore_codec over the C-ABI (Entitycore_agility.
   Ec_ffi) — and asserts byte-equality against the .diag / SEEDS.md ground truth.
   Per S5/S7: byte-identical or the generated code is wrong (S8 the peer must be
   byte-equal to the Go/Rust/Py/C#/TS cohort). Pins are transcribed from
   agility-vectors.diag (the spec-derived source of truth). *)

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
  check "content_hash at the ECFv1-SHA-256 floor (0x00) — the only form"
    "003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45"
    (hex (Peer_identity.build_peer Experimental_test exp_pub ~home:Sha256));
  (* The `content_hash under SHA-384 (0x01)` assertion that stood here, pinning
     `012e64bbde…3eef5a69`, is WITHDRAWN — the corpus vector it transcribed
     (`hash-format-sha-384.2`) was INVERTED upstream and now asserts the opposite.
     §4.5a item 1a pins `system/peer` to the floor unconditionally, so there is no
     SHA-384 form of this fixture to pin; the construction MUST be refused.

     Upstream's note on the retirement is the lesson: the old vector "stayed green
     only because the verifier hand-built the entity instead of routing through the
     constructor that would have refused it. A fixture that exercises a forbidden
     construction and passes by bypassing the code that forbids it certifies the
     opposite of the rule" (GUIDE-CONFORMANCE §2.4a). This harness did exactly that.

     OWED, and deliberately not faked here: the NEGATIVE half — asserting that
     `build_peer … ~home:Sha384` is REFUSED. It is not, today: this peer will still
     construct it. Writing the refusal assertion requires changing
     `Peer_identity.build_peer` to reject a non-floor home for `system/peer`, which
     is a peer-behaviour change and not a test edit. Recorded as a gap rather than
     papered over, because a half-implemented rule reads as done. *)
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
  (* peer_id is home-format-independent, and so is the content_hash: `system/peer`
     is the ONE type with no home format. §4.5a item 1a pins the identity entity
     to the ECFv1-SHA-256 floor UNCONDITIONALLY — its data is wholly recoverable
     from the public peer-id, so an entity nobody fetches to learn its hash cannot
     be hold-and-fetch. `~home` is therefore NOT threaded here.

     This list previously carried `Sha384` for M3.A/M6.A and the 49-byte `01…`
     hashes that produces, and it PASSED 25/25 — because the pins were transcribed
     from a superseded corpus and the peer computed the same wrong thing the test
     expected. A transcribed pin makes the harness compare the peer to itself; the
     two peers that LOAD the corpus (elixir, ruby) failed these same two gates the
     moment the stale copy was removed. Floor-form values below are read from
     `crypto-agility/agility-vectors.diag` (`expected_peer_a_content_hash`). *)
  let matrix : (string * Key_types.algo * int * int * string * string) list =
    [ ("M2.A ed448",   Ed448,   0x42, 57, "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4", "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748");
      ("M2.B ed25519", Ed25519, 0x43, 32, "2K68ekpdm3sTCUfTs39tpNxowivTsXpRsukodvtqwZmudX", "00f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b");
      ("M3.A ed25519", Ed25519, 0x44, 32, "2KJGifeh6LynPNnmyQqHrugjm7iW8YPQ4VpWSGgYvHp2VM", "00af37ab940c4fd3f26d85d1e52343ca6a77b7698191553aee815650beaee92d41");
      ("M3.B ed25519", Ed25519, 0x45, 32, "2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5", "00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040");
      ("M6.A ed448",   Ed448,   0x46, 57, "3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD", "00848e208deeb0b0523fe486f49da12b9e530c40d8d2795feb6ce663f5d517058e");
      ("M6.B ed25519", Ed25519, 0x47, 32, "2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye", "0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335") ]
  in
  Printf.printf "\nMATRIX peer identities (peer_id + floor-form content_hash):\n";
  List.iter
    (fun (label, algo, b, n, peer_id, ch) ->
      let pub = ok (Key_types.public_key_from_seed algo (seed b n)) in
      check (label ^ " peer_id") peer_id (Peer_identity.derive_peer_id algo pub);
      check (label ^ " content_hash") ch
        (hex (Peer_identity.build_peer algo pub ~home:Sha256)))
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
