(* key_type registry (V7 §1.5). Ed25519 (0x01) is the native floor (Sign, over
   mirage-crypto-ec); Ed448 (0x02) is sourced from libentitycore_codec via the
   C-ABI (Ec_ffi) because the OCaml ecosystem has no conformant native Ed448
   (A-OC-002). 0xFE experimental-test is the corpus pubkey-width stub. Per §1.5
   each algorithm has two surfaces: the wire varint [code] and the entity-data
   [name] string. Reserved 0xFF and any unallocated code are refused — the
   §9.1 floor (Ed25519+SHA-256-only) stays conformant by rejecting the rest. *)
open Entitycore_codec

type algo = Ed25519 | Ed448 | Experimental_test

let code = function Ed25519 -> 0x01 | Ed448 -> 0x02 | Experimental_test -> 0xFE
let name = function
  | Ed25519 -> "ed25519" | Ed448 -> "ed448" | Experimental_test -> "experimental-test"
let reserved = 0xFF

let by_code = function
  | 0x01 -> Ok Ed25519
  | 0x02 -> Ok Ed448
  | 0xFE -> Ok Experimental_test
  | 0xFF -> Error "key_type 255 reserved (V7 §1.5)"
  | n -> Error (Printf.sprintf "unsupported key_type 0x%02x" n)

let by_name = function
  | "ed25519" -> Ok Ed25519
  | "ed448" -> Ok Ed448
  | "experimental-test" -> Ok Experimental_test
  | s -> Error (Printf.sprintf "unknown key_type name %S" s)

(* Public key from the algorithm's RFC 8032 secret seed (32 B Ed25519 / 57 B
   Ed448). experimental-test has no keygen — its corpus "pubkey" is a raw
   literal (0xAA×64), so the seed passes through. *)
let public_key_from_seed algo (seed : string) : (string, string) result =
  match algo with
  | Ed25519 -> Ok (Sign.public_of_seed seed)
  | Ed448 -> Ec_ffi.ed448_seed_to_pubkey seed
  | Experimental_test -> Ok seed

(* Deterministic signature (RFC 8032) over [msg]; [seed] is the secret seed. *)
let sign algo ~seed (msg : string) : (string, string) result =
  match algo with
  | Ed25519 -> Ok (Sign.sign ~seed msg)
  | Ed448 -> Ec_ffi.ed448_sign ~priv:seed msg
  | Experimental_test -> Error "experimental-test: no signing"

let verify algo ~pub ~signature ~msg : bool =
  match algo with
  | Ed25519 -> Sign.verify ~pub ~signature ~msg
  | Ed448 -> Ec_ffi.ed448_verify pub msg signature
  | Experimental_test -> false
