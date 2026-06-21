(* OCaml view of the entity-codec C-ABI Ed448 + SHA-384 surface (C-ABI v1.1).
   The native peer is result-typed (no exceptions across the API boundary), so
   the raw [external]s — which raise [Failure] from the C stub on a non-EC_OK
   return — are wrapped into [result] here. Ed448 is the only primitive the
   OCaml ecosystem cannot supply natively (A-OC-002); SHA-384 is also bound so
   the harness can cross-check the FFI digest against the native digestif one. *)

external ed448_seed_to_pubkey_exn : string -> string = "caml_ec_ed448_seed_to_pubkey"
external ed448_sign_exn : string -> string -> string = "caml_ec_ed448_sign"
external ed448_verify : string -> string -> string -> bool = "caml_ec_ed448_verify"
external sha384_exn : string -> string = "caml_ec_sha384"
external abi_version : unit -> string = "caml_ec_abi_version"
external impl_info : unit -> string = "caml_ec_impl_info"

let guard f x = try Ok (f x) with Failure m -> Error m

(* seed: 57 bytes (RFC 8032 Ed448 secret seed, no pre-expansion). *)
let ed448_seed_to_pubkey (seed : string) : (string, string) result =
  guard ed448_seed_to_pubkey_exn seed

(* priv = the 57-byte seed; signs deterministically (RFC 8032). *)
let ed448_sign ~(priv : string) (msg : string) : (string, string) result =
  guard (ed448_sign_exn priv) msg

let sha384 (data : string) : (string, string) result = guard sha384_exn data
