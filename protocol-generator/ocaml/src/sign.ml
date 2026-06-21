(* Ed25519 signing over canonical-ECF bytes (Appendix E `signature` category;
   V7 §1.5 key_type 0x01). RFC 8032 Ed25519 is deterministic, so a fixed 32-byte
   seed + fixed message yields a fixed 64-byte signature — reproducible across
   impls without an RNG. (Ed448 is NOT available in mirage-crypto-ec 2.1.0,
   issue mirage/mirage-crypto#112 — see ambiguity A-OC-002; agility corpus only.) *)

module Ed = Mirage_crypto_ec.Ed25519

let priv_of_seed (seed : string) : Ed.priv =
  match Ed.priv_of_octets seed with
  | Ok p -> p
  | Error _ -> failwith "Sign.priv_of_seed: invalid Ed25519 seed (need 32 bytes)"

let sign ~(seed : string) (msg : string) : string =
  Ed.sign ~key:(priv_of_seed seed) msg

let public_of_seed (seed : string) : string =
  Ed.pub_to_octets (Ed.pub_of_priv (priv_of_seed seed))

let verify ~(pub : string) ~(signature : string) ~(msg : string) : bool =
  match Ed.pub_of_octets pub with
  | Ok key -> Ed.verify ~key signature ~msg
  | Error _ -> false
