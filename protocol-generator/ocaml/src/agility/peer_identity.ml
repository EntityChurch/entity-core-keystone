(* peer_id derivation + home-format system/peer construction under crypto
   agility (V7 §1.5). The §1.5 size-cutoff: a public key at or below the
   identity-multihash floor (≤32 bytes — Ed25519) uses hash_type 0x00 with the
   RAW public key as digest; a larger key (Ed448, 57 bytes) uses SHA-256-form,
   hash_type 0x01, digest = SHA256(public_key). (§7.4's NORMATIVE pseudocode
   still shows SHA-256-form for ALL keys, which contradicts §1.5 for Ed25519 —
   A-OC-007; §1.5 is authoritative.) peer_id is home-format-independent; the
   system/peer content_hash tracks the peer's home content_hash_format. *)
open Entitycore_codec

let identity_cutoff = 32

let derive_peer_id (algo : Key_types.algo) (public_key : string) : string =
  let key_type = Key_types.code algo in
  if String.length public_key <= identity_cutoff then
    Peer_id.format { key_type; hash_type = 0x00; digest = public_key }
  else
    Peer_id.format { key_type; hash_type = 0x01; digest = Hash.sha256 public_key }

(* system/peer {key_type (name), public_key} entity, content-hashed under the
   given home content_hash_format (the agility path; the live peer always
   authors under 0x00 SHA-256). Data-map field order key_type then public_key is
   the ECF length-then-lexicographic order — the encoder sorts. *)
let build_peer (algo : Key_types.algo) (public_key : string)
    ~(home : Hash_formats.fmt) : string =
  let data =
    Cbor.Map
      [ (Cbor.Text "key_type", Cbor.Text (Key_types.name algo));
        (Cbor.Text "public_key", Cbor.Bytes public_key) ]
  in
  Hash.content_hash ~format_code:(Hash_formats.code home) ~typ:"system/peer" ~data ()
