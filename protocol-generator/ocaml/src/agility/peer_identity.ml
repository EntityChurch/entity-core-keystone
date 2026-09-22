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

(* The ECFv1-SHA-256 floor — the §9.1 conformance floor, and the format the
   system/peer identity entity is pinned to unconditionally (§4.5a item 1a). *)
let peer_identity_floor_format = 0x00

(* system/peer {key_type (name), public_key} entity, content-hashed under the
   given home content_hash_format. Data-map field order key_type then public_key
   is the ECF length-then-lexicographic order — the encoder sorts.

   §4.5a item 1a — REFUSES a non-floor home. The identity entity is authored
   under ECFv1-SHA-256 (0x00) unconditionally: on every connection, whatever the
   active format, and whatever the peer's home format. Its data is wholly
   recoverable from the public peer-id, so every consumer DERIVES its hash rather
   than fetching it; a system/peer under any other format is not a form to be
   preserved but a construction that cannot exist.

   This is result-typed rather than raising because the module's convention is
   result-typed (Key_types.of_code, Hash_formats.of_code), and because the
   refusal is the point: `~home` stays in the signature so the caller must still
   state which format it is authoring under, and gets an Error instead of a
   plausible 49-byte digest. Returning the floor hash regardless would be worse
   than refusing — it would silently ignore what the caller asked for.

   The `hash-format-sha-384.2` agility vector requires the refusal to be observed
   HERE. It used to assert the opposite (that the SHA-384 rehash succeeds) and
   stayed green only because the verifier hand-built the entity instead of
   routing through the code that forbids it — a fixture that exercises a
   forbidden construction and passes by bypassing the guard certifies the
   opposite of the rule (GUIDE-CONFORMANCE §2.4a). *)
let build_peer (algo : Key_types.algo) (public_key : string)
    ~(home : Hash_formats.fmt) : (string, string) result =
  let code = Hash_formats.code home in
  if code <> peer_identity_floor_format then
    Error
      (Printf.sprintf
         "system/peer is pinned to the ECFv1-SHA-256 floor (V7 §4.5a item 1a); \
          refusing to author it under content_hash_format %d"
         code)
  else
    let data =
      Cbor.Map
        [ (Cbor.Text "key_type", Cbor.Text (Key_types.name algo));
          (Cbor.Text "public_key", Cbor.Bytes public_key) ]
    in
    Ok (Hash.content_hash ~format_code:code ~typ:"system/peer" ~data ())
