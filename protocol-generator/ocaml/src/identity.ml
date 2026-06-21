(* Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5,
   §7.3, §7.4). The peer's identity is an Ed25519 seed; everything else derives:

     public_key   = Ed25519 pub of seed                       (32 bytes)
     peer_id      = Base58(varint(1) ‖ varint(1) ‖ SHA256(pub))  (§7.4)
     peer entity  = system/peer { public_key, key_type }       (§3.5; v7.65 —
                    NO peer_id in the hashable basis)
     identity_hash = content_hash(peer entity)

   Signing is over the full 33-byte content_hash (format byte + digest, §7.3),
   so a signature is bound to the hash format. *)

type t = {
  seed : string;            (* 32-byte Ed25519 seed *)
  public_key : string;      (* 32 bytes *)
  peer_id : string;         (* Base58 *)
  peer_entity : Model.entity;
  identity_hash : string;   (* content_hash(peer_entity), 33 bytes *)
}

let peer_entity_of_pubkey (public_key : string) : Model.entity =
  Model.make ~typ:"system/peer"
    (Cbor.Map
       [ (Cbor.Text "public_key", Cbor.Bytes public_key);
         (Cbor.Text "key_type", Cbor.Text "ed25519") ])

(* Ed25519 canonical peer_id is identity-multihash form (§1.5 v7.65 table):
   key_type=0x01, hash_type=0x00 (identity), digest = the RAW public_key (≤32 B
   fits below the Base58 floor). NOTE: §7.4's "NORMATIVE" pseudocode still shows
   the pre-v7.65 SHA-256-form (hash_type=0x01, SHA256(public_key)) — that
   contradicts the §1.5 canonical-form table for Ed25519. We follow §1.5 (the
   later, specific contract); the §7.4/§1.5 divergence is logged as A-OC-007. *)
let peer_id_of_pubkey (public_key : string) : string =
  Peer_id.format { key_type = 0x01; hash_type = 0x00; digest = public_key }

let of_seed (seed : string) : t =
  let public_key = Sign.public_of_seed seed in
  let peer_entity = peer_entity_of_pubkey public_key in
  { seed;
    public_key;
    peer_id = peer_id_of_pubkey public_key;
    peer_entity;
    identity_hash = peer_entity.hash }

(* Sign an entity's content_hash; produce the system/signature entity (§3.5):
   target = signed entity hash, signer = our identity hash. *)
let sign_entity (t : t) (target : Model.entity) : Model.entity =
  let sig_bytes = Sign.sign ~seed:t.seed target.hash in
  Model.make ~typ:"system/signature"
    (Cbor.Map
       [ (Cbor.Text "target", Cbor.Bytes target.hash);
         (Cbor.Text "signer", Cbor.Bytes t.identity_hash);
         (Cbor.Text "algorithm", Cbor.Text "ed25519");
         (Cbor.Text "signature", Cbor.Bytes sig_bytes) ])

(* Verify a system/signature entity against the signer's system/peer entity.
   Reads public_key from the peer entity; the §5.2 signer-hash check is the
   caller's responsibility. *)
let verify_signature (signature : Model.entity) (signer_peer : Model.entity) : bool =
  match Model.bytes_field signature "target",
        Model.bytes_field signature "signature",
        Model.bytes_field signer_peer "public_key" with
  | Some target, Some sig_bytes, Some pub ->
      Sign.verify ~pub ~signature:sig_bytes ~msg:target
  | _ -> false
