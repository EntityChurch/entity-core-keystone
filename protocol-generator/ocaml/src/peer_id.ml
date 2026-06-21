(* Peer identifier (V7 §1.2 / §7.3):

     peer_id = Base58(varint(key_type) || varint(hash_type) || digest)

   key_type/hash_type are LEB128 varints (N1). key_type 0x01 = ed25519,
   hash_type 0x01 = sha256. A synthetic key_type >= 0x80 exercises the
   multi-byte varint prefix (corpus peer_id.3). *)

type components = { key_type : int; hash_type : int; digest : string }

let format { key_type; hash_type; digest } : string =
  Base58.encode (Varint.encode key_type ^ Varint.encode hash_type ^ digest)

(* Inverse surface (S2 objective lists "peer-id parse/format"). Not exercised by
   a corpus vector yet, but the peer needs it to read inbound peer-ids; a
   round-trip self-test guards it. *)
let parse (s : string) : components =
  let raw = Base58.decode s in
  let key_type, k1 = Varint.decode raw 0 in
  let hash_type, k2 = Varint.decode raw k1 in
  let off = k1 + k2 in
  { key_type; hash_type; digest = String.sub raw off (String.length raw - off) }
