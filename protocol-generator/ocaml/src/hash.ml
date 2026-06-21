(* content_hash construction (ENTITY-CBOR-ENCODING.md §4.2 / §9.3):

     content_hash = varint(format_code) || HASH(ECF({type, data}))

   format_code 0x00 = ecfv1-sha256 (the required floor). 0x01 = ecfv1-sha384
   (agility). The varint prefix is LEB128 (N1) — a synthetic code >= 0x80
   exercises the multi-byte path (corpus content_hash.4). *)

let sha256 (s : string) : string = Digestif.SHA256.(to_raw_string (digest_string s))
let sha384 (s : string) : string = Digestif.SHA384.(to_raw_string (digest_string s))

(* ECF of the {type, data} entity. The encoder sorts keys, so "data" precedes
   "type" (both 5 encoded bytes, lexicographic). *)
let ecf_of_entity ~typ ~(data : Cbor.t) : string =
  Cbor.encode (Cbor.Map [ (Cbor.Text "type", Cbor.Text typ); (Cbor.Text "data", data) ])

let content_hash ?(format_code = 0) ~typ ~(data : Cbor.t) () : string =
  let ecf = ecf_of_entity ~typ ~data in
  let digest = match format_code with 1 -> sha384 ecf | _ -> sha256 ecf in
  Varint.encode format_code ^ digest
