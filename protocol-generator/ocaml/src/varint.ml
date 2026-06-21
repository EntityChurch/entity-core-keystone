(* Multicodec-style LEB128 varints (V7 §1.5, §7.3 — NORMATIVE).

   Invariant N1: format codes, key_type and hash_type are framed as LEB128
   varints, NOT fixed bytes. Every currently-allocated code is < 0x80 (one
   byte), so this is byte-identical to a fixed field today — the point is that a
   future code >= 0x80 extends to 2+ bytes and a fixed-width impl breaks
   silently. Corpus vectors content_hash.4 (format_code 128) and peer_id.3
   (key_type 128) prove the multi-byte path. *)

let encode (n : int) : string =
  if n < 0 then invalid_arg "Varint.encode: negative";
  let buf = Buffer.create 4 in
  let rec go n =
    if n < 0x80 then Buffer.add_char buf (Char.chr n)
    else (Buffer.add_char buf (Char.chr ((n land 0x7f) lor 0x80)); go (n lsr 7))
  in
  go n;
  Buffer.contents buf

(* Decode one varint at [pos]; returns (value, bytes_consumed). *)
let decode (s : string) (pos : int) : int * int =
  let rec go i shift acc =
    if i >= String.length s then failwith "Varint.decode: truncated";
    let b = Char.code s.[i] in
    let acc = acc lor ((b land 0x7f) lsl shift) in
    if b land 0x80 = 0 then (acc, i - pos + 1) else go (i + 1) (shift + 7) acc
  in
  go pos 0 0
