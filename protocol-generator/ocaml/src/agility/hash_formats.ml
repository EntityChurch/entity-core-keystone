(* content_hash_format registry (V7 §1.2). SHA-256 (0x00, the §9.1 floor) and
   SHA-384 (0x01) are BOTH native via digestif (Hash.sha256 / Hash.sha384) — the
   agility higher bar needs the FFI only for Ed448, not for hashing. The harness
   does cross-check the FFI ec_sha384 against the native digestif digest as a
   differential, but the live hashing path is native. Unknown/reserved codes
   surface unsupported_content_hash_format. The format code is a LEB128 varint
   (N1): 0x80 0x01 decodes to 128 (multi-byte path), which is unsupported — the
   error is an INTERPRETATION error (§1.2 v7.68), not a single-byte short-circuit. *)
open Entitycore_codec

type fmt = Sha256 | Sha384

let sha256_code = 0x00
let sha384_code = 0x01
let reserved = 0xFF

let code = function Sha256 -> 0x00 | Sha384 -> 0x01

let by_code = function
  | 0x00 -> Ok Sha256
  | 0x01 -> Ok Sha384
  | n -> Error (Printf.sprintf "unsupported_content_hash_format (code %d)" n)

let is_supported (n : int) : bool = n = 0x00 || n = 0x01

(* Decode the LEB128 format code from the head of a wire content_hash / hash
   request. Returns the decoded integer (which may be unsupported). *)
let read_format_code (s : string) : int =
  let v, _ = Varint.decode s 0 in
  v

let digest (fmt : fmt) (data : string) : string =
  match fmt with Sha256 -> Hash.sha256 data | Sha384 -> Hash.sha384 data
