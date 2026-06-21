(* Entity Canonical Form (ECF) — hand-rolled canonical CBOR.

   Why hand-rolled and not an opam CBOR library: ECF (ENTITY-CBOR-ENCODING.md
   §4, RFC 8949 §4.2 with Entity clarifications) needs (a) length-then-lex map
   key ordering, (b) shortest-float minimisation incl. f16, (c) recursive
   major-type-6 tag rejection on decode, (d) full uint64/nint range. No surveyed
   OCaml CBOR lib offers these out of the box, and a faithful ECF codec must own
   the canonical layer regardless (the A-005 pattern that C# and TS both hit).

   Integer representation note (OCaml-specific, ambiguity A-OC-001): OCaml's
   native [int] is 63-bit, so it cannot hold uint/​nint values in the top bit of
   the 64-bit range (e.g. corpus vector int.10 = 2^63-1). CBOR integers are
   therefore carried as [Int64.t] interpreted as an *unsigned* 64-bit pattern,
   with all width decisions made via [Int64.unsigned_compare]. This covers the
   full 0 .. 2^64-1 (uint) and -1 .. -2^64 (nint) spec range, including values
   above i64-max that the corpus does not yet exercise. *)

type t =
  | Uint of int64   (* major 0; value = unsigned interpretation of the bits *)
  | Nint of int64   (* major 1; encodes -1 - (unsigned n); stores n's bits   *)
  | Bytes of string (* major 2 *)
  | Text of string  (* major 3 *)
  | Array of t list (* major 4 *)
  | Map of (t * t) list (* major 5; keys are Text or Bytes *)
  | Bool of bool
  | Null
  | Float of float  (* major 7; 0xf9/0xfa/0xfb *)

(* Decode failures. Tag-policy violations (§6.3) surface to the peer layer as
   [400 non_canonical_ecf]; carried here as a plain exception with a tag. *)
exception Decode_error of string

(* ── half-precision (float16) helpers ─────────────────────────────────────── *)

(* Exact float16 → double. Used both on decode and for the encoder's
   round-trip representability check. *)
let half_to_double (h : int) : float =
  let sign = (h lsr 15) land 1 in
  let exp = (h lsr 10) land 0x1f in
  let mant = h land 0x3ff in
  let s = if sign = 1 then -1.0 else 1.0 in
  if exp = 0 then
    if mant = 0 then s *. 0.0                                  (* ±0 *)
    else s *. float_of_int mant *. (2.0 ** -24.0)              (* subnormal *)
  else if exp = 0x1f then
    if mant = 0 then s *. infinity else nan                    (* ±inf / nan *)
  else
    s *. (1.0 +. float_of_int mant /. 1024.0) *. (2.0 ** float_of_int (exp - 15))

(* Round-to-nearest-even double → float16 bits. The encoder only *emits* the
   result when it round-trips bit-exactly through [half_to_double], so an
   imperfect subnormal rounding can never produce wrong canonical bytes — it
   only falls back to f32/f64. (Corpus exercises f16 normals + specials; explicit
   subnormal vectors are a documented future addition, Appendix E.) *)
let double_to_half_bits (x : float) : int =
  let bits = Int64.bits_of_float x in
  let sign = Int64.to_int (Int64.shift_right_logical bits 63) land 1 in
  let sbit = sign lsl 15 in
  let exp = Int64.to_int (Int64.shift_right_logical bits 52) land 0x7ff in
  let mant = Int64.logand bits 0xFFFFFFFFFFFFFL in
  if exp = 0x7ff then (if Int64.equal mant 0L then sbit lor 0x7c00 else 0x7e00)
  else
    let e = exp - 1023 in
    if e > 15 then sbit lor 0x7c00
    else if e >= -14 then begin
      (* normal half: take top 10 of the 52 mantissa bits, round half-to-even *)
      let drop = 42 in
      let m = Int64.to_int (Int64.shift_right_logical mant drop) in
      let rem = Int64.logand mant (Int64.sub (Int64.shift_left 1L drop) 1L) in
      let halfway = Int64.shift_left 1L (drop - 1) in
      let c = Int64.unsigned_compare rem halfway in
      let round_up = c > 0 || (c = 0 && m land 1 = 1) in
      let m = if round_up then m + 1 else m in
      let half_exp, m = if m = 1024 then (e + 15 + 1, 0) else (e + 15, m) in
      if half_exp >= 0x1f then sbit lor 0x7c00
      else sbit lor (half_exp lsl 10) lor (m land 0x3ff)
    end
    else if e < -25 then sbit                                   (* underflow → ±0 *)
    else begin
      (* subnormal half: value = m * 2^-24 *)
      let full = Int64.logor (Int64.shift_left 1L 52) mant in   (* 53-bit significand *)
      let shift = 28 - e in                                      (* >= 43 *)
      if shift >= 64 then sbit
      else begin
        let m = Int64.to_int (Int64.shift_right_logical full shift) in
        let rem = Int64.logand full (Int64.sub (Int64.shift_left 1L shift) 1L) in
        let halfway = Int64.shift_left 1L (shift - 1) in
        let c = Int64.unsigned_compare rem halfway in
        let round_up = c > 0 || (c = 0 && m land 1 = 1) in
        let m = if round_up then m + 1 else m in
        if m >= 1024 then sbit lor (1 lsl 10) else sbit lor (m land 0x3ff)
      end
    end

(* ── big-endian integer emit helpers ──────────────────────────────────────── *)

let add_be buf (v : int64) nbytes =
  for i = nbytes - 1 downto 0 do
    Buffer.add_char buf
      (Char.chr (Int64.to_int (Int64.logand (Int64.shift_right_logical v (i * 8)) 0xFFL)))
  done

(* Emit a CBOR head: major type (0..7) + minimal-length unsigned argument. *)
let add_head buf major (arg : int64) =
  let mt = major lsl 5 in
  let lt a = Int64.unsigned_compare arg a < 0 in
  if lt 24L then Buffer.add_char buf (Char.chr (mt lor Int64.to_int arg))
  else if lt 256L then (Buffer.add_char buf (Char.chr (mt lor 24)); add_be buf arg 1)
  else if lt 65536L then (Buffer.add_char buf (Char.chr (mt lor 25)); add_be buf arg 2)
  else if lt 4294967296L then (Buffer.add_char buf (Char.chr (mt lor 26)); add_be buf arg 4)
  else (Buffer.add_char buf (Char.chr (mt lor 27)); add_be buf arg 8)

(* ── canonical encode ─────────────────────────────────────────────────────── *)

(* RFC 8949 §4.2.1 deterministic key ordering: compare the *encoded* key bytes
   by length first, then bytewise-lexicographically. *)
let compare_canon a b =
  let la = String.length a and lb = String.length b in
  if la <> lb then compare la lb else String.compare a b

let rec encode_to buf = function
  | Uint n -> add_head buf 0 n
  | Nint n -> add_head buf 1 n
  | Bytes s -> add_head buf 2 (Int64.of_int (String.length s)); Buffer.add_string buf s
  | Text s -> add_head buf 3 (Int64.of_int (String.length s)); Buffer.add_string buf s
  | Array l -> add_head buf 4 (Int64.of_int (List.length l)); List.iter (encode_to buf) l
  | Map kvs ->
      let encoded = List.map (fun (k, v) -> (encode k, v)) kvs in
      let sorted = List.sort (fun (a, _) (b, _) -> compare_canon a b) encoded in
      (* Rule 5: reject duplicate keys (adjacent after sort). *)
      let rec dup = function
        | (a, _) :: ((b, _) :: _ as r) ->
            if String.equal a b then raise (Decode_error "duplicate map key") else dup r
        | _ -> ()
      in
      dup sorted;
      add_head buf 5 (Int64.of_int (List.length kvs));
      List.iter (fun (kb, v) -> Buffer.add_string buf kb; encode_to buf v) sorted
  | Bool false -> Buffer.add_char buf '\xf4'
  | Bool true -> Buffer.add_char buf '\xf5'
  | Null -> Buffer.add_char buf '\xf6'
  | Float x -> encode_float buf x

and encode_float buf (x : float) =
  let bits_eq a b = Int64.equal (Int64.bits_of_float a) (Int64.bits_of_float b) in
  if x <> x then (Buffer.add_char buf '\xf9'; add_be buf 0x7e00L 2) (* canonical NaN *)
  else begin
    let h = double_to_half_bits x in
    if bits_eq (half_to_double h) x then
      (Buffer.add_char buf '\xf9'; add_be buf (Int64.of_int h) 2)
    else
      let s32 = Int32.bits_of_float x in
      if bits_eq (Int32.float_of_bits s32) x then
        (Buffer.add_char buf '\xfa';
         add_be buf (Int64.logand (Int64.of_int32 s32) 0xFFFFFFFFL) 4)
      else
        (Buffer.add_char buf '\xfb'; add_be buf (Int64.bits_of_float x) 8)
  end

and encode (v : t) : string =
  let buf = Buffer.create 64 in
  encode_to buf v;
  Buffer.contents buf

(* ── decode (rejects tags + indefinite lengths) ───────────────────────────── *)

let decode (s : string) : t =
  let pos = ref 0 in
  let n = String.length s in
  let need k = if !pos + k > n then raise (Decode_error "truncated") in
  let u8 () = need 1; let c = Char.code s.[!pos] in incr pos; c in
  let take k = need k; let r = String.sub s !pos k in pos := !pos + k; r in
  let be k = need k; let v = ref 0L in
    for _ = 1 to k do v := Int64.logor (Int64.shift_left !v 8) (Int64.of_int (Char.code s.[!pos])); incr pos done;
    !v
  in
  let read_arg ai =
    if ai < 24 then Int64.of_int ai
    else if ai = 24 then be 1
    else if ai = 25 then be 2
    else if ai = 26 then be 4
    else if ai = 27 then be 8
    else raise (Decode_error "non_canonical_ecf: indefinite/reserved length") (* 28..31 *)
  in
  let rec item () =
    let ib = u8 () in
    let major = ib lsr 5 and ai = ib land 0x1f in
    match major with
    | 0 -> Uint (read_arg ai)
    | 1 -> Nint (read_arg ai)
    | 2 -> Bytes (take (Int64.to_int (read_arg ai)))
    | 3 -> Text (take (Int64.to_int (read_arg ai)))
    | 4 ->
        let len = Int64.to_int (read_arg ai) in
        let rec loop i acc = if i = 0 then List.rev acc else loop (i - 1) (item () :: acc) in
        Array (loop len [])
    | 5 ->
        let len = Int64.to_int (read_arg ai) in
        let rec loop i acc =
          if i = 0 then List.rev acc
          else let k = item () in let v = item () in loop (i - 1) ((k, v) :: acc)
        in
        Map (loop len [])
    | 6 -> raise (Decode_error "non_canonical_ecf: CBOR tag not permitted in ECF")
    | 7 ->
        (match ai with
         | 20 -> Bool false
         | 21 -> Bool true
         | 22 -> Null
         | 25 -> Float (half_to_double (Int64.to_int (be 2)))
         | 26 -> Float (Int32.float_of_bits (Int64.to_int32 (be 4)))
         | 27 -> Float (Int64.float_of_bits (be 8))
         | _ -> raise (Decode_error "unsupported simple/float value"))
    | _ -> raise (Decode_error "unreachable major type")
  in
  let v = item () in
  if !pos <> n then raise (Decode_error "trailing bytes after top-level item");
  v
