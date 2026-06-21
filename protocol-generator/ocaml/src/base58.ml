(* Base58 (Bitcoin alphabet) — hand-rolled, used for peer-id formatting.
   Standard byte-array long-division; no bignum dependency needed. Leading
   zero bytes map to leading '1' characters. *)

let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let encode (input : string) : string =
  let len = String.length input in
  (* count leading zero bytes *)
  let zeros = ref 0 in
  while !zeros < len && input.[!zeros] = '\000' do incr zeros done;
  (* base256 → base58 via repeated division, accumulated big-endian *)
  let size = (len * 138 / 100) + 1 in
  let b58 = Bytes.make size '\000' in
  let high = ref (size - 1) in
  for i = 0 to len - 1 do
    let carry = ref (Char.code input.[i]) in
    let j = ref (size - 1) in
    while !j > !high || !carry <> 0 do
      carry := !carry + (256 * Char.code (Bytes.get b58 !j));
      Bytes.set b58 !j (Char.chr (!carry mod 58));
      carry := !carry / 58;
      decr j
    done;
    high := !j
  done;
  (* skip leading zero "digits" in the b58 buffer *)
  let start = ref 0 in
  while !start < size && Bytes.get b58 !start = '\000' do incr start done;
  let buf = Buffer.create (size + !zeros) in
  for _ = 1 to !zeros do Buffer.add_char buf '1' done;
  for k = !start to size - 1 do
    Buffer.add_char buf alphabet.[Char.code (Bytes.get b58 k)]
  done;
  Buffer.contents buf

(* index of each alphabet char, -1 if not a base58 char *)
let values =
  let v = Array.make 128 (-1) in
  String.iteri (fun i c -> v.(Char.code c) <- i) alphabet;
  v

let decode (s : string) : string =
  let len = String.length s in
  let ones = ref 0 in
  while !ones < len && s.[!ones] = '1' do incr ones done;
  let size = (len * 733 / 1000) + 1 in (* log(58)/log(256) ≈ 0.733 *)
  let b256 = Bytes.make size '\000' in
  let high = ref (size - 1) in
  for i = 0 to len - 1 do
    let c = Char.code s.[i] in
    let d = if c < 128 then values.(c) else -1 in
    if d < 0 then invalid_arg "Base58.decode: invalid character";
    let carry = ref d in
    let j = ref (size - 1) in
    while !j > !high || !carry <> 0 do
      carry := !carry + (58 * Char.code (Bytes.get b256 !j));
      Bytes.set b256 !j (Char.chr (!carry land 0xff));
      carry := !carry lsr 8;
      decr j
    done;
    high := !j
  done;
  let start = ref 0 in
  while !start < size && Bytes.get b256 !start = '\000' do incr start done;
  let buf = Buffer.create (size + !ones) in
  for _ = 1 to !ones do Buffer.add_char buf '\000' done;
  Buffer.add_string buf (Bytes.sub_string b256 !start (size - !start));
  Buffer.contents buf
