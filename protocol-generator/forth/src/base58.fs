\ entity-core-protocol-forth — Base58 (Bitcoin alphabet), pure Forth.
\
\ peer_id digests are 32-34 bytes — far past a 64-bit cell — so the base-256 <-> base-58
\ conversion CANNOT go through a single-cell bignum (contrast Rexx, which had native
\ decimal bignum). Instead we do the classic BYTE-ARRAY long division: repeated divide
\ of the big-endian byte array by 58 (encode) / multiply-by-58-add-digit (decode),
\ carrying across bytes. This is the fixed-width-cell discipline (A-FT-001) applied to a
\ >64-bit quantity: the number lives as its bytes, the cell holds only a byte-wide carry.
\
\ Leading zero bytes map to leading '1' characters and vice-versa (§1.5).

\ The Bitcoin base58 alphabet, as a counted string in the dictionary.
create B58-ALPHA
  char 1 c, char 2 c, char 3 c, char 4 c, char 5 c, char 6 c, char 7 c, char 8 c,
  char 9 c, char A c, char B c, char C c, char D c, char E c, char F c, char G c,
  char H c, char J c, char K c, char L c, char M c, char N c, char P c, char Q c,
  char R c, char S c, char T c, char U c, char V c, char W c, char X c, char Y c,
  char Z c, char a c, char b c, char c c, char d c, char e c, char f c, char g c,
  char h c, char i c, char j c, char k c, char m c, char n c, char o c, char p c,
  char q c, char r c, char s c, char t c, char u c, char v c, char w c, char x c,
  char y c, char z c,

\ b58-char ( n -- c )  the alphabet character for digit n (0..57).
: b58-char ( n -- c )  B58-ALPHA + c@ ;

\ b58-val ( c -- n | -1 )  the digit value of a base58 char, or -1 if not in alphabet.
: b58-val ( c -- n )
  58 0 ?do
    dup i b58-char = if drop i unloop exit then
  loop drop -1 ;

\ Scratch big-number byte array (big-endian) for the long division. 64 bytes is ample
\ for any peer_id (varint prefix + <=57-byte digest) and its base58 expansion.
128 constant B58-MAX
create b58-num  B58-MAX allot          \ big-endian working number
create b58-out  B58-MAX 2* allot       \ output digit scratch (built reversed)

\ base58-encode ( c-addr u -- )  append the base58 text of the byte span to the arena.
: base58-encode { c-addr u -- }
  u 0= if exit then
  u B58-MAX > if E-BAD-BASE58 throw then
  \ copy input into the working number
  c-addr b58-num u move
  \ count leading zero bytes -> that many leading '1's
  0 { nz }
  u 0 ?do  b58-num i + c@ 0= if 1 nz + to nz else leave then  loop
  \ repeated divide-by-58 over the big-endian byte array; collect remainders.
  0 { nout }
  begin
    \ is the number all-zero?
    0 { anynz }
    u 0 ?do  b58-num i + c@ if 1 to anynz leave then  loop
    anynz
  while
    0 { rem }                                   \ running remainder (0..57)
    u 0 ?do
      rem 256 * b58-num i + c@ +                 ( acc )
      dup 58 / b58-num i + c!                    \ quotient byte back in place
      58 mod to rem                              \ new remainder
    loop
    rem b58-char b58-out nout + c!  nout 1+ to nout
  repeat
  \ leading '1' for each leading zero byte
  nz 0 ?do [char] 1 b, loop
  \ emit collected digits in reverse (most-significant first)
  nout 0 ?do  b58-out nout 1- i - + c@ b,  loop ;

\ base58-decode ( c-addr u -- )  append the decoded bytes of a base58 string to the
\ arena; reject a non-alphabet char.
: base58-decode { c-addr u -- }
  u 0= if exit then
  \ leading '1's -> leading zero bytes
  0 { nz }
  u 0 ?do  c-addr i + c@ [char] 1 = if 1 nz + to nz else leave then  loop
  \ build the big-endian byte array by num = num*58 + digit
  b58-num B58-MAX erase
  1 { nbytes }                                  \ current significant length (>=1)
  u 0 ?do
    c-addr i + c@ b58-val  dup 0< if E-BAD-BASE58 throw then  ( digit )
    \ multiply the big-endian number (last nbytes bytes) by 58, add digit as carry.
    { digit }
    digit { carry }
    nbytes 0 ?do
      b58-num B58-MAX 1- i - + c@ 58 * carry +  ( acc )
      dup 255 and b58-num B58-MAX 1- i - + c!
      8 rshift to carry
    loop
    begin carry 0<> while
      carry 255 and b58-num B58-MAX 1- nbytes - + c!
      carry 8 rshift to carry
      nbytes 1+ to nbytes
    repeat
  loop
  \ emit leading zeros then the nbytes significant bytes (skip internal leading zeros
  \ beyond the counted length — nbytes is exact).
  nz 0 ?do 0 b, loop
  nbytes 0 ?do  b58-num B58-MAX nbytes - i + + c@ b,  loop ;
