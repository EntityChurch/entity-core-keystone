\ entity-core-protocol-forth — RFC-4648 base64 DECODE (for the keypair PEM: the entity-core
\ private key file is `-----BEGIN ENTITY PRIVATE KEY-----` armor + base64 of the raw 32-byte
\ Ed25519 seed). gforth has no base64; hand-rolled over the arena (like base58.fs).

\ b64-val ( ch -- v | -1 )  the 6-bit value of a base64 alphabet char, or -1.
: b64-val ( ch -- v )
  dup [char] A >= over [char] Z <= and if [char] A - exit then
  dup [char] a >= over [char] z <= and if [char] a - 26 + exit then
  dup [char] 0 >= over [char] 9 <= and if [char] 0 - 52 + exit then
  dup [char] + = if drop 62 exit then
  dup [char] / = if drop 63 exit then
  drop -1 ;

\ b64-decode ( c-addr u -- out-addr out-u )  decode base64 into the arena. Skips any
\ non-alphabet char (newlines, armor already stripped by the caller); stops at '='.
: b64-decode { caddr cu -- oaddr ou }
  am-mark { mk }
  0 0 { acc bits }
  cu 0 ?do
    caddr i + c@ { ch }
    ch [char] = = if leave then
    ch b64-val { v }
    v 0>= if
      acc 6 lshift v or to acc
      bits 6 + to bits
      bits 8 >= if
        bits 8 - { sh }
        acc sh rshift 255 and b,
        acc  1 sh lshift 1- and  to acc      \ keep low `sh` bits
        sh to bits
      then
    then
  loop
  mk am-span ;
