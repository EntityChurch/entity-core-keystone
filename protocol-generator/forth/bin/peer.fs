\ entity-core-protocol-forth — the peer CLI entry (bin/peer.fs).
\
\ Boot convention (matches the cohort — study rexx bin/peer.rex):
\   gforth bin/peer.fs --port N [--name NAME] [--seed HH] [--validate]
\
\   --name NAME  loads the Ed25519 identity from ~/.entity/peers/NAME/keypair (PEM = base64
\                of a raw 32-byte seed; armor lines starting '-' are skipped).
\   --seed HH    a single hex byte, repeated x32, as the seed (test convenience).
\   --port N     listen port (0 => ephemeral). Default 0.
\   --validate   enable the system/validate/* conformance handlers (OFF by default; the
\                dispatch-outbound reentry probe is reference-peer-gated — S4).
\   --debug-open-grants  accepted (no-op at S3; deprecated degenerate seed policy).
\
\ On success prints exactly `LISTENING <bound-port>` on stdout (the harness scrapes this),
\ then serves the select loop forever.

require ../src/peer-all.fs

\ ── option state ──
variable opt-port      0 opt-port !
variable opt-validate  0 opt-validate !
create   opt-name  256 allot   variable opt-name-len   0 opt-name-len !
2variable opt-seed-hex         0. opt-seed-hex 2!       \ (addr,len) of a --seed value

create seed-buf 32 allot

\ ── seed resolution ──
: hex-nibble ( ch -- v )
  dup [char] 0 >= over [char] 9 <= and if [char] 0 - exit then
  dup [char] a >= over [char] f <= and if [char] a - 10 + exit then
  dup [char] A >= over [char] F <= and if [char] A - 10 + exit then  drop 0 ;

\ seed-from-hex ( addr u -- )  --seed HH : one hex byte, repeated 32 times.
: seed-from-hex { haddr hu -- }
  hu 2 >= if  haddr c@ hex-nibble 16 *  haddr 1+ c@ hex-nibble +
         else  $11  then  { b }
  32 0 ?do  b seed-buf i + c!  loop ;

\ ── keypair PEM loading ──
create pem-line 512 allot
create path-buf 512 allot

\ keypair-path ( name-addr name-u -- p-addr p-u )  ~/.entity/peers/NAME/keypair
: keypair-path { naddr nu -- paddr pu }
  s" HOME" getenv dup 0= if 2drop s" /root" then    ( h-addr h-u )
  path-buf swap dup { c } move
  s" /.entity/peers/" path-buf c + swap dup { d } move  c d + to c
  naddr path-buf c + nu move  c nu + to c
  s" /keypair" path-buf c + swap dup { e } move  c e + to c
  path-buf c ;

\ load-keypair ( name-addr name-u -- ok? )  read the PEM, strip armor/blank lines, base64
\ decode the body into seed-buf (must be 32 bytes). read-line: ( c-addr u1 fid -- u2 flag ior ).
: load-keypair { naddr nu -- ok }
  naddr nu keypair-path r/o open-file if drop false exit then { fid }
  am-mark { b64mk }
  begin
    pem-line 512 fid read-line drop     \ ( u2 flag ) — drop ior (best-effort)
  while                                  ( u2 )
    { len }
    len 0> pem-line c@ [char] - <> and if pem-line len bytes, then
  repeat
  drop                                   \ final u2
  fid close-file drop
  b64mk am-span b64-decode { du } { daddr }
  du 32 <> if false exit then
  daddr seed-buf 32 move true ;

\ resolve-seed ( -- ok )  --name > --seed > default (0x11 x32).
: resolve-seed ( -- ok )
  opt-name-len @ 0<> if  opt-name opt-name-len @ load-keypair exit  then
  opt-seed-hex 2@ dup 0<> if  opt-seed-hex 2@ seed-from-hex true exit  then  drop
  32 0 ?do  $11 seed-buf i + c!  loop  true ;

\ ── argument parsing (gforth next-arg: ( -- c-addr u ), u=0 when exhausted) ──
: str= ( a1 u1 a2 u2 -- flag )  compare 0= ;
: arg-uint ( c-addr u -- n )  0 0 2swap >number 2drop drop ;

: parse-args ( -- )
  begin
    next-arg  dup 0> while           ( a u )
    2dup s" --port"     str= if 2drop next-arg arg-uint opt-port ! else
    2dup s" --name"     str= if 2drop next-arg opt-name swap dup opt-name-len ! move else
    2dup s" --seed"     str= if 2drop next-arg opt-seed-hex 2! else
    2dup s" --validate" str= if 2drop 1 opt-validate ! else
    2dup s" --debug-open-grants" str= if 2drop else
      2drop                          \ unknown flag: ignore (S3 is permissive)
    then then then then then
  repeat 2drop ;

\ ── main ──
: main ( -- )
  parse-args
  resolve-seed 0= if ." keypair load failed" cr 2 (bye) then
  seed-buf 32 opt-validate @ peer-bootstrap
  opt-port @ peer-listen { bound }
  ." LISTENING " bound . cr
  \ flush stdout so the harness scrapes LISTENING immediately
  stdout flush-file drop
  peer-serve ;

main
bye
