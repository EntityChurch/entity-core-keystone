\ entity-core-protocol-forth — transport: native BSD sockets + a single-thread select
\ event loop, framing, and the §4.10(a) 16-MiB inbound cap.
\
\ A-FT-008 (the transport verdict vs the Rexx precedent): gforth has GENUINE in-process
\ BSD sockets (unix/socket.fs) AND genuine in-process crypto (libcc, A-FT-005), so — unlike
\ Rexx (Regina's rxfuncadd was dead + its FIFO reads corrupt under a concurrent subprocess,
\ A-RX-008/011, forcing an `ecnet` C co-process daemon) — Forth owns the sockets, the
\ select() loop, the §1.6 de-framing, the 16-MiB cap and TCP_NODELAY DIRECTLY in-process.
\ This is the COBOL/Tcl native-socket shape, not the Rexx daemon shape. §7b store-safety is
\ STRUCTURAL: one interpreter, one thread, one frame dispatched to completion before the
\ next select() wake — no lock, no data race by construction (§4.8).
\
\ We bind the low-level fd syscalls ourselves (unix/socket.fs's high-level words wrap fds
\ in FILE* and `abort"` on error — unusable for a select loop). select()/FD_SET live behind
\ tiny C shims (a static fd_set the shim owns) so the peer never marshals an fd_set from
\ Forth. Frame := [4-byte BE length][payload] (§1.6). A length prefix > MAX-FRAME is the
\ §4.10(a) violation: we DRAIN-and-keep the connection (a 413-class rejection at the
\ de-framer; never a silent close, never buffering the oversize body — §4.9 keep-serving).

require libcc.fs

\ NOTE: the c-library NAME becomes part of the generated wrapper's C symbol names, so it
\ MUST be a valid C identifier — NO hyphens (a hyphen made gcc reject the wrapper; A-FT-010).
\ We bind ALL socket primitives ourselves rather than `require unix/socket.fs` — its
\ high-level words wrap fds in FILE* and `abort"` (unusable for a select loop), and a second
\ `require` of it re-runs its own c-library block (a redefine flood). We only need the raw
\ syscalls + byte-order helpers, all bound below.
c-library ecnetsock
  \c #include <sys/types.h>
  \c #include <sys/socket.h>
  \c #include <netinet/in.h>
  \c #include <netinet/tcp.h>
  \c #include <sys/select.h>
  \c #include <fcntl.h>
  \c #include <errno.h>
  \c #include <unistd.h>
  \c #include <arpa/inet.h>
  \c #include <string.h>
  \ A static read fd_set the shim owns — the peer never marshals an fd_set from Forth.
  \c static fd_set ec_rfds;
  \c static void ec_fdzero(void){ FD_ZERO(&ec_rfds); }
  \c static void ec_fdset(int fd){ FD_SET(fd,&ec_rfds); }
  \c static int  ec_fdisset(int fd){ return FD_ISSET(fd,&ec_rfds)?1:0; }
  \ select() with an inline timeval built from (sec,usec). Returns #ready / 0 timeout / <0.
  \c static int ec_select(int nfds,long sec,long usec){
  \c   struct timeval tv; tv.tv_sec=sec; tv.tv_usec=usec;
  \c   return select(nfds,&ec_rfds,0,0,&tv); }
  \c static int ec_geterrno(void){ return errno; }
  c-function ec-fdzero   ec_fdzero  -- void
  c-function ec-fdset    ec_fdset   n -- void
  c-function ec-fdisset  ec_fdisset n -- n
  c-function ec-select   ec_select  n n n -- n
  c-function ec-socket   socket     n n n -- n
  c-function ec-bind     bind       n a n -- n
  c-function ec-listen   listen     n n -- n
  c-function ec-accept   accept     n a a -- n
  c-function ec-connect  connect    n a n -- n
  c-function ec-recv     recv       n a n n -- n
  c-function ec-send     send       n a n n -- n
  c-function ec-close    close      n -- n
  c-function ec-getsockname getsockname n a a -- n
  c-function ec-setsockopt  setsockopt  n n n a n -- n
  c-function ec-fcntl    fcntl      n n n -- n
  c-function ec-errno    ec_geterrno -- n
  c-function htons       htons      n -- n
  c-function htonl       htonl      n -- n
end-c-library

2 constant AF-INET
1 constant SOCK-STREAM
6 constant IPPROTO-TCP
1 constant TCP-NODELAY
1 constant SOL-SOCKET
2 constant SO-REUSEADDR
4 constant F-SETFL
2048 constant O-NONBLOCK        \ Linux O_NONBLOCK
11 constant EAGAIN-             \ EAGAIN / EWOULDBLOCK on Linux

16 1024 * 1024 * constant MAX-FRAME     \ §4.10(a) 16-MiB inbound frame cap (informative default)

\ ── little scratch buffers for sockaddr_in / getsockname / send-len ──
create sa-buf   16 allot
create sn-buf   16 allot
create snl-buf  1 cells allot
create opt1     1 cells allot   1 opt1 !

\ fill-sockaddr ( ip-be port-host addr -- )  write an AF_INET sockaddr_in at addr:
\   family(u16 host) port(u16 net) sin_addr(u32 net==ip-be already) 8 pad.
: fill-sockaddr { ipbe porth addr -- }
  addr 16 erase
  AF-INET addr w!                          \ family (host order for the struct field on Linux)
  porth htons addr 2 + w!                  \ port network order
  ipbe addr 4 + l! ;                       \ sin_addr (already network order)

\ ntohs is not in unix/socket.fs (only htons/htonl/ntohl are). A 16-bit network<->host
\ swap is its own inverse; define it directly so we never depend on a missing word.
: ntohs ( u16-net -- u16-host )  dup 8 rshift 255 and  swap 255 and 8 lshift or ;

$0100007F constant LOOPBACK-BE             \ 127.0.0.1 in network byte order

\ ── socket setup ──
: net-new-socket ( -- fd )
  AF-INET SOCK-STREAM 0 ec-socket ;

: net-nodelay ( fd -- )  IPPROTO-TCP TCP-NODELAY opt1 4 ec-setsockopt drop ;
: net-reuseaddr ( fd -- )  SOL-SOCKET SO-REUSEADDR opt1 4 ec-setsockopt drop ;
: net-nonblocking ( fd -- )  F-SETFL O-NONBLOCK ec-fcntl drop ;

\ net-listen ( port -- lfd bound-port )  bind 127.0.0.1:port (0 => ephemeral), listen,
\ return the listen fd + the actually-bound port (host order). THROWs E-NET on failure.
-25100 constant E-NET
: net-listen { port -- lfd bound }
  net-new-socket dup 0< if drop E-NET throw then { lfd }
  lfd net-reuseaddr
  LOOPBACK-BE port sa-buf fill-sockaddr
  lfd sa-buf 16 ec-bind 0< if E-NET throw then
  lfd 128 ec-listen 0< if E-NET throw then
  16 snl-buf !
  lfd sn-buf snl-buf ec-getsockname 0< if E-NET throw then
  sn-buf 2 + w@ ntohs { boundport }             \ port field, net->host
  lfd boundport ;

\ net-dial ( port -- fd )  connect to 127.0.0.1:port, set TCP_NODELAY. THROWs E-NET.
: net-dial { port -- fd }
  net-new-socket dup 0< if drop E-NET throw then { fd }
  fd net-nodelay
  LOOPBACK-BE port sa-buf fill-sockaddr
  fd sa-buf 16 ec-connect 0< if E-NET throw then
  fd ;

\ net-accept ( lfd -- fd )  accept a pending connection, set TCP_NODELAY. -1 on error.
create acc-sa  16 allot   create acc-len 1 cells allot
: net-accept { lfd -- fd }
  16 acc-len !
  lfd acc-sa acc-len ec-accept dup 0>= if dup net-nodelay then ;

\ ── framed I/O over a blocking socket (the select loop gates readability first) ──
\ recv-exact ( fd buf n -- ok? )  read exactly n bytes into buf; false on EOF/error.
: recv-exact { fd buf n -- ok }
  0 { got }
  begin got n < while
    fd  buf got +  n got -  0 ec-recv  { r }
    r 0<= if
      r 0= if false exit then                     \ orderly EOF
      ec-errno EAGAIN- = if else false exit then   \ real error (EAGAIN: retry)
    else
      got r + to got
    then
  repeat true ;

\ send-all ( fd buf n -- )  write all n bytes (loops over short sends).
: send-all { fd buf n -- }
  0 { sent }
  begin sent n < while
    fd  buf sent +  n sent -  0 ec-send  { r }
    r 0< if
      ec-errno EAGAIN- = if else E-NET throw then
    else
      sent r + to sent
    then
  repeat ;

\ drain-bytes ( fd n -- )  read and discard n bytes (an oversize §4.10 body). Keeps the
\ connection (§4.9 keep-serving) instead of buffering the body or dropping the peer.
create drain-buf 4096 allot
: drain-bytes { fd n -- }
  begin n 0> while
    fd drain-buf  n 4096 min  0 ec-recv  { r }
    r 0<= if r 0= if exit then ec-errno EAGAIN- = if else exit then
         else n r - to n then
  repeat ;

\ ── one inbound frame ── net-read-frame ( fd -- addr len | 0 0 | -1 -1 )
\   (addr,len) — a valid frame appended to the arena.
\   0 0        — §4.10(a) oversize: drained + connection kept; caller loops on.
\   -1 -1      — EOF / error: caller closes the connection.
: net-read-frame { fd -- addr len }
  \ 4-byte BE length prefix
  drain-buf fd swap 4 recv-exact 0= if -1 dup exit then    \ reuse drain-buf transiently
  drain-buf 0 4 @be { flen }
  flen 0< flen MAX-FRAME > or if
    \ §4.10(a): oversize — drain the body, keep the connection (413-class at de-framer).
    fd flen drain-bytes  0 0 exit
  then
  am-mark { mk }
  fd  arena-here  flen  recv-exact 0= if mk rewind -1 dup exit then
  flen ap +!                                          \ commit the recv'd body into the arena
  mk flen ;

\ frame-out ( fd payload-addr payload-len -- )  send [len:4 BE][payload] (§1.6).
create flen-hdr 4 allot
: frame-out { fd paddr plen -- }
  \ write BE length into flen-hdr
  plen 24 rshift 255 and flen-hdr    c!
  plen 16 rshift 255 and flen-hdr 1+ c!
  plen  8 rshift 255 and flen-hdr 2 + c!
  plen           255 and flen-hdr 3 + c!
  fd flen-hdr 4 send-all
  fd paddr plen send-all ;

\ ── the select event loop primitives ──
\ A pending connection is a fd; the peer keeps a small fd table (see peer.fs). The select
\ helpers operate over an fd list the caller supplies.
\ net-select ( fd-array count timeout-sec timeout-usec -- nready )  arm the read set with
\ every fd in the array, select with the timeout, return #ready (fd-isset queried after).
: net-select { fds n sec usec -- nready }
  ec-fdzero
  0 { maxfd }
  n 0 ?do
    fds i cells + @ { f }
    f ec-fdset
    f maxfd > if f to maxfd then
  loop
  maxfd 1+ sec usec ec-select ;
: net-ready? ( fd -- flag )  ec-fdisset 0<> ;

: net-close ( fd -- )  ec-close drop ;
