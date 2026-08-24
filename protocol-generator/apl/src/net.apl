⍝ entity-core-protocol-apl — src/net.apl (L4 transport substrate: NATIVE ⎕FIO sockets).
⍝
⍝ GNU APL provides Berkeley sockets natively via ⎕FIO (A-APL-006) — NO C net-shim (a point
⍝ of difference from COBOL/Fortran). The whole peer is ONE image on ONE ⎕FIO[40] select
⍝ loop → §7b/§4.8 store-safety is STRUCTURAL. Verified socket ABI (see status/PHASE-S3.md,
⍝ A-APL-015): an IPv4 address is a SINGLE INTEGER in the (AF ip port) triple; accept
⍝ returns (handle AF ip port) so the new fd is item [1]; recv on a closed socket yields an
⍝ EMPTY vector (EOF); byte cells cross as integers 0..255 (the array byte model).
⍝
⍝ ⎕FIO[40] select — TWO GNU-APL-1.9 bugs, both handled here (A-APL-015):
⍝   (1) the timeout is parsed but NEVER applied (`to` stays NULL) → select ALWAYS blocks
⍝       until an fd is ready. We use the 3-element (no-timeout) form as a clean "block until
⍝       readable" primitive; a broken peer still wakes it (a closed socket reads-ready+EOF).
⍝   (2) fds_to_val loops `m < max_fd` (off-by-one) → it DROPS the highest ready fd from the
⍝       returned read list. Recovered: if count > #reported, the dropped fd is ⌈/readset.

AF_INET←2 ⋄ LOOPBACK←2130706433                 ⍝ 127.0.0.1 as a single integer
IPPROTO_TCP←6 ⋄ TCP_NODELAY_OPT←1

∇Z←NowMs                                         ⍝ gettimeofday ms (tradfn — A-APL-016)
 Z←⎕FIO[50] 1000
∇

⍝ set TCP_NODELAY on an accepted/dialed socket (§7b latency floor).
NetNodelay←{(IPPROTO_TCP TCP_NODELAY_OPT 1)⎕FIO[47] ⍵}

∇Z←NetSocket                                     ⍝ a NEW AF_INET/SOCK_STREAM socket (tradfn)
 Z←⎕FIO[32] AF_INET
∇
NetClose←{⎕FIO[4] ⍵}
NetBoundPort←{(⎕FIO[44] ⍵)[3]}

⍝ open a loopback listener on `port` (0 = ephemeral) -> fd (¯1 on failure).
∇Z←NetListen port;fd;rc
 Z←¯1
 fd←NetSocket
 →(fd<0)/0
 rc←(AF_INET LOOPBACK port)⎕FIO[33] fd
 →(rc≠0)/fail
 rc←⎕FIO[34] fd
 →(rc≠0)/fail
 Z←fd ⋄ →0
 fail:zz←NetClose fd
∇

⍝ dial 127.0.0.1:port -> fd (¯1 on failure); TCP_NODELAY set.
∇Z←NetConnect port;fd;rc
 Z←¯1
 fd←NetSocket
 →(fd<0)/0
 rc←(AF_INET LOOPBACK port)⎕FIO[36] fd
 →(rc≠0)/fail
 zz←NetNodelay fd
 Z←fd ⋄ →0
 fail:zz←NetClose fd
∇

⍝ accept a pending connection on listener `⍵` -> conn fd (call ONLY when readable);
⍝ TCP_NODELAY set. ¯1 on failure.
∇Z←NetAccept lfd;acc
 acc←⎕FIO[35] lfd
 Z←¯1
 →(2>≢acc)/0
 Z←acc[1]
 zz←NetNodelay Z
∇

⍝ recv up to 64 KiB -> integer byte vector (0..255); EMPTY = EOF/closed.
NetRecv←{,65536 ⎕FIO[37] ⍵}

⍝ send a whole byte vector; returns bytes sent (loops on a short write).
∇Z←fd NetSend bytes;n;sent;c
 n←≢bytes ⋄ sent←0
 lp:→(sent≥n)/done
 c←((sent)↓bytes)⎕FIO[38] fd
 →(c≤0)/done
 sent←sent+c ⋄ →lp
 done:Z←sent
∇

⍝ block until ≥1 of `fds` (a vector) is readable -> the vector of readable fds (bug-2
⍝ recovered). No timeout (bug-1) — a dead peer wakes it via a read-ready EOF.
∇Z←NetSelectRead fds;R;cnt;rdy;mx
 R←⎕FIO[40]((fds)(⍬)(⍬))
 cnt←1⊃R ⋄ rdy←,2⊃R ⋄ mx←⌈/fds
 Z←rdy,((cnt>≢rdy)/mx)
∇
