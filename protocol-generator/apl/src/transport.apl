⍝ entity-core-protocol-apl — src/transport.apl (§1.6 framing + §6.11 demux + §4.10 413).
⍝
⍝ The mechanical layer between the ⎕FIO sockets (net.apl) and the peer brain (peer.apl):
⍝ §1.6 length-prefix framing, per-fd receive buffers (a socket read may split/coalesce
⍝ frames), and the §6.11 request_id DEMUX table (a reply's request_id -> its delivered
⍝ payload). One image, one select loop, one pump → no lock: store-safety structural (§7b).
⍝
⍝ Frame := [4-byte BE length][canonical-ECF payload]. §4.10(a): a length prefix > 16 MiB
⍝ is rejected as 413 payload_too_large BEFORE the body is buffered (the prefix is all we
⍝ read) — TrRxExtract flags oversize and drops the connection buffer.

MAX_FRAME←16×1024×1024                            ⍝ §4.10 informative 16 MiB inbound cap

∇TrReset
 gPendRid←⍬ ⋄ gPendPay←⍬ ⋄ gPendDone←⍬
 gRxFd←⍬ ⋄ gRxBuf←⍬
∇

FrameOf←{((4⍴256)⊤≢⍵),⍵}                          ⍝ payload -> [4-byte BE len][payload]

⍝ ── per-fd receive buffers ──
∇Z←RxIndex fd;i
 Z←0 ⋄ i←0
 lp:→(i≥≢gRxFd)/0
 i←i+1 ⋄ →((i⊃gRxFd)≠fd)/lp
 Z←i ⋄ →0
∇

∇fd TrRxAppend bytes;idx
 idx←RxIndex fd
 →(idx>0)/have
 gRxFd←gRxFd,fd ⋄ gRxBuf←gRxBuf,⊂bytes ⋄ →0
 have:gRxBuf[idx]←⊂(idx⊃gRxBuf),bytes
∇

⍝ 1 iff fd's receive buffer still holds bytes that never completed a frame. §4.11's
⍝ framing arm needs this to tell a MID-FRAME end of stream (a refusal, owed a coded
⍝ frame) from a clean close at a frame boundary (an ordinary hangup, owed nothing). The
⍝ two are indistinguishable at the socket: read(2) answers 0 for both.
∇Z←TrRxPending fd;idx
 Z←0
 idx←RxIndex fd
 →(idx=0)/0
 Z←0<≢idx⊃gRxBuf
∇

∇TrRxDrop fd;idx
 idx←RxIndex fd
 →(idx=0)/0
 gRxFd←gRxFd/⍨(⍳≢gRxFd)≠idx
 gRxBuf←gRxBuf/⍨(⍳≢gRxBuf)≠idx
∇

⍝ pull all complete frames out of fd's buffer -> (frames oversize). oversize=1 iff a
⍝ length prefix exceeds MAX_FRAME (413 before buffering the body).
∇Z←TrRxExtract fd;idx;buf;frames;len
 frames←⍬
 idx←RxIndex fd
 →(idx=0)/none
 buf←idx⊃gRxBuf
 lp:→((≢buf)<4)/save
 len←256⊥4↑buf
 →(len>MAX_FRAME)/over
 →((≢buf)<4+len)/save
 frames←frames,⊂len↑4↓buf
 buf←(4+len)↓buf
 →lp
 over:gRxBuf[idx]←⊂⍬
 Z←frames 1 ⋄ →0
 save:gRxBuf[idx]←⊂buf
 Z←frames 0 ⋄ →0
 none:Z←(⍬)0
∇

⍝ ── §6.11 request_id demux table ──
∇Z←PendIndex rid;i
 Z←0 ⋄ i←0
 lp:→(i≥≢gPendRid)/0
 i←i+1 ⋄ →(~(i⊃gPendRid)≡rid)/lp
 Z←i ⋄ →0
∇

⍝ register interest in a request_id BEFORE sending it, so an early reply is captured.
∇TrPendRegister rid;idx
 idx←PendIndex rid
 →(idx>0)/have
 gPendRid←gPendRid,⊂rid ⋄ gPendPay←gPendPay,⊂⍬ ⋄ gPendDone←gPendDone,0 ⋄ →0
 have:gPendDone[idx]←0
∇

∇rid TrPendDeliver payload;idx
 idx←PendIndex rid
 →(idx=0)/0                              ⍝ not registered: drop (unexpected reply)
 gPendPay[idx]←⊂payload ⋄ gPendDone[idx]←1
∇

∇Z←TrPendDone rid;idx
 Z←0
 idx←PendIndex rid
 →(idx=0)/0
 Z←idx⊃gPendDone
∇

⍝ take + clear the delivered payload -> (payload found).
∇Z←TrPendTake rid;idx
 Z←(⍬)0
 idx←PendIndex rid
 →(idx=0)/0
 →(0=idx⊃gPendDone)/0
 Z←(idx⊃gPendPay)1
 gPendDone[idx]←0 ⋄ gPendPay[idx]←⊂⍬
∇
