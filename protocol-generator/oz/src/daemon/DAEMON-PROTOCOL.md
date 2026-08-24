# entity-codec-daemon — the co-process seam convention (v1)

The reusable convention for a peer whose substrate can neither link C (no FFI
surface) nor do crypto natively, but CAN spawn a child process and speak to it
byte-cleanly over pipes. First carried by Rexx (`ecnet`, over FIFOs, hex-armored);
this document is the *convention* write-up the Oz build was asked to produce
("design once, document as the entity-codec-daemon convention").

## Shape

One long-lived C co-process per peer process, linking `libentitycore_codec`
(the codec C-ABI — `ffi-generator/c-abi/spec/`). The peer spawns it at boot
(Oz: `Open.pipe`), talks over the child's **stdin/stdout**, and the child exits
when its stdin closes. stderr is diagnostics only.

The daemon owns **crypto + wall-clock + entropy — nothing else**. In particular
it owns NO sockets (that was `ecnet`'s Regina-specific burden; a substrate that
can listen natively MUST keep its own transport, or the paradigm probe forfeits
its axis) and does NO CBOR (a peer that can hand-roll canonical ECF natively
must — that's where the findings come from).

## Framing (binary, length-prefixed — v1)

Regina needed hex-over-FIFO armor because its FIFO line reads lose bytes
(A-RX-011). A byte-exact pipe (proven at Oz S1 incl 0x00/0xFF) needs no armor:

```
request  = op:u8 ‖ len:u32be ‖ payload[len]
response = status:u8 ‖ len:u32be ‖ payload[len]     status: 0=OK, 1=ERR
```

Strictly one response per request, in request order. The channel is a shared
serial resource: the peer serializes access (Oz: a port agent owns the pipe;
each caller's request carries a dataflow variable the agent binds).

## Op vocabulary (v1) — ecnet's crypto subset, plus Ed448

| op | name | request payload | OK response payload |
|----|------|-----------------|---------------------|
| 0x01 | SHA256 | msg | 32-byte digest |
| 0x02 | SHA384 | msg | 48-byte digest |
| 0x03 | ED25519_PUB | seed(32) | pub(32) |
| 0x04 | ED25519_SIGN | seed(32) ‖ msg | sig(64) |
| 0x05 | ED25519_VERIFY | pub(32) ‖ sig(64) ‖ msg | 1 byte: 1=valid, 0=invalid |
| 0x06 | ED448_PUB | seed(57) | pub(57) |
| 0x07 | ED448_SIGN | seed(57) ‖ msg | sig(114) |
| 0x08 | ED448_VERIFY | pub(57) ‖ sig(114) ‖ msg | 1 byte: 1=valid, 0=invalid |
| 0x10 | NOW | (empty) | 8-byte BE unix milliseconds |
| 0x11 | RND | n:u16be | n random bytes (n ≤ 4096) |

ERR responses carry a short ASCII reason. An unknown op is an ERR, not a crash.
NOW is served from `clock_gettime(CLOCK_REALTIME)` in **milliseconds** — on a
content-addressed protocol, mint-timestamp precision is a correctness parameter
(A-PD-016), so the daemon, not the substrate's coarse clock, is the time source.

## Versioning

Op codes are append-only; framing changes bump to a v2 doc. A consumer MUST
treat an ERR for a known op as "unsupported here" (mirrors the C-ABI's
validated-not-required Ed448 stance).
