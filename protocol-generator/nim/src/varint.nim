## Multicodec-style LEB128 varints (V8 §1.5 / §7.3 — NORMATIVE; invariant N1).
##
## format codes, key_type and hash_type are framed as LEB128 varints, NOT fixed
## bytes. Every currently-allocated code is < 0x80 (a single byte) so this is
## byte-identical to a fixed field today — the point is that a future code
## >= 0x80 extends to 2+ bytes and a fixed-width impl breaks silently. Corpus
## vectors content_hash.4 (format_code 128) and peer_id.3 (key_type 128) prove
## the multi-byte path.
##
## SPDX-License-Identifier: Apache-2.0

import ./errors

proc varintEncode*(dst: var seq[byte]; n: uint64) =
  ## Append the LEB128 encoding of `n` to `dst`.
  var v = n
  while true:
    let b = byte(v and 0x7f'u64)
    v = v shr 7
    if v == 0'u64:
      dst.add b
      break
    else:
      dst.add (b or 0x80'u8)

type VarintResult* = tuple[value: uint64, len: int]

proc varintDecode*(s: openArray[byte]; pos: int): VarintResult {.raises: [TruncatedInput].} =
  ## Decode one varint starting at `s[pos]`; returns value + bytes consumed.
  var
    acc: uint64 = 0
    shift = 0
    i = pos
  while true:
    if i >= s.len:
      raise newException(TruncatedInput, "varint runs off the end of the buffer")
    let b = s[i]
    acc = acc or (uint64(b and 0x7f'u8) shl shift)
    inc i
    if (b and 0x80'u8) == 0'u8:
      return (value: acc, len: i - pos)
    shift += 7
