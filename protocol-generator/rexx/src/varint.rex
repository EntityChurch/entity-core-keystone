/* entity-core-protocol-rexx — unsigned LEB128 varint (multicodec key/hash/format
 * codes). N1: route all format-code / key-type / hash-type framing through a real
 * varint, never fixed bytes (a code >= 0x80 must widen — peer_id.3 / content_hash.4
 * test this). Pure Rexx over D2C/C2D + BITAND.
 */

/* Varint_Encode: whole number -> byte string (unsigned LEB128). */
Varint_Encode: procedure expose EC.
  parse arg n
  numeric digits 200
  if n < 0 then call Reject 'BAD_VARINT', 'negative'
  out = ''
  do forever
    low7 = n // 128            /* remainder = low 7 bits */
    n = n % 128                /* integer divide = >> 7 */
    if n \= 0 then out = out || d2c(low7 + 128)
    else do; out = out || d2c(low7); leave; end
  end
  return out

/* Varint_Decode: (bytes, startpos) -> value; leaves the position AFTER the varint in
 * the exposed global EC.!VPOS (1-indexed). Rejects a truncated or non-minimal form. */
Varint_Decode: procedure expose EC.
  parse arg s, start
  numeric digits 200
  EC.!VPOS = start
  shift = 0; result = 0; nb = 0
  do forever
    if EC.!VPOS > length(s) then call Reject 'BAD_VARINT', 'truncated'
    byte = substr(s, EC.!VPOS, 1); EC.!VPOS = EC.!VPOS + 1; nb = nb + 1
    low7 = c2d(bitand(byte, '7f'x))
    result = result + low7 * (2 ** shift)
    if bitand(byte, '80'x) == '00'x then do
      if nb > 1 & byte == '00'x then call Reject 'BAD_VARINT', 'non_minimal'
      leave
    end
    shift = shift + 7
  end
  return result
