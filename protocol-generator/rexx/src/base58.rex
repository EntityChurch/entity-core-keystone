/* entity-core-protocol-rexx — Base58 (Bitcoin alphabet), pure Rexx.
 * Uses Rexx's native arbitrary-precision DECIMAL arithmetic (NUMERIC DIGITS 200) for
 * the big-endian base-256 <-> base-58 conversion — no fixed-width limit. Leading zero
 * bytes map to leading '1's. C2D turns big-endian bytes into a decimal bignum.
 */

/* Base58_Encode: byte string -> base58 string. */
Base58_Encode: procedure expose EC.
  parse arg bytes
  numeric digits 200
  ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  if length(bytes) == 0 then return ''
  /* count leading zero bytes */
  nz = 0
  do i = 1 to length(bytes)
    if substr(bytes, i, 1) == '00'x then nz = nz + 1
    else leave
  end
  num = c2d(bytes)                 /* big-endian bytes -> decimal bignum */
  out = ''
  do while num > 0
    r = num // 58                  /* remainder */
    num = num % 58                 /* integer divide */
    out = substr(ALPHA, r + 1, 1) || out
  end
  return copies('1', nz) || out

/* Base58_Decode: base58 string -> byte string (rejects a non-alphabet char). */
Base58_Decode: procedure expose EC.
  parse arg s
  numeric digits 200
  ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  if length(s) == 0 then return ''
  nz = 0
  do i = 1 to length(s)
    if substr(s, i, 1) == '1' then nz = nz + 1
    else leave
  end
  num = 0
  do i = 1 to length(s)
    c = substr(s, i, 1)
    d = pos(c, ALPHA) - 1
    if d < 0 then call Reject 'BAD_BASE58', 'char'
    num = num * 58 + d
  end
  body = ''
  do while num > 0
    body = d2c(num // 256) || body
    num = num % 256
  end
  return copies('00'x, nz) || body
