/* entity-core-protocol-rexx — canonical CBOR (ECF) codec, pure Rexx.
 *
 * THE DECIMAL-NUMBER-MODEL PROBE (A-RX-002). Rexx has NO binary numeric type: values
 * are strings, arithmetic is arbitrary-precision DECIMAL (NUMERIC DIGITS 200 here),
 * and there is no IEEE float type nor any built-in to read/write IEEE bits. The
 * integer tower is native and clean (D2C(n,len) is big-endian, C2D is exact); the
 * FLOAT tower is hand-computed entirely in decimal arithmetic + D2C/C2D — the deepest
 * hand-roll in the cohort. Crucially the codec ROUND-TRIP stays in IEEE-bit-space: a
 * decoded float is stored as its 8-byte f64 pattern (widened from f16/f32 on decode);
 * encode narrows back down the shortest-float ladder. No decimal<->IEEE conversion is
 * needed for conformance — only bit re-layout, done with `%` (integer divide = shift
 * right), `//` (remainder = mask), and `* 2**k` (shift left).
 *
 * INTERNAL TAGGED-VALUE REP (EIAS-aligned: a decoded value is itself a self-
 * delimiting byte string; LEN = D2C(n,4) big-endian):
 *   'i' LEN <decimal-ascii>     int (mt0/1; sign in the ascii, Rexx bignum)
 *   'b' LEN <raw bytes>         byte string (mt2)
 *   't' LEN <utf-8 bytes>       text string (mt3; Regina is byte-oriented, LEN=bytes)
 *   'f' LEN <8-byte f64 BE>     float (mt7; ALWAYS the f64 rep internally)
 *   'a' LEN <child TVs...>      array (mt4; LEN = element count)
 *   'm' LEN <(k,v) TVs...>      map   (mt5; LEN = pair count)
 *   'R' 'F' 'N' 'U'             true / false / null / undef (mt7 simple, no payload)
 *   's' LEN <1 byte>            simple value (mt7)
 *
 * Canonical rules (ENTITY-CBOR-ENCODING v1.5, invariants N1-N3): minimal int/length
 * heads, length-then-lex map-key ordering on ENCODED key bytes (§4.2.1), shortest-
 * float ladder f16->f32->f64 (Rule 4) + canonical NaN 0x7e00, recursive major-type-6
 * tag REJECTION on decode (N2), full-consume (no trailing) + minimal-head re-validate.
 */

/* ===================== ENCODE ===================== */

Cbor_Encode: procedure expose EC.
  parse arg tv
  numeric digits 200
  EC.!OK = 1
  EC.!WTV = tv; EC.!WPOS = 1
  return _enc_node()

_tv_tag: procedure expose EC.
  ch = substr(EC.!WTV, EC.!WPOS, 1); EC.!WPOS = EC.!WPOS + 1; return ch
_tv_len: procedure expose EC.
  n = c2d(substr(EC.!WTV, EC.!WPOS, 4)); EC.!WPOS = EC.!WPOS + 4; return n
_tv_take: procedure expose EC.
  parse arg n
  s = substr(EC.!WTV, EC.!WPOS, n); EC.!WPOS = EC.!WPOS + n; return s

/* CBOR head: major<<5 | minimal-argument. */
_emit_head: procedure
  parse arg major, arg
  numeric digits 200
  ib = major * 32
  if arg <= 23 then return d2c(ib + arg)
  else if arg <= 255 then return d2c(ib + 24) || d2c(arg, 1)
  else if arg <= 65535 then return d2c(ib + 25) || d2c(arg, 2)
  else if arg <= 4294967295 then return d2c(ib + 26) || d2c(arg, 4)
  else return d2c(ib + 27) || d2c(arg, 8)

_enc_node: procedure expose EC.
  numeric digits 200
  tag = _tv_tag()
  select
    when tag == 'i' then do
      n = _tv_take(_tv_len())
      if n >= 0 then return _emit_head(0, n)
      else return _emit_head(1, -1 - n)
    end
    when tag == 'b' then do
      b = _tv_take(_tv_len())
      return _emit_head(2, length(b)) || b
    end
    when tag == 't' then do
      s = _tv_take(_tv_len())
      return _emit_head(3, length(s)) || s
    end
    when tag == 'a' then do
      n = _tv_len()
      out = _emit_head(4, n)
      do i = 1 to n; out = out || _enc_node(); end
      return out
    end
    when tag == 'm' then return _enc_map()
    when tag == 'f' then do
      f64 = _tv_take(_tv_len())
      return _enc_float(f64)
    end
    when tag == 'R' then return 'f5'x
    when tag == 'F' then return 'f4'x
    when tag == 'N' then return 'f6'x
    when tag == 'U' then return 'f7'x
    when tag == 's' then do
      v = c2d(_tv_take(_tv_len()))
      if v < 24 then return d2c(224 + v)
      else return 'f8'x || d2c(v, 1)
    end
    otherwise call Reject 'NON_CANONICAL_ECF', 'unknown TV tag ' || c2x(tag)
  end

/* canonical map: sort entries by ENCODED KEY bytes, length-then-lex (§4.2.1). */
_enc_map: procedure expose EC.
  numeric digits 200
  n = _tv_len()
  do i = 1 to n
    keys.i = _enc_node()        /* encode key TV -> wire bytes */
    vals.i = _enc_node()        /* encode val TV -> wire bytes */
    idx.i = i
  end
  /* insertion sort the indices by Keycmp(keys.a, keys.b). Rexx forbids an EXPRESSION
     subscript (idx.(j-1)); compute the tail into a plain variable first. */
  do i = 2 to n
    j = i
    do while j > 1
      jm = j - 1
      a = idx.j; b = idx.jm
      if Keycmp(keys.a, keys.b) < 0 then do
        idx.j = b; idx.jm = a; j = jm
      end
      else leave
    end
  end
  out = _emit_head(5, n)
  do i = 1 to n
    k = idx.i
    out = out || keys.k || vals.k
  end
  return out

/* shortest-float ladder over the 8-byte f64 rep: try f16, then f32, else f64. */
_enc_float: procedure expose EC.
  numeric digits 200
  parse arg f64
  bits = c2d(f64)
  exp = (bits % (2**52)) // (2**11)
  mant = bits // (2**52)
  sign = bits % (2**63)
  if exp == 2047 then do
    if mant == 0 then do
      if sign == 1 then return 'f9'x || 'fc00'x    /* -Inf */
      else return 'f9'x || '7c00'x                 /* +Inf */
    end
    return 'f9'x || '7e00'x                          /* canonical NaN */
  end
  half = _f64bits_to_f16(bits)
  if half \== '' then return 'f9'x || d2c(half, 2)
  f32 = _f64bits_to_f32(bits)
  if f32 \== '' then return 'fa'x || d2c(f32, 4)
  return 'fb'x || f64

/* ===================== DECODE ===================== */

Cbor_Decode: procedure expose EC.
  parse arg bytes
  numeric digits 200
  EC.!OK = 1
  EC.!DBYTES = bytes; EC.!DPOS = 1
  tv = _dec_node()
  if \EC.!OK then return ''
  if EC.!DPOS \= length(bytes) + 1 then do; call Reject 'TRUNCATED_INPUT', 'trailing data'; return ''; end
  return tv

_dbyte: procedure expose EC.
  if EC.!DPOS > length(EC.!DBYTES) then do; call Reject 'TRUNCATED_INPUT', 'read past end'; return 0; end
  v = c2d(substr(EC.!DBYTES, EC.!DPOS, 1)); EC.!DPOS = EC.!DPOS + 1; return v
_dtake: procedure expose EC.
  parse arg n
  if n < 0 | EC.!DPOS + n - 1 > length(EC.!DBYTES) then do; call Reject 'TRUNCATED_INPUT', 'read past end'; return ''; end
  s = substr(EC.!DBYTES, EC.!DPOS, n); EC.!DPOS = EC.!DPOS + n; return s

/* read a head; return "major arg" with minimal-argument enforcement. */
_dhead: procedure expose EC.
  numeric digits 200
  ib = _dbyte()
  if \EC.!OK then return '0 0'
  major = ib % 32
  ai = ib // 32
  if ai < 24 then return major ai
  else if ai == 24 then do
    v = _dbyte()
    if \EC.!OK then return '0 0'
    if v < 24 then do; call Reject 'NON_CANONICAL_ECF', 'non-minimal 1-byte arg'; return '0 0'; end
    return major v
  end
  else if ai == 25 then do
    s = _dtake(2); if \EC.!OK then return '0 0'
    v = c2d(s)
    if v <= 255 then do; call Reject 'NON_CANONICAL_ECF', 'non-minimal 2-byte arg'; return '0 0'; end
    return major v
  end
  else if ai == 26 then do
    s = _dtake(4); if \EC.!OK then return '0 0'
    v = c2d(s)
    if v <= 65535 then do; call Reject 'NON_CANONICAL_ECF', 'non-minimal 4-byte arg'; return '0 0'; end
    return major v
  end
  else if ai == 27 then do
    s = _dtake(8); if \EC.!OK then return '0 0'
    v = c2d(s)
    if v <= 4294967295 then do; call Reject 'NON_CANONICAL_ECF', 'non-minimal 8-byte arg'; return '0 0'; end
    return major v
  end
  else do; call Reject 'NON_CANONICAL_ECF', 'reserved additional-info'; return '0 0'; end

_dec_node: procedure expose EC.
  numeric digits 200
  if \EC.!OK then return ''
  if EC.!DPOS > length(EC.!DBYTES) then do; call Reject 'TRUNCATED_INPUT', 'read past end'; return ''; end
  ib0 = c2d(substr(EC.!DBYTES, EC.!DPOS, 1))
  major0 = ib0 % 32
  if major0 == 6 then do; call Reject 'TAG_REJECTED', 'major-type-6 tag not permitted in ECF'; return ''; end
  if major0 == 7 then return _dec_simple()
  parse value _dhead() with major arg
  if \EC.!OK then return ''
  select
    when major == 0 then return 'i' || d2c(length(arg), 4) || arg
    when major == 1 then do
      nv = -1 - arg
      return 'i' || d2c(length(nv), 4) || nv
    end
    when major == 2 then do
      b = _dtake(arg); if \EC.!OK then return ''
      return 'b' || d2c(length(b), 4) || b
    end
    when major == 3 then do
      s = _dtake(arg); if \EC.!OK then return ''
      return 't' || d2c(length(s), 4) || s
    end
    when major == 4 then do
      out = 'a' || d2c(arg, 4)
      do i = 1 to arg
        out = out || _dec_node()
        if \EC.!OK then return ''
      end
      return out
    end
    when major == 5 then do
      kv = ''; prevkb = ''
      do i = 1 to arg
        kstart = EC.!DPOS
        ktv = _dec_node()
        if \EC.!OK then return ''
        kb = substr(EC.!DBYTES, kstart, EC.!DPOS - kstart)
        if i > 1 then if Keycmp(prevkb, kb) >= 0 then do; call Reject 'NON_CANONICAL_ECF', 'map keys not in canonical order'; return ''; end
        prevkb = kb
        vtv = _dec_node()
        if \EC.!OK then return ''
        kv = kv || ktv || vtv
      end
      return 'm' || d2c(arg, 4) || kv
    end
    otherwise do; call Reject 'NON_CANONICAL_ECF', 'unexpected major ' || major; return ''; end
  end

_dec_simple: procedure expose EC.
  numeric digits 200
  ib = _dbyte()
  if \EC.!OK then return ''
  ai = ib // 32
  select
    when ai == 20 then return 'F'
    when ai == 21 then return 'R'
    when ai == 22 then return 'N'
    when ai == 23 then return 'U'
    when ai == 24 then do
      v = _dbyte(); if \EC.!OK then return ''
      if v < 32 then do; call Reject 'NON_CANONICAL_ECF', 'simple value < 32 must be 1-byte form'; return ''; end
      return 's' || d2c(1, 4) || d2c(v, 1)
    end
    when ai == 25 then return _dec_f16()
    when ai == 26 then return _dec_f32()
    when ai == 27 then return _dec_f64()
    otherwise do
      if ai < 20 then return 's' || d2c(1, 4) || d2c(ai, 1)
      call Reject 'NON_CANONICAL_ECF', 'reserved simple/float additional-info'; return ''
    end
  end

_dec_f16: procedure expose EC.
  s = _dtake(2); if \EC.!OK then return ''
  bits = _f16bits_to_f64bits(c2d(s))
  return 'f' || d2c(8, 4) || d2c(bits, 8)
_dec_f32: procedure expose EC.
  s = _dtake(4); if \EC.!OK then return ''
  bits = _f32bits_to_f64bits(c2d(s))
  if _would_be_f16(bits) then do; call Reject 'NON_CANONICAL_ECF', 'float not shortest (f32 fits f16)'; return ''; end
  return 'f' || d2c(8, 4) || d2c(bits, 8)
_dec_f64: procedure expose EC.
  s = _dtake(8); if \EC.!OK then return ''
  bits = c2d(s)
  if _would_be_f16(bits) | _would_be_f32(bits) then do; call Reject 'NON_CANONICAL_ECF', 'float not shortest (f64 fits narrower)'; return ''; end
  return 'f' || d2c(8, 4) || d2c(bits, 8)

/* ===================== IEEE bit re-layout (all decimal arithmetic) ===================== */

/* f64 bit pattern -> f16 bit pattern, or '' if not exactly representable. */
_f64bits_to_f16: procedure
  parse arg bits
  numeric digits 200
  sign = bits % (2**63)
  exp  = (bits % (2**52)) // (2**11)
  mant = bits // (2**52)
  if exp == 0 then do
    if mant == 0 then return sign * (2**15)
    return ''
  end
  if exp == 2047 then return ''
  unbiased = exp - 1023
  if unbiased > 15 then return ''
  if unbiased >= -14 then do
    if mant // (2**42) \= 0 then return ''
    m10 = mant % (2**42)
    e5 = unbiased + 15
    return sign * (2**15) + e5 * (2**10) + m10
  end
  if unbiased >= -24 then do
    full = (2**52) + mant
    shift = 42 + (-14 - unbiased)
    if full // (2**shift) \= 0 then return ''
    m = full % (2**shift)
    return sign * (2**15) + m
  end
  return ''

_f16bits_to_f64bits: procedure
  parse arg h
  numeric digits 200
  sign = h % (2**15)
  exp  = (h % (2**10)) // (2**5)
  mant = h // (2**10)
  if exp == 0 then do
    if mant == 0 then return sign * (2**63)
    e = -14
    do while mant < 1024; mant = mant * 2; e = e - 1; end
    mant = mant // (2**10)
    exp64 = e + 1023
    return sign * (2**63) + exp64 * (2**52) + mant * (2**42)
  end
  else if exp == 31 then return sign * (2**63) + 2047 * (2**52) + mant * (2**42)
  exp64 = exp - 15 + 1023
  return sign * (2**63) + exp64 * (2**52) + mant * (2**42)

/* f64 -> f32 bit pattern, or '' if not exactly representable. */
_f64bits_to_f32: procedure
  parse arg bits
  numeric digits 200
  sign = bits % (2**63)
  exp  = (bits % (2**52)) // (2**11)
  mant = bits // (2**52)
  if exp == 0 then do
    if mant == 0 then return sign * (2**31)
    return ''
  end
  if exp == 2047 then return ''
  unbiased = exp - 1023
  if unbiased > 127 then return ''
  if unbiased >= -126 then do
    if mant // (2**29) \= 0 then return ''
    m23 = mant % (2**29)
    e8 = unbiased + 127
    return sign * (2**31) + e8 * (2**23) + m23
  end
  if unbiased >= -149 then do
    full = (2**52) + mant
    shift = 29 + (-126 - unbiased)
    if full // (2**shift) \= 0 then return ''
    m = full % (2**shift)
    return sign * (2**31) + m
  end
  return ''

_f32bits_to_f64bits: procedure
  parse arg f32
  numeric digits 200
  sign = f32 % (2**31)
  exp  = (f32 % (2**23)) // (2**8)
  mant = f32 // (2**23)
  if exp == 0 then do
    if mant == 0 then return sign * (2**63)
    e = -126
    do while mant < (2**23); mant = mant * 2; e = e - 1; end
    mant = mant // (2**23)
    exp64 = e + 1023
    return sign * (2**63) + exp64 * (2**52) + mant * (2**29)
  end
  else if exp == 255 then return sign * (2**63) + 2047 * (2**52) + mant * (2**29)
  exp64 = exp - 127 + 1023
  return sign * (2**63) + exp64 * (2**52) + mant * (2**29)

_would_be_f16: procedure
  parse arg bits
  numeric digits 200
  exp = (bits % (2**52)) // (2**11)
  if exp == 2047 then return 1
  return (_f64bits_to_f16(bits) \== '')

_would_be_f32: procedure
  parse arg bits
  numeric digits 200
  exp = (bits % (2**52)) // (2**11)
  if exp == 2047 then return 1
  return (_f64bits_to_f32(bits) \== '')
