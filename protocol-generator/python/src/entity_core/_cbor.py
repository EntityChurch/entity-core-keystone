"""Hand-rolled canonical CBOR / Entity Canonical Form (ECF) codec.

Authoritative spec: ``ENTITY-CBOR-ENCODING.md`` v1.5 (spec-data/v7.75).  No
Python CBOR library delivers the full ECF contract (length-then-lex map order
on ENCODED key bytes, shortest-float incl. f16, recursive major-type-6 tag
rejection on decode, full uint64/nint range, raw-byte ``data`` fidelity), so
the canonical layer is hand-rolled (profile A-PY-001).

Canonical rules implemented (RFC 8949 §4.2 / ECF §4.2.1):

  * Rule 1 — shortest integer head (0/1/2/4/8 extra bytes); enforced on decode.
  * Rule 3 — definite-length containers only; indefinite-length (0x5f/0x7f/
    0x9f/0xbf) rejected on decode.
  * Rule 4 — shortest float preserving value (f64 → f32 → f16 ladder), with a
    decode-side minimality check.
  * Rule 4a — canonical special floats: NaN→F9 7E00, ±Inf→F9 7C00/FC00,
    -0.0→F9 8000.
  * §4.2.1 deterministic map-key order: byte-wise lexicographic on the ENCODED
    key bytes (length-then-lex emerges naturally because the length lives in
    the head byte).
  * Rule 5 — duplicate map keys rejected on decode.
  * §6.3 — any CBOR tag (major type 6) at any depth rejected on decode
    (``400 non_canonical_ecf``).

Value model (mirrors the conformance value tree):
  None / bool / int / float / str (tstr) / bytes (bstr) / list / dict.
Byte-string MAP KEYS are carried as :class:`ByteKey` (a ``bytes`` subclass)
so they encode as major type 2; plain ``str`` keys encode as major type 3.
"""

from __future__ import annotations

import math
import struct
from typing import Any

from .errors import NonCanonicalEcfError, TruncatedError

# Major types.
_MT_UINT = 0
_MT_NINT = 1
_MT_BSTR = 2
_MT_TSTR = 3
_MT_ARRAY = 4
_MT_MAP = 5
_MT_TAG = 6
_MT_SIMPLE = 7

# Simple/float initial bytes.
_FALSE = 0xF4
_TRUE = 0xF5
_NULL = 0xF6
_UNDEFINED = 0xF7
_F16 = 0xF9
_F32 = 0xFA
_F64 = 0xFB


class ByteKey(bytes):
    """Marker for a byte-string map key (encodes as CBOR major type 2).

    A ``bytes`` subclass so it stays hashable and usable as a ``dict`` key,
    while remaining distinguishable from a ``str`` key (major type 3) at
    encode time.
    """

    __slots__ = ()


# ─────────────────────────────────────────────────────────────────────────────
# Encode
# ─────────────────────────────────────────────────────────────────────────────
def _encode_head(major: int, arg: int) -> bytes:
    """Emit a CBOR initial byte + the SHORTEST argument bytes (Rule 1)."""
    head = major << 5
    if arg < 24:
        return bytes([head | arg])
    if arg < 0x100:
        return bytes([head | 24, arg])
    if arg < 0x10000:
        return bytes([head | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([head | 26]) + arg.to_bytes(4, "big")
    if arg < 0x10000000000000000:
        return bytes([head | 27]) + arg.to_bytes(8, "big")
    raise ValueError(f"argument {arg} exceeds 64-bit head form")


def _encode_int(value: int) -> bytes:
    if value >= 0:
        if value >= 0x10000000000000000:
            raise ValueError(f"uint {value} exceeds 2**64-1 (out of CBOR head range)")
        return _encode_head(_MT_UINT, value)
    # Negative: major type 1, argument = -1 - value.
    arg = -1 - value
    if arg >= 0x10000000000000000:
        raise ValueError(f"nint {value} exceeds -2**64 (out of CBOR head range)")
    return _encode_head(_MT_NINT, arg)


def _encode_float(value: float) -> bytes:
    """Rule 4 / 4a: shortest float preserving exact value (f16 → f32 → f64)."""
    # Specials canonicalise to f16 (Rule 4a).
    if value != value:  # NaN
        return bytes([_F16, 0x7E, 0x00])
    if value == math.inf:
        return bytes([_F16, 0x7C, 0x00])
    if value == -math.inf:
        return bytes([_F16, 0xFC, 0x00])

    # Try f16 if it round-trips exactly (covers ±0.0 via the bit pattern check).
    h = _try_pack_f16(value)
    if h is not None:
        return bytes([_F16]) + h

    # Try f32 if it round-trips exactly.
    f32 = struct.pack(">f", value)
    if struct.unpack(">f", f32)[0] == value:
        return bytes([_F32]) + f32

    # Fall back to f64.
    return bytes([_F64]) + struct.pack(">d", value)


def _try_pack_f16(value: float) -> bytes | None:
    """Return the 2-byte half-precision encoding iff it represents ``value``
    exactly (bit-exact, so -0.0 is preserved); else ``None``."""
    f16 = _float_to_half_bits(value)
    if f16 is None:
        return None
    packed = struct.pack(">H", f16)
    # Verify exact round-trip including sign of zero.
    back = _half_bits_to_float(f16)
    if back == value and math.copysign(1.0, back) == math.copysign(1.0, value):
        return packed
    return None


def _float_to_half_bits(value: float) -> int | None:
    """IEEE 754 binary16 bit pattern for ``value`` if exactly representable
    as a (normal or subnormal) half, else ``None``.  Specials handled by the
    caller."""
    # Decompose the double.
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    sign = (bits >> 63) & 0x1
    exp = (bits >> 52) & 0x7FF
    mant = bits & 0xFFFFFFFFFFFFF

    if exp == 0 and mant == 0:
        # ±0.0
        return sign << 15

    # Unbiased exponent of the double.
    e = exp - 1023
    # Half-precision normal range: exponent in [-14, 15].
    if e > 15:
        return None  # too large for half

    if e >= -14:
        # Candidate normal half. Need the low 42 mantissa bits to be zero
        # (half keeps 10 mantissa bits; double has 52).
        if mant & ((1 << 42) - 1):
            return None
        half_mant = mant >> 42
        half_exp = e + 15
        return (sign << 15) | (half_exp << 10) | half_mant

    # Subnormal half: value = ±(implicit-1.mant) * 2**e, e < -14.
    # Smallest subnormal half = 2**-24. Represent as integer multiple.
    if e < -24:
        return None
    full_mant = (1 << 52) | mant  # the implicit leading 1 + 52 fraction bits
    # Half subnormal mantissa = full significand shifted so the value becomes
    # m * 2**-24. value = full_mant * 2**(e-52); want m * 2**-24.
    shift = (e - 52) + 24  # = e - 28
    if shift > 0:
        return None  # would need fractional half-mantissa bit
    drop = -shift
    if full_mant & ((1 << drop) - 1):
        return None  # not exactly representable (lost bits)
    half_mant = full_mant >> drop
    if half_mant > 0x3FF:
        return None
    return (sign << 15) | half_mant


def _half_bits_to_float(h: int) -> float:
    """Decode a binary16 bit pattern to a Python float (exact)."""
    sign = -1.0 if (h >> 15) & 0x1 else 1.0
    exp = (h >> 10) & 0x1F
    mant = h & 0x3FF
    if exp == 0:
        if mant == 0:
            return sign * 0.0
        return sign * (mant / 1024.0) * (2.0 ** -14)
    if exp == 0x1F:
        return sign * math.inf if mant == 0 else math.nan
    return sign * (1.0 + mant / 1024.0) * (2.0 ** (exp - 15))


def _encode_key(key: Any) -> bytes:
    if isinstance(key, ByteKey):
        return _encode_head(_MT_BSTR, len(key)) + bytes(key)
    if isinstance(key, str):
        kb = key.encode("utf-8")
        return _encode_head(_MT_TSTR, len(kb)) + kb
    if isinstance(key, bool):
        return bytes([_TRUE if key else _FALSE])
    if isinstance(key, int):
        return _encode_int(key)
    raise ValueError(f"unsupported map key type: {type(key).__name__}")


def encode(value: Any) -> bytes:
    """Encode a value tree to canonical ECF bytes."""
    out = bytearray()
    _encode_into(value, out)
    return bytes(out)


def _encode_into(value: Any, out: bytearray) -> None:
    # bool MUST precede int (bool is an int subclass in Python).
    if value is None:
        out.append(_NULL)
    elif isinstance(value, bool):
        out.append(_TRUE if value else _FALSE)
    elif isinstance(value, int):
        out.extend(_encode_int(value))
    elif isinstance(value, float):
        out.extend(_encode_float(value))
    elif isinstance(value, str):
        b = value.encode("utf-8")
        out.extend(_encode_head(_MT_TSTR, len(b)))
        out.extend(b)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        out.extend(_encode_head(_MT_BSTR, len(b)))
        out.extend(b)
    elif isinstance(value, (list, tuple)):
        out.extend(_encode_head(_MT_ARRAY, len(value)))
        for item in value:
            _encode_into(item, out)
    elif isinstance(value, dict):
        _encode_map_into(value, out)
    else:
        raise ValueError(f"cannot ECF-encode value of type {type(value).__name__}")


def _encode_map_into(m: dict, out: bytearray) -> None:
    pairs = []
    seen: set[bytes] = set()
    for k, v in m.items():
        kb = _encode_key(k)
        if kb in seen:
            raise NonCanonicalEcfError("duplicate map key")
        seen.add(kb)
        vb = encode(v)
        pairs.append((kb, vb))
    # Canonical order: byte-wise lexicographic on encoded key bytes
    # (length-then-lex emerges because the length is in the head byte).
    pairs.sort(key=lambda p: p[0])
    out.extend(_encode_head(_MT_MAP, len(pairs)))
    for kb, vb in pairs:
        out.extend(kb)
        out.extend(vb)


# ─────────────────────────────────────────────────────────────────────────────
# Decode (strict ECF)
# ─────────────────────────────────────────────────────────────────────────────
class _Decoder:
    __slots__ = ("buf", "pos", "n")

    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0
        self.n = len(buf)

    def _need(self, k: int) -> None:
        if self.pos + k > self.n:
            raise TruncatedError("unexpected end of input")

    def _read(self, k: int) -> bytes:
        self._need(k)
        b = self.buf[self.pos : self.pos + k]
        self.pos += k
        return b

    def _read_argument(self, info: int) -> int:
        """Read the head argument, enforcing shortest-form (Rule 1)."""
        if info < 24:
            return info
        if info == 24:
            v = self._read(1)[0]
            if v < 24:
                raise NonCanonicalEcfError("non-minimal integer head (1-byte)")
            return v
        if info == 25:
            v = int.from_bytes(self._read(2), "big")
            if v < 0x100:
                raise NonCanonicalEcfError("non-minimal integer head (2-byte)")
            return v
        if info == 26:
            v = int.from_bytes(self._read(4), "big")
            if v < 0x10000:
                raise NonCanonicalEcfError("non-minimal integer head (4-byte)")
            return v
        if info == 27:
            v = int.from_bytes(self._read(8), "big")
            if v < 0x100000000:
                raise NonCanonicalEcfError("non-minimal integer head (8-byte)")
            return v
        # 28..30 reserved; 31 = indefinite-length.
        if info == 31:
            raise NonCanonicalEcfError("indefinite-length item forbidden in ECF")
        raise NonCanonicalEcfError(f"reserved additional-info value {info}")

    def decode(self) -> Any:
        v = self._decode_value()
        if self.pos != self.n:
            raise NonCanonicalEcfError("trailing bytes after top-level item")
        return v

    def _decode_value(self) -> Any:
        self._need(1)
        ib = self.buf[self.pos]
        self.pos += 1
        major = ib >> 5
        info = ib & 0x1F

        if major == _MT_UINT:
            return self._read_argument(info)
        if major == _MT_NINT:
            return -1 - self._read_argument(info)
        if major == _MT_BSTR:
            if info == 31:
                raise NonCanonicalEcfError("indefinite-length byte string forbidden")
            length = self._read_argument(info)
            return self._read(length)
        if major == _MT_TSTR:
            if info == 31:
                raise NonCanonicalEcfError("indefinite-length text string forbidden")
            length = self._read_argument(info)
            raw = self._read(length)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise NonCanonicalEcfError(f"invalid UTF-8 in text string: {e}") from e
        if major == _MT_ARRAY:
            if info == 31:
                raise NonCanonicalEcfError("indefinite-length array forbidden")
            length = self._read_argument(info)
            return [self._decode_value() for _ in range(length)]
        if major == _MT_MAP:
            if info == 31:
                raise NonCanonicalEcfError("indefinite-length map forbidden")
            length = self._read_argument(info)
            return self._decode_map(length)
        if major == _MT_TAG:
            # §6.3: any CBOR tag (major type 6) at any depth is rejected.
            raise NonCanonicalEcfError("CBOR tag (major type 6) forbidden in ECF (non_canonical_ecf)")
        # major == 7: simple values + floats.
        return self._decode_simple(info)

    def _decode_map(self, length: int) -> dict:
        out: dict = {}
        prev_key_bytes: bytes | None = None
        for _ in range(length):
            key_start = self.pos
            key = self._decode_key()
            key_bytes = self.buf[key_start : self.pos]
            # Rule 5: no duplicate keys.
            if key in out:
                raise NonCanonicalEcfError("duplicate map key")
            # §4.2.1 ordering enforced on decode: strictly ascending encoded keys.
            if prev_key_bytes is not None and key_bytes <= prev_key_bytes:
                raise NonCanonicalEcfError("map keys not in canonical order")
            prev_key_bytes = key_bytes
            out[key] = self._decode_value()
        return out

    def _decode_key(self) -> Any:
        self._need(1)
        ib = self.buf[self.pos]
        major = ib >> 5
        if major == _MT_BSTR:
            v = self._decode_value()
            return ByteKey(v)
        # str / int / bool keys decode via the value path.
        return self._decode_value()

    def _decode_simple(self, info: int) -> Any:
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info == 23:
            raise NonCanonicalEcfError("'undefined' (0xf7) not used in ECF")
        if info == 25:  # f16
            return self._decode_f16()
        if info == 26:  # f32
            return self._decode_f32()
        if info == 27:  # f64
            return self._decode_f64()
        if info == 31:
            raise NonCanonicalEcfError("indefinite-length 'break' forbidden")
        raise NonCanonicalEcfError(f"unsupported simple value (info {info})")

    def _decode_f16(self) -> float:
        bits = int.from_bytes(self._read(2), "big")
        return _half_bits_to_float(bits)

    def _decode_f32(self) -> float:
        raw = self._read(4)
        value = struct.unpack(">f", raw)[0]
        # Rule 4 on decode: a value that fits exactly in f16 must have used f16.
        if value == value and value not in (math.inf, -math.inf):
            if _float_to_half_bits(value) is not None and _try_pack_f16(value) is not None:
                raise NonCanonicalEcfError("non-minimal float: f32 used where f16 suffices")
        return value

    def _decode_f64(self) -> float:
        raw = self._read(8)
        value = struct.unpack(">d", raw)[0]
        # Rule 4 on decode: reject if a shorter float preserves the value.
        if value == value and value not in (math.inf, -math.inf):
            if _try_pack_f16(value) is not None:
                raise NonCanonicalEcfError("non-minimal float: f64 used where f16 suffices")
            f32 = struct.pack(">f", value)
            if struct.unpack(">f", f32)[0] == value:
                raise NonCanonicalEcfError("non-minimal float: f64 used where f32 suffices")
        return value


def decode(buf: bytes) -> Any:
    """Strictly decode canonical ECF bytes to a value tree.

    Raises :class:`NonCanonicalEcfError` for any non-canonical input (tags,
    indefinite-length, non-minimal int/float head, mis-ordered/duplicate map
    keys) and :class:`TruncatedError` on a short read.
    """
    return _Decoder(bytes(buf)).decode()
