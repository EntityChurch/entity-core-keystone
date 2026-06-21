import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';
import 'ecf_value.dart';

/// Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder + decoder.
///
/// Per ENTITY-CBOR-ENCODING.md v1.5 (spec-data v7.71/v7.75). No Dart CBOR
/// package gives ECF's guarantees (length-FIRST then byte-lexicographic map-key
/// ordering; the f16 shortest-float ladder; recursive major-type-6 tag
/// rejection; raw-byte fidelity), so the canonical layer is owned here. Authored
/// as an INDEPENDENT Dart reading of V7 (A-DART-001):
///  - minimal integer encoding (Rule 1) — full uint64 / -2^64 range via [BigInt]
///    (web-safe: a bare Dart `int` truncates to 53 bits under dart2js);
///  - map keys sorted by ENCODED LENGTH then byte-lexicographic (Rule 2 / §3.5);
///  - definite lengths only (Rule 3) — no 0x5f/0x7f/0x9f/0xbf;
///  - shortest float preserving value incl. f16 (Rule 4) + Rule-4a specials;
///  - recursive major-type-6 (tag) rejection on decode (invariant N2; §6.3);
///  - empty map = the single byte 0xA0 (invariant N3 — falls out of the generic
///    map encoder, not special-cased).
///
/// Public surface: [encode]/[decode] return an [EcfResult] (the Dart-3 sealed
/// Result). The recursive hot path throws an internal [EcfException] carrying the
/// sealed [EntityError]; the public wrappers translate it back into an [Err] — so
/// the THROW never escapes the codec, and callers match with an exhaustive
/// `switch`.
class Ecf {
  Ecf._();

  /// ECF §10.2 nesting depth limit.
  static const int maxDepth = 64;

  static final BigInt _maxU64 = BigInt.one << 64; // exclusive
  static final BigInt _byteMask = BigInt.from(0xff);

  // ───────────────────────────────────────────────────────────────────────────
  // Encode
  // ───────────────────────────────────────────────────────────────────────────

  /// Encode [value] to canonical ECF bytes (result-returning public surface).
  static EcfResult<Uint8List> encode(EcfValue value) {
    try {
      final out = BytesBuilder(copy: false);
      _enc(value, out);
      return Ok(out.takeBytes());
    } on EcfException catch (e) {
      return Err(e.error);
    }
  }

  /// Encode and unwrap — for internal callers that treat encode failures as bugs.
  static Uint8List encodeOrThrow(EcfValue value) {
    final out = BytesBuilder(copy: false);
    _enc(value, out);
    return out.takeBytes();
  }

  static void _enc(EcfValue value, BytesBuilder out) {
    switch (value) {
      case EcfFloatSpecial.nan:
        out.add(const [0xf9, 0x7e, 0x00]);
      case EcfFloatSpecial.positiveInfinity:
        out.add(const [0xf9, 0x7c, 0x00]);
      case EcfFloatSpecial.negativeInfinity:
        out.add(const [0xf9, 0xfc, 0x00]);
      case EcfFloatSpecial.negativeZero:
        out.add(const [0xf9, 0x80, 0x00]);
      case EcfBool.trueValue:
        out.addByte(0xf5);
      case EcfBool.falseValue:
        out.addByte(0xf4);
      case EcfNull():
        out.addByte(0xf6);
      case EcfInt(:final value):
        _encInt(value, out);
      case EcfFloat(:final value):
        _encFloat(value, out);
      case EcfBytes():
        final o = value.rawUnsafe;
        _encHead(2, BigInt.from(o.length), out);
        out.add(o);
      case EcfText(:final value):
        final o = utf8.encode(value);
        _encHead(3, BigInt.from(o.length), out);
        out.add(o);
      case EcfArray(:final items):
        _encHead(4, BigInt.from(items.length), out);
        for (final item in items) {
          _enc(item, out);
        }
      case EcfMap():
        _encMap(value, out);
    }
  }

  static void _encInt(BigInt v, BytesBuilder out) {
    if (v.sign >= 0) {
      _encHead(0, v, out);
    } else {
      // major 1, argument = -1 - v
      _encHead(1, -v - BigInt.one, out);
    }
  }

  /// Emit a CBOR initial byte for [major] with the SHORTEST argument for the
  /// non-negative [arg] (RFC 8949 §4.2.1 Rule 1). Operates over [BigInt] since
  /// the corpus + uncovered-range tests reach 2^64-1 (max uint64) and -2^64 (max
  /// nint argument) — the band a bare `int` truncates on web.
  static void _encHead(int major, BigInt arg, BytesBuilder out) {
    final m = major << 5;
    if (arg.isNegative || arg >= _maxU64) {
      throw EcfException(NonCanonicalEcf('argument out of uint64 range: $arg'));
    }
    if (arg < BigInt.from(24)) {
      out.addByte(m | arg.toInt());
    } else if (arg < BigInt.from(0x100)) {
      out.addByte(m | 24);
      out.addByte(arg.toInt() & 0xff);
    } else if (arg < BigInt.from(0x10000)) {
      out.addByte(m | 25);
      final a = arg.toInt();
      out.addByte((a >> 8) & 0xff);
      out.addByte(a & 0xff);
    } else if (arg < BigInt.from(0x100000000)) {
      out.addByte(m | 26);
      final a = arg.toInt();
      for (var i = 3; i >= 0; i--) {
        out.addByte((a >> (8 * i)) & 0xff);
      }
    } else {
      out.addByte(m | 27);
      for (var i = 7; i >= 0; i--) {
        out.addByte(((arg >> (8 * i)) & _byteMask).toInt());
      }
    }
  }

  static void _encMap(EcfMap m, BytesBuilder out) {
    // Encode each key + value, then sort entries by encoded-KEY bytes
    // (length-then-lex, ECF Rule 2). Duplicate keys in a canonical map are
    // illegal, so there are no ties on the key bytes.
    final encoded = m.entries
        .map((e) => _EncodedEntry(encodeOrThrow(e.key), encodeOrThrow(e.value)))
        .toList()
      ..sort(_compareKeys);
    _encHead(5, BigInt.from(encoded.length), out);
    for (final e in encoded) {
      out.add(e.key);
      out.add(e.value);
    }
  }

  /// Length-then-byte-lexicographic order on encoded-key octets (ECF Rule 2).
  /// Because CBOR head-encoding puts the length in the low bits of the initial
  /// byte, this is byte-wise lexicographic on the FULL encoded key — the same
  /// order the Go oracle's `bytes.Compare(keyBytes)` produces.
  static int _compareKeys(_EncodedEntry a, _EncodedEntry b) {
    if (a.key.length != b.key.length) {
      return a.key.length.compareTo(b.key.length);
    }
    for (var i = 0; i < a.key.length; i++) {
      if (a.key[i] != b.key[i]) return a.key[i].compareTo(b.key[i]);
    }
    return 0;
  }

  // ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ────────

  static void _encFloat(double f, BytesBuilder out) {
    // -0.0 is canonical f16 (Rule 4a). (Callers route NaN/Inf/-0.0 through
    // EcfFloatSpecial; this guards a stray -0.0 that arrives as a plain double.)
    if (f == 0.0 && f.isNegative) {
      out.add(const [0xf9, 0x80, 0x00]);
      return;
    }
    final h = _doubleToF16(f);
    if (h != null && _f16ToDouble(h) == f) {
      out.addByte(0xf9);
      out.addByte((h >> 8) & 0xff);
      out.addByte(h & 0xff);
      return;
    }
    // f32 if it round-trips exactly.
    final f32 = ByteData(4)..setFloat32(0, f, Endian.big);
    if (f32.getFloat32(0, Endian.big) == f) {
      out.addByte(0xfa);
      out.add(f32.buffer.asUint8List());
      return;
    }
    // f64 fallback.
    final f64 = ByteData(8)..setFloat64(0, f, Endian.big);
    out.addByte(0xfb);
    out.add(f64.buffer.asUint8List());
  }

  /// Convert a finite double to a 16-bit IEEE half, or null if not exactly
  /// representable as a finite f16 (caller falls back to f32/f64).
  static int? _doubleToF16(double f) {
    final bd = ByteData(8)..setFloat64(0, f, Endian.big);
    final bits = bd.getUint64(0, Endian.big);
    final sign = ((bits >> 63) & 0x1);
    final exp = ((bits >> 52) & 0x7ff);
    final mant = bits & 0xfffffffffffff;
    if (exp == 0x7ff) return null; // inf/nan handled as specials, not here
    if (exp == 0 && mant == 0) return sign == 1 ? 0x8000 : 0x0000;
    final int unbiased;
    final int fullMant;
    if (exp == 0) {
      // subnormal double — normalize
      final lead = _numberOfLeadingZeros53(mant);
      unbiased = -1022 - lead;
      fullMant = ((mant << (lead + 1)) & 0x1fffffffffffff) | 0x10000000000000;
    } else {
      unbiased = exp - 1023;
      fullMant = mant | 0x10000000000000;
    }
    final he = unbiased + 15; // half biased exponent
    if (he > 30) return null; // too large for finite f16
    if (he >= 1) {
      // normalized f16: low 42 mantissa bits must be zero (10-bit fraction)
      if ((mant & 0x3ffffffffff) != 0) return null;
      final hmant = mant >> 42;
      return (sign << 15) | (he << 10) | hmant;
    }
    // subnormal f16 (he <= 0): value = significand * 2^(unbiased-52);
    // representable iff value * 2^24 is an integer in [1,1023].
    final scaledExp = (unbiased - 52) + 24;
    if (scaledExp >= 0) {
      final scaled = BigInt.from(fullMant) << scaledExp;
      if (scaled.sign > 0 && scaled <= BigInt.from(1023)) {
        final s = scaled.toInt();
        if (s >= 1) return (sign << 15) | s;
      }
      return null;
    }
    final shift = -scaledExp;
    if ((fullMant & ((1 << shift) - 1)) != 0) return null;
    final q = fullMant >> shift;
    if (q >= 1 && q <= 1023) return (sign << 15) | q;
    return null;
  }

  /// Leading zeros of a 53-bit mantissa magnitude (relative to bit 52). Mirrors
  /// the Kotlin `numberOfLeadingZeros(mant) - (63 - 52)`. `mant` is in [1, 2^52).
  static int _numberOfLeadingZeros53(int mant) {
    // Highest set bit position among bits 0..51.
    var n = 0;
    for (var bit = 51; bit >= 0; bit--) {
      if ((mant >> bit) & 1 == 1) break;
      n++;
    }
    return n;
  }

  /// Convert a 16-bit IEEE half to a double (finite values only on this path).
  static double _f16ToDouble(int h) {
    final sign = (h >> 15) & 0x1;
    final exp = (h >> 10) & 0x1f;
    final mant = h & 0x3ff;
    final s = sign == 1 ? -1.0 : 1.0;
    if (exp == 0) {
      if (mant == 0) return s * 0.0;
      return s * mant * _pow2(-24); // subnormal
    }
    if (exp == 0x1f) {
      return mant == 0 ? s * double.infinity : double.nan;
    }
    return s * (1024 + mant) * _pow2(exp - 25); // (1.m) * 2^(exp-15)
  }

  static double _pow2(int e) {
    // Exact power of two via ByteData (avoids dart:math import for an exact op).
    if (e >= 0) {
      return (BigInt.one << e).toDouble();
    }
    return 1.0 / (BigInt.one << (-e)).toDouble();
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Decode
  // ───────────────────────────────────────────────────────────────────────────

  /// Decode canonical ECF bytes to a value; rejects trailing bytes.
  static EcfResult<EcfValue> decode(Uint8List octets) {
    try {
      final c = _Cursor(octets);
      final v = _dec(c, 0);
      if (c.i < octets.length) {
        throw EcfException(
            NonCanonicalEcf('trailing bytes: ${octets.length - c.i}'));
      }
      return Ok(v);
    } on EcfException catch (e) {
      return Err(e.error);
    }
  }

  static EcfValue _dec(_Cursor c, int depth) {
    if (depth > maxDepth) {
      throw const EcfException(NonCanonicalEcf('max depth exceeded'));
    }
    if (c.i >= c.o.length) {
      throw const EcfException(TruncatedInput('item: ran off end'));
    }
    final ib = c.o[c.i];
    final major = ib >> 5;
    final info = ib & 0x1f;
    c.i++;
    switch (major) {
      case 0:
        return EcfInt(_decArg(c, info));
      case 1:
        return EcfInt(-_decArg(c, info) - BigInt.one);
      case 2:
        final len = _decLen(c, info);
        _need(c, len);
        final b = Uint8List.sublistView(c.o, c.i, c.i + len);
        final copy = Uint8List.fromList(b);
        c.i += len;
        return EcfBytes.owned(copy);
      case 3:
        final len = _decLen(c, info);
        _need(c, len);
        final s = utf8.decode(Uint8List.sublistView(c.o, c.i, c.i + len));
        c.i += len;
        return EcfText(s);
      case 4:
        final len = _decLen(c, info);
        final items = <EcfValue>[];
        for (var k = 0; k < len; k++) {
          items.add(_dec(c, depth + 1));
        }
        return EcfArray(items);
      case 5:
        final len = _decLen(c, info);
        final entries = <EcfEntry>[];
        final seen = <String>{};
        for (var k = 0; k < len; k++) {
          final key = _dec(c, depth + 1);
          final value = _dec(c, depth + 1);
          if (!seen.add(_keySurrogate(key))) {
            throw const EcfException(DuplicateKey('duplicate map key'));
          }
          entries.add(EcfEntry(key, value));
        }
        return EcfMap(entries);
      case 6:
        throw EcfException(TagRejected('major-type-6 tag rejected at ${c.i - 1}'));
      case 7:
        return _decSimple(c, info);
      default:
        throw EcfException(NonCanonicalEcf('bad major type $major'));
    }
  }

  /// Decode the argument for majors 0/1 (full uint64 range -> BigInt).
  static BigInt _decArg(_Cursor c, int info) {
    if (info < 24) {
      return BigInt.from(info);
    } else if (info == 24) {
      _need(c, 1);
      final v = c.o[c.i];
      c.i += 1;
      return BigInt.from(v);
    } else if (info == 25) {
      _need(c, 2);
      final v = (c.o[c.i] << 8) | c.o[c.i + 1];
      c.i += 2;
      return BigInt.from(v);
    } else if (info == 26) {
      _need(c, 4);
      var v = 0;
      for (var k = 0; k < 4; k++) {
        v = (v << 8) | c.o[c.i + k];
      }
      c.i += 4;
      return BigInt.from(v);
    } else if (info == 27) {
      _need(c, 8);
      var v = BigInt.zero;
      for (var k = 0; k < 8; k++) {
        v = (v << 8) | BigInt.from(c.o[c.i + k]);
      }
      c.i += 8;
      return v;
    } else {
      throw EcfException(
          NonCanonicalEcf('reserved/indefinite argument: $info'));
    }
  }

  /// Decode a length argument (majors 2-5); must fit in a Dart int.
  static int _decLen(_Cursor c, int info) {
    final v = _decArg(c, info);
    if (v.bitLength > 31) {
      throw EcfException(NonCanonicalEcf('length too large: $v'));
    }
    return v.toInt();
  }

  static EcfValue _decSimple(_Cursor c, int info) {
    switch (info) {
      case 20:
        return EcfBool.falseValue;
      case 21:
        return EcfBool.trueValue;
      case 22:
        return EcfNull.instance;
      case 25:
        _need(c, 2);
        final b0 = c.o[c.i];
        final b1 = c.o[c.i + 1];
        c.i += 2;
        return _decodeF16(b0, b1);
      case 26:
        _need(c, 4);
        var bits = 0;
        for (var k = 0; k < 4; k++) {
          bits = (bits << 8) | c.o[c.i + k];
        }
        c.i += 4;
        return _decodeF32(bits);
      case 27:
        _need(c, 8);
        final bd = ByteData(8);
        for (var k = 0; k < 8; k++) {
          bd.setUint8(k, c.o[c.i + k]);
        }
        c.i += 8;
        return _decodeF64(bd);
      default:
        throw EcfException(NonCanonicalEcf('bad simple value: $info'));
    }
  }

  static EcfValue _decodeF16(int b0, int b1) {
    final h = (b0 << 8) | b1;
    final s = (h >> 15) & 1;
    final e = (h >> 10) & 0x1f;
    final m = h & 0x3ff;
    if (e == 0x1f) {
      return m == 0
          ? (s == 1
              ? EcfFloatSpecial.negativeInfinity
              : EcfFloatSpecial.positiveInfinity)
          : EcfFloatSpecial.nan;
    }
    if (e == 0 && m == 0) {
      return s == 1 ? EcfFloatSpecial.negativeZero : const EcfFloat(0.0);
    }
    return EcfFloat(_f16ToDouble(h));
  }

  static EcfValue _decodeF32(int bits) {
    final s = (bits >> 31) & 1;
    final e = (bits >> 23) & 0xff;
    final m = bits & 0x7fffff;
    if (e == 0xff) {
      return m == 0
          ? (s == 1
              ? EcfFloatSpecial.negativeInfinity
              : EcfFloatSpecial.positiveInfinity)
          : EcfFloatSpecial.nan;
    }
    if (e == 0 && m == 0) {
      return s == 1 ? EcfFloatSpecial.negativeZero : const EcfFloat(0.0);
    }
    final bd = ByteData(4)..setUint32(0, bits, Endian.big);
    return EcfFloat(bd.getFloat32(0, Endian.big));
  }

  static EcfValue _decodeF64(ByteData bd) {
    final bits = bd.getUint64(0, Endian.big);
    final s = (bits >> 63) & 1;
    final e = (bits >> 52) & 0x7ff;
    final m = bits & 0xfffffffffffff;
    if (e == 0x7ff) {
      return m == 0
          ? (s == 1
              ? EcfFloatSpecial.negativeInfinity
              : EcfFloatSpecial.positiveInfinity)
          : EcfFloatSpecial.nan;
    }
    if (e == 0 && m == 0) {
      return s == 1 ? EcfFloatSpecial.negativeZero : const EcfFloat(0.0);
    }
    return EcfFloat(bd.getFloat64(0, Endian.big));
  }

  static void _need(_Cursor c, int len) {
    if (len < 0 || c.i + len > c.o.length) {
      throw EcfException(TruncatedInput('need $len at ${c.i}'));
    }
  }

  static String _keySurrogate(EcfValue key) {
    switch (key) {
      case EcfText(:final value):
        return 's:$value';
      case EcfBytes():
        return 'b:${key.rawUnsafe.join(',')}';
      case EcfInt(:final value):
        return 'i:$value';
      default:
        throw const EcfException(
            NonCanonicalEcf('non-canonical map key type'));
    }
  }
}

class _Cursor {
  _Cursor(this.o);
  final Uint8List o;
  int i = 0;
}

class _EncodedEntry {
  _EncodedEntry(this.key, this.value);
  final Uint8List key;
  final Uint8List value;
}
