require "./error"

module EntityCore
  # Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder/decoder
  # (ENTITY-CBOR-ENCODING.md v1.5). No Crystal shard delivers the full ECF
  # contract (length-first map ordering on encoded key bytes, shortest-float incl.
  # f16, recursive major-type-6 rejection on decode, full uint64/nint range,
  # raw-byte `data` fidelity), so the canonical layer is owned here.
  #
  # == Value representation (the tagged EcValue union)
  #
  # Crystal's `String` is UTF-8-validated and cannot hold arbitrary bytes, so —
  # unlike the Ruby peer's encoding-tagged String — the text/byte distinction is
  # carried in the STATIC TYPE:
  #
  # * a CBOR text string (major 3) is a Crystal `String` (UTF-8);
  # * a CBOR byte string (major 2) is a Crystal `Bytes` (Slice(UInt8)).
  #
  # Entity `data` is an arbitrary ECF value (NOT necessarily a map / Hash), so the
  # whole model is the recursive `EcValue` union below — never assume Hash
  # (data_is_arbitrary_ecf / A-JAVA-010).
  #
  # | CBOR                    | Crystal EcValue                       |
  # |-------------------------|---------------------------------------|
  # | unsigned int            | UInt64 (via Int::Signed/UInt promo)   |
  # | negative int            | Int64 (or a boxed nint for -2^64..)   |
  # | float (finite)          | Float64                               |
  # | float NaN/+Inf/-Inf     | Float64 (native specials)             |
  # | text string             | String (UTF-8)                        |
  # | byte string             | Bytes (Slice(UInt8))                  |
  # | array                   | Array(EcValue)                        |
  # | map                     | ::Hash(EcValue, EcValue)                |
  # | bool                    | Bool                                  |
  # | null                    | Nil                                   |
  #
  # Integers: the fixed-width trap. Crystal ints are machine ints; a uint in
  # [2^63, 2^64-1] does not fit Int64 and MUST be carried as UInt64. To preserve
  # the full CBOR unsigned/negative head-form across the whole [0, 2^64-1] range
  # (major 0) and [-2^64, -1] range (major 1, value = -1-n), integers are modelled
  # by the `EcInt` struct which records the major type + the raw uint64 argument.
  # A plain Int/UInt literal is promoted to `EcInt` on encode; decode always
  # yields an `EcInt`.
  module Cbor
    # ECF §10.2 nesting limit.
    MAX_DEPTH = 64

    # A CBOR integer as (major, argument): major 0 (unsigned, value == arg) or
    # major 1 (negative, value == -1 - arg). `arg` is the raw uint64 head
    # argument, so the full [0, 2^64-1] / [-2^64, -1] range is representable on
    # Crystal's fixed-width ints without a BigInt (native_fixed_width_int; the
    # Ruby peer's native_bignum does NOT hold here — the overfit trap).
    struct EcInt
      getter major : UInt8
      getter arg : UInt64

      def initialize(@major : UInt8, @arg : UInt64)
      end

      # Build from any Crystal integer, choosing the CBOR major type + argument.
      def self.from(n : Int)
        if n >= 0
          new(0_u8, n.to_u64)
        else
          # value = -1 - arg  =>  arg = -1 - value = -(n) - 1
          # For Int64::MIN this would overflow the signed negate; compute in the
          # unsigned domain: arg = (-1 - n). Use the wrapping-safe form.
          mag = n.to_i64
          arg = (~mag).to_u64 # ~x == -1 - x, exact in two's complement
          new(1_u8, arg)
        end
      end

      # The integer value as an Int64 when it fits, else raises (callers that need
      # the full range read `major`/`arg` directly).
      def to_i64 : Int64
        if @major == 0_u8
          raise UnsupportedValueError.new("uint #{@arg} exceeds Int64") if @arg > Int64::MAX.to_u64
          @arg.to_i64
        else
          # value = -1 - arg
          raise UnsupportedValueError.new("nint exceeds Int64") if @arg > Int64::MAX.to_u64
          (-1_i64 - @arg.to_i64)
        end
      end

      def ==(other : EcInt)
        @major == other.major && @arg == other.arg
      end

      def_hash @major, @arg
    end

    # The recursive ECF value union. Byte strings (`Bytes`) are distinct from text
    # strings (`String`) — the wire major-type distinction is a static-type
    # distinction here (byte_slices_for_wire).
    alias EcValue = Nil | Bool | EcInt | Float64 | String | Bytes | Array(EcValue) | ::Hash(EcValue, EcValue)

    # Non-finite float sentinels (Rule 4a — exact bytes, no implementation
    # choice). NaN canonicalizes to the 0x7e00 payload.
    NAN_BYTES      = Bytes[0xF9, 0x7E, 0x00]
    POS_INF_BYTES  = Bytes[0xF9, 0x7C, 0x00]
    NEG_INF_BYTES  = Bytes[0xF9, 0xFC, 0x00]
    NEG_ZERO_BYTES = Bytes[0xF9, 0x80, 0x00]

    extend self

    # ─────────────────────────────────────────────────────────────────────────
    # Coercion — promote plain Crystal values into the EcValue model so callers
    # can write `Cbor.encode({"a" => 1})` without hand-building EcInt everywhere.
    # ─────────────────────────────────────────────────────────────────────────

    def coerce(value) : EcValue
      case value
      when Nil     then nil
      when Bool    then value
      when EcInt   then value
      when Int     then EcInt.from(value)
      when Float64 then value
      when Float   then value.to_f64
      when String  then value
      when Bytes   then value
      when ::Array
        value.map { |item| coerce(item).as(EcValue) }
      when ::Hash
        h = ::Hash(EcValue, EcValue).new
        value.each { |k, v| h[coerce(k)] = coerce(v) }
        h
      when EcValue
        value
      else
        raise UnsupportedValueError.new("cannot ECF-encode #{value.class}")
      end
    end

    # ─────────────────────────────────────────────────────────────────────────
    # Encode
    # ─────────────────────────────────────────────────────────────────────────

    # Encode any coercible value to canonical ECF bytes.
    def encode(value) : Bytes
      io = IO::Memory.new
      enc(coerce(value), io)
      io.to_slice
    end

    private def enc(value : EcValue, io : IO)
      case value
      when Nil     then io.write_byte(0xF6_u8)
      when Bool    then io.write_byte(value ? 0xF5_u8 : 0xF4_u8)
      when EcInt   then enc_int(value, io)
      when Float64 then enc_float(value, io)
      when String  then enc_text(value, io)
      when Bytes   then enc_bytes(value, io)
      when Array(EcValue) then enc_array(value, io)
      when ::Hash(EcValue, EcValue) then enc_map(value, io)
      else
        raise UnsupportedValueError.new("cannot ECF-encode #{value.class}")
      end
    end

    private def enc_int(n : EcInt, io : IO)
      head(n.major, n.arg, io)
    end

    private def enc_text(s : String, io : IO)
      head(3_u8, s.bytesize.to_u64, io)
      io.write(s.to_slice)
    end

    private def enc_bytes(b : Bytes, io : IO)
      head(2_u8, b.size.to_u64, io)
      io.write(b)
    end

    private def enc_array(list : Array(EcValue), io : IO)
      head(4_u8, list.size.to_u64, io)
      list.each { |item| enc(item, io) }
    end

    # Map (major 5) — keys sorted by ENCODED bytes, length-first then
    # lexicographic over the encoded key bytes (RFC 8949 §4.2.1 / ECF Rule 2).
    # Each key is encoded into its own buffer so we sort on the key's encoded
    # form; NOT plain value-wise (crystal-cbor's insertion-order is wrong).
    private def enc_map(map : ::Hash(EcValue, EcValue), io : IO)
      entries = map.map do |k, v|
        kio = IO::Memory.new
        enc(k, kio)
        vio = IO::Memory.new
        enc(v, vio)
        {kio.to_slice, vio.to_slice}
      end
      entries.sort! { |a, b| cmp_len_lex(a[0], b[0]) }
      head(5_u8, map.size.to_u64, io)
      entries.each do |ek, ev|
        io.write(ek)
        io.write(ev)
      end
    end

    # Length-then-lex comparison over two encoded-key byte slices.
    private def cmp_len_lex(a : Bytes, b : Bytes) : Int32
      if a.size != b.size
        return a.size <=> b.size
      end
      i = 0
      while i < a.size
        return a[i] <=> b[i] if a[i] != b[i]
        i += 1
      end
      0
    end

    # CBOR head byte + minimal argument (majors 0-5). Minimal-length argument per
    # Rule 1 — never a wider encoding than the value needs.
    private def head(major : UInt8, n : UInt64, io : IO)
      mt = major << 5
      if n < 24_u64
        io.write_byte(mt | n.to_u8)
      elsif n < 0x100_u64
        io.write_byte(mt | 24_u8)
        io.write_byte(n.to_u8)
      elsif n < 0x10000_u64
        io.write_byte(mt | 25_u8)
        write_be(io, n, 2)
      elsif n < 0x100000000_u64
        io.write_byte(mt | 26_u8)
        write_be(io, n, 4)
      else
        io.write_byte(mt | 27_u8)
        write_be(io, n, 8)
      end
    end

    private def write_be(io : IO, n : UInt64, bytes : Int32)
      (bytes - 1).downto(0) do |shift|
        io.write_byte(((n >> (shift * 8)) & 0xFF_u64).to_u8)
      end
    end

    # Float ladder (Rule 4): specials (NaN/±Inf/-0.0) take their fixed Rule 4a
    # f16 bytes, then f16, then f32, else f64. A narrower candidate is accepted
    # only if it round-trips bit-exactly (and is not a silent overflow to Inf).
    private def enc_float(f : Float64, io : IO)
      if f.nan?
        io.write(NAN_BYTES)
      elsif f.infinite?
        io.write(f > 0 ? POS_INF_BYTES : NEG_INF_BYTES)
      elsif f == 0.0 && (1.0 / f) < 0.0 # -0.0 (sign bit set)
        io.write(NEG_ZERO_BYTES)
      elsif (b16 = fits_f16(f))
        io.write_byte(0xF9_u8)
        io.write(b16)
      elsif (b32 = fits_f32(f))
        io.write_byte(0xFA_u8)
        io.write(b32)
      else
        io.write_byte(0xFB_u8)
        write_be(io, f.unsafe_as(UInt64), 8)
      end
    end

    # f16 is hand-encoded from the IEEE-754 binary64 bits. Returns the 2
    # big-endian half bytes if `f` is an EXACT finite f16 value (not an
    # all-ones-exp overflow to Inf), else nil.
    private def fits_f16(f : Float64) : Bytes?
      bits = f.unsafe_as(UInt64)
      sign = (bits >> 63) & 0x1_u64
      exp = (bits >> 52) & 0x7FF_u64
      mant = bits & 0xF_FFFF_FFFF_FFFF_u64

      # f == +0.0 (the -0.0 case is handled earlier).
      if exp.zero? && mant.zero?
        return u16_be((sign << 15).to_u16)
      end

      unbiased = exp.to_i32 - 1023
      # f16 normal exponent range is [-14, 15].
      return nil if unbiased < -14 || unbiased > 15
      # Low 42 mantissa bits must be zero (f64 has 52, f16 keeps 10 => 42 zero).
      return nil unless (mant & 0x3FF_FFFF_FFFF_u64).zero?

      half_mant = (mant >> 42) & 0x3FF_u64
      half_exp = (unbiased + 15).to_u64
      half = (sign << 15) | (half_exp << 10) | half_mant
      u16_be(half.to_u16)
    end

    # Returns the 4 big-endian f32 bytes if `f` round-trips exactly through
    # binary32 without becoming Inf (all-ones-exp guard), else nil.
    private def fits_f32(f : Float64) : Bytes?
      f32 = f.to_f32
      return nil if f32.infinite? # overflow to Inf on narrowing
      return nil unless f32.to_f64 == f
      bits = f32.unsafe_as(UInt32)
      exp = (bits >> 23) & 0xFF_u32
      return nil if exp == 0xFF_u32
      u32_be(bits)
    end

    private def u16_be(v : UInt16) : Bytes
      Bytes[((v >> 8) & 0xFF).to_u8, (v & 0xFF).to_u8]
    end

    private def u32_be(v : UInt32) : Bytes
      Bytes[
        ((v >> 24) & 0xFF).to_u8,
        ((v >> 16) & 0xFF).to_u8,
        ((v >> 8) & 0xFF).to_u8,
        (v & 0xFF).to_u8,
      ]
    end

    # ─────────────────────────────────────────────────────────────────────────
    # Decode
    # ─────────────────────────────────────────────────────────────────────────

    # Decode canonical ECF bytes to an EcValue. Raises a CodecError subclass on
    # any non-canonical input: a CBOR tag (major 6, invariant N2/§6.3),
    # indefinite length, non-minimal argument, reserved additional-info,
    # duplicate map key, over-depth, or trailing bytes.
    def decode(bin : Bytes) : EcValue
      cur = Cursor.new(bin)
      value = decode_value(cur, 0)
      unless cur.eof?
        raise NonCanonicalError.new("trailing bytes after value: #{cur.remaining} byte(s)")
      end
      value
    end

    # Internal byte cursor over a `Bytes`.
    private class Cursor
      def initialize(@bytes : Bytes)
        @pos = 0
      end

      def eof? : Bool
        @pos >= @bytes.size
      end

      def remaining : Int32
        @bytes.size - @pos
      end

      def read_byte : UInt8
        raise TruncatedError.new("unexpected end of input") if @pos >= @bytes.size
        b = @bytes[@pos]
        @pos += 1
        b
      end

      def read(n : Int32) : Bytes
        raise TruncatedError.new("need #{n} bytes, have #{remaining}") if n > remaining
        slice = @bytes[@pos, n]
        @pos += n
        slice
      end
    end

    private def decode_value(cur : Cursor, depth : Int32) : EcValue
      raise NonCanonicalError.new("nesting deeper than #{MAX_DEPTH}") if depth > MAX_DEPTH

      ib = cur.read_byte
      major = ib >> 5
      info = ib & 0x1F

      case major
      when 0_u8
        EcInt.new(0_u8, read_argument(info, cur))
      when 1_u8
        EcInt.new(1_u8, read_argument(info, cur))
      when 2_u8
        len = read_argument(info, cur)
        # Copy out so the value owns its bytes.
        raise NonCanonicalError.new("byte string too large") if len > Int32::MAX.to_u64
        cur.read(len.to_i32).dup
      when 3_u8
        len = read_argument(info, cur)
        raise NonCanonicalError.new("text string too large") if len > Int32::MAX.to_u64
        raw = cur.read(len.to_i32)
        s = String.new(raw)
        unless s.valid_encoding?
          raise NonCanonicalError.new("invalid UTF-8 in text string")
        end
        s
      when 4_u8
        len = read_argument(info, cur)
        arr = Array(EcValue).new(len.to_i32)
        len.times { arr << decode_value(cur, depth + 1) }
        arr
      when 5_u8
        read_map(info, cur, depth + 1)
      when 6_u8
        # Invariant N2 / ECF §6.3 — tags MUST be rejected anywhere in the input.
        raise NonCanonicalError.new("CBOR tag (major type 6) is not permitted in ECF")
      else # 7
        read_simple(info, cur)
      end
    end

    # Argument decode for majors 0-5. Enforces minimal-length encoding, rejects
    # reserved additional-info (28-30) and indefinite length (31).
    private def read_argument(info : UInt8, cur : Cursor) : UInt64
      case info
      when 0_u8..23_u8
        info.to_u64
      when 24_u8
        n = cur.read_byte.to_u64
        raise NonCanonicalError.new("non-minimal uint8 argument: #{n}") if n < 24_u64
        n
      when 25_u8
        n = read_be(cur, 2)
        raise NonCanonicalError.new("non-minimal uint16 argument: #{n}") if n < 0x100_u64
        n
      when 26_u8
        n = read_be(cur, 4)
        raise NonCanonicalError.new("non-minimal uint32 argument: #{n}") if n < 0x10000_u64
        n
      when 27_u8
        n = read_be(cur, 8)
        raise NonCanonicalError.new("non-minimal uint64 argument: #{n}") if n < 0x100000000_u64
        n
      when 31_u8
        raise NonCanonicalError.new("indefinite length is not permitted in ECF")
      else # 28, 29, 30
        raise NonCanonicalError.new("reserved additional-info value: #{info}")
      end
    end

    private def read_be(cur : Cursor, bytes : Int32) : UInt64
      raw = cur.read(bytes)
      v = 0_u64
      raw.each { |b| v = (v << 8) | b.to_u64 }
      v
    end

    private def read_map(info : UInt8, cur : Cursor, depth : Int32) : ::Hash(EcValue, EcValue)
      len = read_argument(info, cur)
      map = ::Hash(EcValue, EcValue).new
      len.times do
        k = decode_value(cur, depth)
        v = decode_value(cur, depth)
        raise NonCanonicalError.new("duplicate map key") if map.has_key?(k)
        map[k] = v
      end
      map
    end

    private def read_simple(info : UInt8, cur : Cursor) : EcValue
      case info
      when 20_u8 then false
      when 21_u8 then true
      when 22_u8 then nil
      when 25_u8 then decode_f16(cur.read(2))
      when 26_u8 then decode_f32(cur.read(4))
      when 27_u8 then read_be(cur, 8).unsafe_as(Float64)
      else
        raise NonCanonicalError.new("unsupported simple/float additional-info: #{info}")
      end
    end

    private def decode_f16(two : Bytes) : Float64
      bits = (two[0].to_u16 << 8) | two[1].to_u16
      sign = (bits >> 15) & 0x1
      exp = (bits >> 10) & 0x1F
      mant = bits & 0x3FF

      if exp == 0x1F
        return Float64::NAN if mant != 0
        return sign == 1 ? -Float64::INFINITY : Float64::INFINITY
      end

      value =
        if exp.zero?
          Math.ldexp(mant.to_f64 / 1024.0, -14)
        else
          Math.ldexp(1.0 + mant.to_f64 / 1024.0, exp.to_i32 - 15)
        end
      sign == 1 ? -value : value
    end

    private def decode_f32(four : Bytes) : Float64
      bits = 0_u32
      four.each { |b| bits = (bits << 8) | b.to_u32 }
      bits.unsafe_as(Float32).to_f64
    end
  end
end
