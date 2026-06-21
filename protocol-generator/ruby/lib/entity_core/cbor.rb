# frozen_string_literal: true

require_relative "error"

module EntityCore
  # Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder/decoder
  # (ENTITY-CBOR-ENCODING.md v1.5). No Ruby CBOR gem delivers the full ECF
  # contract (length-first map ordering on encoded key bytes, shortest-float
  # incl. f16, recursive major-type-6 rejection on decode, full uint64/nint
  # range, raw-byte +data+ fidelity), so the canonical layer is owned here.
  #
  # == Value representation
  #
  # The decoded form is native Ruby values. Two distinctions are encoded in the
  # +String+ ENCODING (the idiomatic Ruby seam), not in a wrapper type:
  #
  # * a text string (CBOR major 3) is a +String+ in a text encoding (UTF-8);
  # * a byte string (CBOR major 2) is a +String+ in +Encoding::BINARY+
  #   (ASCII-8BIT). Use +String#b+ / +force_encoding(Encoding::BINARY)+ to build
  #   one. This is the +byte_strings_ascii_8bit+ profile idiom.
  #
  # Finite floats are Ruby +Float+s; +Float::NAN+ / +Float::INFINITY+ /
  # +-Float::INFINITY+ carry the non-finite specials natively. Ruby's
  # arbitrary-precision +Integer+ means the uint64 head-form is just an Integer
  # — no native-int head-form trap (native_bignum). Entity +data+ is modelled as
  # an arbitrary ECF value (NOT necessarily a Hash) — duck_typing / A-JAVA-010.
  #
  # | CBOR                    | Ruby                                  |
  # |-------------------------|---------------------------------------|
  # | unsigned / negative int | Integer                               |
  # | float (finite)          | Float                                 |
  # | float NaN/+Inf/-Inf     | Float::NAN / Float::INFINITY / -Inf   |
  # | text string             | String (UTF-8)                        |
  # | byte string             | String (BINARY / ASCII-8BIT)          |
  # | array                   | Array                                 |
  # | map                     | Hash                                  |
  # | bool                    | true / false                          |
  # | null                    | nil                                   |
  module Cbor
    # ECF §10.2 nesting limit.
    MAX_DEPTH = 64

    BINARY = Encoding::BINARY
    private_constant :BINARY

    # Non-finite float sentinels (Rule 4a — exact bytes, no implementation
    # choice). NaN canonicalizes to the 0x7e00 payload.
    NAN_BYTES     = "\xF9\x7E\x00".b
    POS_INF_BYTES = "\xF9\x7C\x00".b
    NEG_INF_BYTES = "\xF9\xFC\x00".b
    NEG_ZERO_BYTES = "\xF9\x80\x00".b
    private_constant :NAN_BYTES, :POS_INF_BYTES, :NEG_INF_BYTES, :NEG_ZERO_BYTES

    module_function

    # ═══════════════════════════════════════════════════════════════════════
    # Encode
    # ═══════════════════════════════════════════════════════════════════════

    # Encode a Ruby value to canonical ECF bytes (an +Encoding::BINARY+ String).
    def encode(value)
      buf = String.new(encoding: BINARY)
      enc(value, buf)
      buf
    end

    def enc(value, buf)
      case value
      when nil   then buf << "\xF6".b
      when true  then buf << "\xF5".b
      when false then buf << "\xF4".b
      when ::Integer then enc_integer(value, buf)
      when ::Float   then enc_float(value, buf)
      when ::String  then enc_string(value, buf)
      when ::Array   then enc_array(value, buf)
      when ::Hash    then enc_map(value, buf)
      else
        raise UnsupportedValueError, "cannot ECF-encode #{value.class}: #{value.inspect}"
      end
    end
    private_class_method :enc

    def enc_integer(n, buf)
      if n >= 0
        head(0, n, buf)
      else
        head(1, -1 - n, buf) # major type 1: value = -1 - n
      end
    end
    private_class_method :enc_integer

    # Byte string (major 2, BINARY encoding) vs text string (major 3).
    def enc_string(s, buf)
      if s.encoding == BINARY
        head(2, s.bytesize, buf)
        buf << s
      else
        bytes = s.b
        head(3, bytes.bytesize, buf)
        buf << bytes
      end
    end
    private_class_method :enc_string

    def enc_array(list, buf)
      head(4, list.length, buf)
      list.each { |item| enc(item, buf) }
    end
    private_class_method :enc_array

    # Map (major 5) — keys sorted by ENCODED bytes, length-first then
    # lexicographic (RFC 8949 §4.2.1 / ECF Rule 2). Each value is encoded into
    # its own buffer so we sort on the key's encoded form.
    def enc_map(map, buf)
      entries = map.map do |k, v|
        ek = encode(k)
        ev = encode(v)
        [ek, ev]
      end
      entries.sort_by! { |ek, _ev| [ek.bytesize, ek] }
      head(5, map.size, buf)
      entries.each do |ek, ev|
        buf << ek << ev
      end
    end
    private_class_method :enc_map

    # CBOR head byte + minimal argument (majors 0-5). Minimal-length argument
    # per Rule 1 — never a wider encoding than the value needs.
    def head(major, n, buf)
      mt = major << 5
      if n < 24
        buf << (mt | n).chr
      elsif n < 0x100
        buf << (mt | 24).chr << n.chr
      elsif n < 0x10000
        buf << (mt | 25).chr << [n].pack("n")
      elsif n < 0x1_0000_0000
        buf << (mt | 26).chr << [n].pack("N")
      elsif n < 0x1_0000_0000_0000_0000
        buf << (mt | 27).chr << [n].pack("Q>")
      else
        raise UnsupportedValueError, "argument exceeds uint64: #{n}"
      end
    end
    private_class_method :head

    # Float ladder (Rule 4): -0.0, then f16, then f32, else f64. Specials
    # (NaN/±Inf) take their fixed Rule 4a f16 bytes. A narrower candidate is
    # accepted only if its exponent is not all-ones (f16/f32 silent
    # overflow-to-Inf guard) AND it round-trips bit-exactly.
    def enc_float(f, buf)
      if f.nan?
        buf << NAN_BYTES
      elsif f.infinite?
        buf << (f.positive? ? POS_INF_BYTES : NEG_INF_BYTES)
      elsif f.zero? && (1.0 / f).negative? # -0.0 (sign bit set)
        buf << NEG_ZERO_BYTES
      elsif (b16 = fits_f16(f))
        buf << "\xF9".b << b16
      elsif (b32 = fits_f32(f))
        buf << "\xFA".b << b32
      else
        buf << "\xFB".b << [f].pack("G")
      end
    end
    private_class_method :enc_float

    # Ruby's Array#pack has no native half-float, so f16 is hand-encoded from
    # the IEEE-754 binary64 bits. Returns the 2 big-endian half bytes if +f+ is
    # an EXACT finite f16 value (not an all-ones exponent — that would be a
    # silent overflow to Inf), else nil.
    def fits_f16(f)
      bits = [f].pack("G").unpack1("Q>")
      sign = (bits >> 63) & 0x1
      exp  = (bits >> 52) & 0x7FF
      mant = bits & 0xF_FFFF_FFFF_FFFF

      # f == 0.0 (the +0.0 case; -0.0 handled earlier).
      return [(sign << 15)].pack("n") if exp.zero? && mant.zero?

      unbiased = exp - 1023
      # f16 normal exponent range is [-14, 15]; outside → not representable as a
      # finite f16 (the all-ones-exp overflow guard).
      return nil if unbiased < -14 || unbiased > 15

      # Need the low 42 mantissa bits zero (f16 keeps 10 mantissa bits; f64 has
      # 52, so 52-10 = 42 must be zero for an exact value).
      return nil unless (mant & 0x3FF_FFFF_FFFF).zero?

      half_mant = mant >> 42
      half_exp  = unbiased + 15
      half = (sign << 15) | (half_exp << 10) | half_mant
      [half].pack("n")
    end
    private_class_method :fits_f16

    # Returns the 4 big-endian f32 bytes if +f+ round-trips exactly through
    # binary32 without becoming Inf (all-ones-exponent guard), else nil.
    def fits_f32(f)
      candidate = [f].pack("g")
      bits = candidate.unpack1("N")
      exp = (bits >> 23) & 0xFF
      return nil if exp == 0xFF # would be Inf/NaN — overflow, not exact

      return nil unless candidate.unpack1("g") == f

      candidate
    end
    private_class_method :fits_f32

    # ═══════════════════════════════════════════════════════════════════════
    # Decode
    # ═══════════════════════════════════════════════════════════════════════

    # Decode canonical ECF bytes to a Ruby value. Raises a CodecError subclass
    # on any non-canonical input: a CBOR tag (major 6, invariant N2/§6.3),
    # indefinite length, non-minimal argument, reserved additional-info,
    # duplicate map key, over-depth, or trailing bytes.
    def decode(bin)
      bytes = bin.b
      cursor = Cursor.new(bytes)
      value = decode_value(cursor, 0)
      unless cursor.eof?
        raise NonCanonicalError, "trailing bytes after value: #{cursor.remaining} byte(s)"
      end

      value
    end

    # Internal byte cursor over an ASCII-8BIT String (blocks_for_iteration idiom
    # would fight the need to backtrack/peek, so a small cursor is clearer).
    class Cursor
      def initialize(bytes)
        @bytes = bytes
        @pos = 0
        @len = bytes.bytesize
      end

      def eof?
        @pos >= @len
      end

      def remaining
        @len - @pos
      end

      def read_byte
        raise TruncatedError, "unexpected end of input" if @pos >= @len

        b = @bytes.getbyte(@pos)
        @pos += 1
        b
      end

      def read(n)
        raise TruncatedError, "need #{n} bytes, have #{remaining}" if n > remaining

        slice = @bytes.byteslice(@pos, n)
        @pos += n
        slice
      end
    end
    private_constant :Cursor

    def decode_value(cur, depth)
      raise NonCanonicalError, "nesting deeper than #{MAX_DEPTH}" if depth > MAX_DEPTH

      ib = cur.read_byte
      major = ib >> 5
      info = ib & 0x1F

      case major
      when 0 then read_argument(info, cur)
      when 1 then -1 - read_argument(info, cur)
      when 2
        len = read_argument(info, cur)
        cur.read(len).force_encoding(BINARY)
      when 3
        len = read_argument(info, cur)
        s = cur.read(len).force_encoding(Encoding::UTF_8)
        raise NonCanonicalError, "invalid UTF-8 in text string" unless s.valid_encoding?

        s
      when 4
        len = read_argument(info, cur)
        Array.new(len) { decode_value(cur, depth + 1) }
      when 5
        read_map(info, cur, depth + 1)
      when 6
        # Invariant N2 / ECF §6.3 — tags MUST be rejected anywhere in the input.
        raise NonCanonicalError, "CBOR tag (major type 6) is not permitted in ECF"
      when 7
        read_simple(info, cur)
      end
    end
    private_class_method :decode_value

    # Argument decode for majors 0-5. Enforces minimal-length encoding (a value
    # that fits a shorter form in a longer form is non-canonical), and rejects
    # reserved additional-info (28-30) and indefinite length (31).
    def read_argument(info, cur)
      case info
      when 0..23 then info
      when 24
        n = cur.read_byte
        raise NonCanonicalError, "non-minimal uint8 argument: #{n}" if n < 24

        n
      when 25
        n = cur.read(2).unpack1("n")
        raise NonCanonicalError, "non-minimal uint16 argument: #{n}" if n < 0x100

        n
      when 26
        n = cur.read(4).unpack1("N")
        raise NonCanonicalError, "non-minimal uint32 argument: #{n}" if n < 0x10000

        n
      when 27
        n = cur.read(8).unpack1("Q>")
        raise NonCanonicalError, "non-minimal uint64 argument: #{n}" if n < 0x1_0000_0000

        n
      when 31
        raise NonCanonicalError, "indefinite length is not permitted in ECF"
      else # 28, 29, 30
        raise NonCanonicalError, "reserved additional-info value: #{info}"
      end
    end
    private_class_method :read_argument

    def read_map(info, cur, depth)
      len = read_argument(info, cur)
      map = {}
      len.times do
        k = decode_value(cur, depth)
        v = decode_value(cur, depth)
        raise NonCanonicalError, "duplicate map key" if map.key?(k)

        map[k] = v
      end
      map
    end
    private_class_method :read_map

    def read_simple(info, cur)
      case info
      when 20 then false
      when 21 then true
      when 22 then nil
      when 25 then decode_f16(cur.read(2))
      when 26 then decode_f32(cur.read(4))
      when 27 then cur.read(8).unpack1("G")
      else
        raise NonCanonicalError, "unsupported simple/float additional-info: #{info}"
      end
    end
    private_class_method :read_simple

    # Decode a half-float (no native unpack). Specials surface as the native
    # Float::NAN / ±Float::INFINITY.
    def decode_f16(two)
      bits = two.unpack1("n")
      sign = (bits >> 15) & 0x1
      exp  = (bits >> 10) & 0x1F
      mant = bits & 0x3FF

      if exp == 0x1F
        return Float::NAN if mant != 0

        return sign == 1 ? -Float::INFINITY : Float::INFINITY
      end

      value =
        if exp.zero?
          # subnormal: 2^-14 * (mant/1024)
          Math.ldexp(mant.to_f / 1024.0, -14)
        else
          Math.ldexp(1.0 + mant.to_f / 1024.0, exp - 15)
        end
      sign == 1 ? -value : value
    end
    private_class_method :decode_f16

    def decode_f32(four)
      bits = four.unpack1("N")
      exp = (bits >> 23) & 0xFF
      mant = bits & 0x7F_FFFF
      if exp == 0xFF
        return Float::NAN if mant != 0

        sign = (bits >> 31) & 0x1
        return sign == 1 ? -Float::INFINITY : Float::INFINITY
      end
      four.unpack1("g")
    end
    private_class_method :decode_f32
  end
end
