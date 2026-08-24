require "./error"

module EntityCore
  # Multicodec-style unsigned LEB128 varints (§1.5 / §7.3, invariant N1).
  #
  # Used for the format-code / key-type / hash-type framing in content hashes
  # and peer-ids. Every currently-allocated code is < 0x80 (a single byte), but
  # the framing routes through a real LEB128 primitive so a future code >= 0x80
  # extends to multiple bytes correctly instead of silently truncating (N1, the
  # bug class that bit the reference impls).
  module Varint
    extend self

    # Encode a non-negative integer as unsigned LEB128 into `buf`.
    # `n` is a UInt64 — the framing codes are small but the full uint64 range is
    # representable so a >= 2^32 code still extends correctly.
    def encode(n : UInt64, buf : IO)
      loop do
        byte = (n & 0x7F_u64).to_u8
        n >>= 7
        if n.zero?
          buf.write_byte(byte)
          break
        else
          buf.write_byte(byte | 0x80_u8)
        end
      end
    end

    # Encode to a freshly allocated `Bytes`.
    def encode(n : UInt64) : Bytes
      io = IO::Memory.new
      encode(n, io)
      io.to_slice
    end

    # Decode an unsigned LEB128 varint from the front of `bin`. Returns
    # `{value, consumed}` where `consumed` is the number of bytes read. Raises
    # `TruncatedError` on truncation.
    def decode(bin : Bytes) : {UInt64, Int32}
      value = 0_u64
      shift = 0
      i = 0
      loop do
        raise TruncatedError.new("truncated varint") if i >= bin.size
        byte = bin[i]
        i += 1
        value |= (byte & 0x7F_u64) << shift
        break if (byte & 0x80_u8).zero?
        shift += 7
      end
      {value, i}
    end
  end
end
