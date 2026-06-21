# frozen_string_literal: true

require_relative "error"

module EntityCore
  # Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3, invariant N1).
  #
  # Used for the format-code / key-type / hash-type framing in content hashes
  # and peer-ids. Every currently-allocated code is < 0x80 (a single byte), but
  # the framing routes through a real LEB128 primitive so a future code >= 0x80
  # extends to multiple bytes correctly instead of silently truncating (N1, the
  # bug class that bit the reference impls).
  module Varint
    module_function

    # Encode a non-negative Integer as unsigned LEB128 (an Encoding::BINARY
    # String).
    def encode(n)
      raise UnsupportedValueError, "varint must be non-negative: #{n}" if n.negative?

      out = String.new(encoding: Encoding::BINARY)
      loop do
        byte = n & 0x7F
        n >>= 7
        if n.zero?
          out << byte.chr
          break
        else
          out << (byte | 0x80).chr
        end
      end
      out
    end

    # Decode an unsigned LEB128 varint from the front of +bin+. Returns
    # +[value, rest]+ where +rest+ is the remaining bytes. Raises on truncation.
    def decode(bin)
      bytes = bin.b
      value = 0
      shift = 0
      i = 0
      loop do
        raise TruncatedError, "truncated varint" if i >= bytes.bytesize

        byte = bytes.getbyte(i)
        i += 1
        value |= (byte & 0x7F) << shift
        break if (byte & 0x80).zero?

        shift += 7
      end
      [value, bytes.byteslice(i, bytes.bytesize - i)]
    end
  end
end
