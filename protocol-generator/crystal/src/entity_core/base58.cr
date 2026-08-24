require "big"
require "./error"

module EntityCore
  # Base58 (Bitcoin alphabet) encode/decode, hand-rolled (no shard — dodges a dep
  # + a pin). Used for peer-id formatting/parsing (§1.5). Each leading zero byte
  # maps to a leading "1", per the standard Base58 convention. BigInt-backed
  # (Crystal's fixed-width ints do not span a 32/57-byte key digest).
  module Base58
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    # char -> index lookup, built once.
    INDEX = begin
      h = ::Hash(Char, Int32).new
      ALPHABET.each_char_with_index { |c, i| h[c] = i }
      h
    end

    extend self

    # Encode raw bytes to a Base58 String.
    def encode(bin : Bytes) : String
      zeros = 0
      while zeros < bin.size && bin[zeros].zero?
        zeros += 1
      end

      n = BigInt.new(0)
      bin.each do |b|
        n = (n << 8) | b.to_i
      end

      body = String.build do |sb|
        stack = [] of Char
        while n > 0
          n, rem = n.divmod(58)
          stack << ALPHABET[rem.to_i]
        end
        stack.reverse_each { |c| sb << c }
      end

      String.build do |sb|
        zeros.times { sb << '1' }
        sb << body
      end
    end

    # Decode a Base58 String back to raw bytes. Raises `CodecError` on a
    # non-alphabet character.
    def decode(str : String) : Bytes
      ones = 0
      str.each_char do |c|
        break unless c == '1'
        ones += 1
      end

      n = BigInt.new(0)
      str.each_char do |c|
        idx = INDEX[c]?
        raise CodecError.new("invalid base58 character: #{c.inspect}") if idx.nil?
        n = (n * 58) + idx
      end

      body = [] of UInt8
      while n > 0
        n, rem = n.divmod(256)
        body << rem.to_u8
      end
      body.reverse!

      out = Bytes.new(ones + body.size)
      body.each_with_index { |b, i| out[ones + i] = b }
      out
    end
  end
end
