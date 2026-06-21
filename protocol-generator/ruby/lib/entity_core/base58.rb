# frozen_string_literal: true

require_relative "error"

module EntityCore
  # Base58 (Bitcoin alphabet) encode/decode, hand-rolled (no gem — dodges a dep
  # + a pin). Used for peer-id formatting/parsing (V7 §1.5). Each leading
  # zero byte maps to a leading "1", per the standard Base58 convention.
  module Base58
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    INDEX = ALPHABET.each_char.with_index.to_h.freeze

    module_function

    # Encode an Encoding::BINARY String to a Base58 (UTF-8) String.
    def encode(bin)
      bytes = bin.b
      zeros = 0
      zeros += 1 while zeros < bytes.bytesize && bytes.getbyte(zeros).zero?

      n = bytes.empty? ? 0 : bytes.unpack1("H*").to_i(16)
      body = +""
      while n.positive?
        n, rem = n.divmod(58)
        body.prepend(ALPHABET[rem])
      end

      ("1" * zeros) + body
    end

    # Decode a Base58 String back to an Encoding::BINARY String. Raises
    # CodecError on a non-alphabet character.
    def decode(str)
      ones = 0
      ones += 1 while ones < str.length && str[ones] == "1"

      n = 0
      str.each_char do |c|
        idx = INDEX[c]
        raise CodecError, "invalid base58 character: #{c.inspect}" if idx.nil?

        n = (n * 58) + idx
      end

      body =
        if n.zero?
          String.new(encoding: Encoding::BINARY)
        else
          hex = n.to_s(16)
          hex = "0#{hex}" if hex.length.odd?
          [hex].pack("H*")
        end

      (("\x00".b * ones) + body)
    end
  end
end
