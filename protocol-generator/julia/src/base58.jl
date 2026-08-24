# Base58 (Bitcoin alphabet) — hand-rolled (profile [codec].base58_library = hand-rolled).
# BigInt (GMP) makes base-256 ↔ base-58 long division trivial, so this is pure arithmetic,
# no byte-array carry loop. Leading zero bytes map to leading '1' characters (and back).
module Base58

export base58encode, base58decode

const ALPHABET = collect("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

# reverse map: char → 0..57, or -1
const INV = let m = fill(-1, 128)
    for (i, c) in enumerate(ALPHABET)
        m[Int(c)+1] = i - 1
    end
    m
end

"""Base58-encode bytes → String. Leading 0x00 bytes become leading '1's."""
function base58encode(input::AbstractVector{UInt8})::String
    zeros = 0
    while zeros < length(input) && input[zeros+1] == 0x00
        zeros += 1
    end
    num = BigInt(0)
    for b in input
        num = num * 256 + Int(b)
    end
    digits = Char[]
    while num > 0
        num, rem = divrem(num, 58)
        push!(digits, ALPHABET[Int(rem)+1])
    end
    reverse!(digits)
    return String(vcat(fill('1', zeros), digits))
end

"""Base58-decode a String → bytes. Leading '1's restore leading 0x00 bytes."""
function base58decode(s::AbstractString)::Vector{UInt8}
    ones = 0
    for c in s
        c == '1' ? (ones += 1) : break
    end
    num = BigInt(0)
    for c in s
        ci = Int(c)
        (ci < 0 || ci >= 128 || INV[ci+1] < 0) && error("invalid base58 character: $c")
        num = num * 58 + INV[ci+1]
    end
    body = UInt8[]
    while num > 0
        num, rem = divrem(num, 256)
        push!(body, UInt8(rem))
    end
    reverse!(body)
    return vcat(fill(0x00, ones), body)
end

end # module Base58
