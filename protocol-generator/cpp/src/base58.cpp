// base58.cpp — Base58 (Bitcoin alphabet) encode/decode. SPDX-License-Identifier: Apache-2.0
#include "entity_core/base58.hpp"

#include <array>
#include <cstdint>

namespace entity_core::base58 {

namespace {
constexpr std::string_view kAlphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int b58_index(char c) {
    for (int i = 0; i < 58; ++i)
        if (kAlphabet[static_cast<std::size_t>(i)] == c) return i;
    return -1;
}
}  // namespace

std::string encode(std::span<const std::byte> in) {
    std::size_t zeros = 0;
    while (zeros < in.size() && static_cast<std::uint8_t>(in[zeros]) == 0) ++zeros;

    // ceil(in_len * log(256)/log(58)) + 1, log256/log58 ~= 1.365658; 138/100 over-est.
    const std::size_t cap = in.size() * 138 / 100 + 1;
    std::vector<std::uint8_t> digits(cap, 0);

    std::size_t length = 0;  // base58 digits held at the END of `digits`
    for (std::size_t bi = 0; bi < in.size(); ++bi) {
        int carry = static_cast<std::uint8_t>(in[bi]);
        std::size_t k = cap;  // write index, walking backward
        for (std::size_t processed = 0; processed < length || carry != 0; ++processed) {
            --k;
            carry += 256 * digits[k];
            digits[k] = static_cast<std::uint8_t>(carry % 58);
            carry /= 58;
        }
        length = cap - k;
    }

    std::size_t k = cap - length;  // most-significant digit
    std::string out;
    out.reserve(zeros + (cap - k));
    out.append(zeros, '1');
    for (; k < cap; ++k) out.push_back(kAlphabet[digits[k]]);
    return out;
}

Result<std::vector<std::byte>> decode(std::string_view str) {
    std::size_t ones = 0;
    while (ones < str.size() && str[ones] == '1') ++ones;

    // ceil(slen * log(58)/log(256)) + 1, log58/log256 ~= 0.7322; 733/1000 over-est.
    const std::size_t cap = str.size() * 733 / 1000 + 1;
    std::vector<std::uint8_t> bytes(cap, 0);

    std::size_t length = 0;  // base256 bytes held at the END of `bytes`
    for (char ch : str) {
        const int d = b58_index(ch);
        if (d < 0) return std::unexpected(EcfError::BadInput);
        int carry = d;
        std::size_t k = cap;
        for (std::size_t processed = 0; processed < length || carry != 0; ++processed) {
            --k;
            carry += 58 * bytes[k];
            bytes[k] = static_cast<std::uint8_t>(carry & 0xff);
            carry >>= 8;
        }
        length = cap - k;
    }

    const std::size_t k = cap - length;
    const std::size_t body = cap - k;
    std::vector<std::byte> result(ones + body, std::byte{0});  // leading '1' -> 0x00
    for (std::size_t j = 0; j < body; ++j)
        result[ones + j] = std::byte{bytes[k + j]};
    return result;
}

}  // namespace entity_core::base58
