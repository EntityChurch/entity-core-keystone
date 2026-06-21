// ecf.cpp — canonical ECF (CBOR) encoder + structural decoder.
// See include/entity_core/ecf.hpp for the contract. SPDX-License-Identifier: Apache-2.0
#include "entity_core/ecf.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

namespace entity_core::ecf {

namespace {
constexpr int kMaxDepth = 64;  // ECF §10.2 nesting depth limit
}  // namespace

std::string_view to_string(EcfError e) noexcept {
    switch (e) {
        case EcfError::Truncated:       return "truncated_input";
        case EcfError::NonCanonicalEcf: return "non_canonical_ecf";
        case EcfError::TagRejected:     return "tag_rejected";
        case EcfError::DuplicateKey:    return "duplicate_key";
        case EcfError::NonTextByteKey:  return "non_text_byte_key";
        case EcfError::DepthExceeded:   return "depth_exceeded";
        case EcfError::BadInput:        return "bad_input";
    }
    return "unknown";
}

const EcfValue* EcfValue::find(std::string_view text_key) const noexcept {
    const auto* m = std::get_if<Map>(&v_);
    if (!m) return nullptr;
    const auto* want = reinterpret_cast<const char8_t*>(text_key.data());
    for (const auto& e : *m) {
        const auto* k = std::get_if<Text>(&e.key->as_variant());
        if (k && k->size() == text_key.size() &&
            std::memcmp(k->data(), want, text_key.size()) == 0) {
            return &*e.value;
        }
    }
    return nullptr;
}

// ──────────────────────────────── encode ────────────────────────────────────
namespace {

using Buf = std::vector<std::byte>;

inline void put(Buf& b, std::uint8_t x) { b.push_back(std::byte{x}); }

// Emit a CBOR head: major (0..7) with the shortest argument for `arg` (Rule 1).
void enc_head(Buf& b, int major, std::uint64_t arg) {
    const std::uint8_t m = static_cast<std::uint8_t>(major << 5);
    if (arg < 24) {
        put(b, m | static_cast<std::uint8_t>(arg));
    } else if (arg < 0x100ULL) {
        put(b, m | 24);
        put(b, static_cast<std::uint8_t>(arg));
    } else if (arg < 0x10000ULL) {
        put(b, m | 25);
        put(b, static_cast<std::uint8_t>(arg >> 8));
        put(b, static_cast<std::uint8_t>(arg));
    } else if (arg < 0x100000000ULL) {
        put(b, m | 26);
        for (int i = 3; i >= 0; --i) put(b, static_cast<std::uint8_t>(arg >> (8 * i)));
    } else {
        put(b, m | 27);
        for (int i = 7; i >= 0; --i) put(b, static_cast<std::uint8_t>(arg >> (8 * i)));
    }
}

// ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ────────
// Pure-integer representability test (no f16 hardware). std::bit_cast keeps it
// strict-aliasing-clean (UBSan on in tests).

double f16_to_double(int h) {
    const int sign = (h >> 15) & 0x1;
    const int exp = (h >> 10) & 0x1f;
    const int mant = h & 0x3ff;
    const double s = (sign == 1) ? -1.0 : 1.0;
    if (exp == 0) {
        if (mant == 0) return s * 0.0;
        double v = static_cast<double>(mant);
        for (int i = 0; i < 24; ++i) v *= 0.5;  // mant * 2^-24
        return s * v;
    }
    // (1024 + mant) * 2^(exp-25)  (exp==0x1f handled by caller as special)
    double v = static_cast<double>(1024 + mant);
    int e = exp - 25;
    if (e >= 0) {
        for (int i = 0; i < e; ++i) v *= 2.0;
    } else {
        for (int i = 0; i < -e; ++i) v *= 0.5;
    }
    return s * v;
}

// Convert a finite double to a 16-bit IEEE half if exactly representable.
bool double_to_f16(double f, int& out) {
    const std::uint64_t bits = std::bit_cast<std::uint64_t>(f);
    const int sign = static_cast<int>((bits >> 63) & 0x1);
    const int exp = static_cast<int>((bits >> 52) & 0x7ff);
    const std::uint64_t mant = bits & 0xfffffffffffffULL;
    if (exp == 0x7ff) return false;  // inf/nan are specials, not here
    if (exp == 0 && mant == 0) {
        out = (sign == 1) ? 0x8000 : 0x0000;
        return true;
    }
    int unbiased;
    std::uint64_t full_mant;  // 53-bit significand incl. implicit leading 1
    if (exp == 0) {
        // subnormal double — normalize
        const int lead = std::countl_zero(mant) - (63 - 52);
        unbiased = -1022 - lead;
        full_mant = (mant << (lead + 1)) & 0x1fffffffffffffULL;
        full_mant |= 0x10000000000000ULL;
    } else {
        unbiased = exp - 1023;
        full_mant = mant | 0x10000000000000ULL;
    }
    const int he = unbiased + 15;  // half biased exponent
    if (he > 30) return false;     // too large for finite f16
    if (he >= 1) {
        // normalized f16: low 42 mantissa bits must be zero (10-bit fraction)
        if ((mant & 0x3ffffffffffULL) != 0) return false;
        const int hmant = static_cast<int>(mant >> 42);
        out = (sign << 15) | (he << 10) | hmant;
        return true;
    }
    // subnormal f16 (he <= 0): value = full_mant * 2^(unbiased-52); representable
    // iff full_mant divisible by 2^shift and quotient in [1,1023].
    const int scaled_exp = (unbiased - 52) + 24;
    if (scaled_exp >= 0) {
        if (scaled_exp >= 11) return false;
        const std::uint64_t scaled = full_mant << scaled_exp;
        if (scaled >= 1 && scaled <= 1023) {
            out = (sign << 15) | static_cast<int>(scaled);
            return true;
        }
        return false;
    }
    const int shift = -scaled_exp;
    if (shift >= 64 || (full_mant & ((std::uint64_t{1} << shift) - 1)) != 0) return false;
    const std::uint64_t q = full_mant >> shift;
    if (q >= 1 && q <= 1023) {
        out = (sign << 15) | static_cast<int>(q);
        return true;
    }
    return false;
}

void enc_float(Buf& b, double f) {
    // -0.0 is canonical f16 (Rule 4a). (+0.0 falls through to the f16 path.)
    if (f == 0.0 && std::bit_cast<std::uint64_t>(f) != 0) {
        put(b, 0xf9); put(b, 0x80); put(b, 0x00);
        return;
    }
    int h;
    if (double_to_f16(f, h) && f16_to_double(h) == f) {
        put(b, 0xf9);
        put(b, static_cast<std::uint8_t>(h >> 8));
        put(b, static_cast<std::uint8_t>(h));
        return;
    }
    const float sf = static_cast<float>(f);
    if (static_cast<double>(sf) == f) {
        const std::uint32_t bits = std::bit_cast<std::uint32_t>(sf);
        put(b, 0xfa);
        for (int i = 3; i >= 0; --i) put(b, static_cast<std::uint8_t>(bits >> (8 * i)));
        return;
    }
    const std::uint64_t bits = std::bit_cast<std::uint64_t>(f);
    put(b, 0xfb);
    for (int i = 7; i >= 0; --i) put(b, static_cast<std::uint8_t>(bits >> (8 * i)));
}

Result<void> enc_value(const EcfValue& v, Buf& b, int depth);

// Length-FIRST then byte-lexicographic on encoded-key octets (ECF Rule 2 / CTAP2).
struct EncEntry {
    Buf key;
    Buf val;
};

bool key_order(const EncEntry& a, const EncEntry& b) {
    if (a.key.size() != b.key.size()) return a.key.size() < b.key.size();
    return std::memcmp(a.key.data(), b.key.data(), a.key.size()) < 0;
}

Result<void> enc_map(const Map& m, Buf& b, int depth) {
    std::vector<EncEntry> entries;
    entries.reserve(m.size());
    for (const auto& e : m) {
        EncEntry ee;
        if (auto r = enc_value(*e.key, ee.key, depth + 1); !r) return r;
        if (auto r = enc_value(*e.value, ee.val, depth + 1); !r) return r;
        entries.push_back(std::move(ee));
    }
    if (entries.size() > 1) std::sort(entries.begin(), entries.end(), key_order);

    enc_head(b, 5, entries.size());
    for (const auto& e : entries) {
        b.insert(b.end(), e.key.begin(), e.key.end());
        b.insert(b.end(), e.val.begin(), e.val.end());
    }
    return {};
}

Result<void> enc_value(const EcfValue& v, Buf& b, int depth) {
    if (depth > kMaxDepth) return std::unexpected(EcfError::DepthExceeded);
    return std::visit(
        [&](const auto& x) -> Result<void> {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, Int>) {
                enc_head(b, x.negative ? 1 : 0, x.arg);
            } else if constexpr (std::is_same_v<T, double>) {
                enc_float(b, x);
            } else if constexpr (std::is_same_v<T, FloatSpecial>) {
                switch (x) {
                    case FloatSpecial::NaN:     put(b, 0xf9); put(b, 0x7e); put(b, 0x00); break;
                    case FloatSpecial::PosInf:  put(b, 0xf9); put(b, 0x7c); put(b, 0x00); break;
                    case FloatSpecial::NegInf:  put(b, 0xf9); put(b, 0xfc); put(b, 0x00); break;
                    case FloatSpecial::NegZero: put(b, 0xf9); put(b, 0x80); put(b, 0x00); break;
                }
            } else if constexpr (std::is_same_v<T, bool>) {
                put(b, x ? 0xf5 : 0xf4);
            } else if constexpr (std::is_same_v<T, Null>) {
                put(b, 0xf6);
            } else if constexpr (std::is_same_v<T, Bytes>) {
                enc_head(b, 2, x.size());
                b.insert(b.end(), x.begin(), x.end());
            } else if constexpr (std::is_same_v<T, Text>) {
                enc_head(b, 3, x.size());
                const auto* p = reinterpret_cast<const std::byte*>(x.data());
                b.insert(b.end(), p, p + x.size());
            } else if constexpr (std::is_same_v<T, Array>) {
                enc_head(b, 4, x.size());
                for (const auto& item : x) {
                    if (auto r = enc_value(*item, b, depth + 1); !r) return r;
                }
            } else if constexpr (std::is_same_v<T, Map>) {
                return enc_map(x, b, depth);
            }
            return Result<void>{};
        },
        v.as_variant());
}

}  // namespace

Result<std::vector<std::byte>> encode(const EcfValue& v) {
    Buf b;
    if (auto r = enc_value(v, b, 0); !r) return std::unexpected(r.error());
    return b;
}

// ──────────────────────────────── decode ────────────────────────────────────
namespace {

struct Cursor {
    std::span<const std::byte> in;
    std::size_t i = 0;

    std::size_t remaining() const noexcept { return in.size() - i; }
    std::uint8_t byte_at(std::size_t k) const noexcept {
        return static_cast<std::uint8_t>(in[k]);
    }
};

Result<EcfValue> dec_value(Cursor& c, int depth);

// Decode a CBOR head argument; enforce minimal (canonical) encoding.
Result<std::uint64_t> dec_arg(Cursor& c, int info) {
    if (info < 24) return static_cast<std::uint64_t>(info);
    switch (info) {
        case 24: {
            if (c.remaining() < 1) return std::unexpected(EcfError::Truncated);
            std::uint64_t v = c.byte_at(c.i);
            c.i += 1;
            if (v < 24) return std::unexpected(EcfError::NonCanonicalEcf);
            return v;
        }
        case 25: {
            if (c.remaining() < 2) return std::unexpected(EcfError::Truncated);
            std::uint64_t v = (std::uint64_t{c.byte_at(c.i)} << 8) | c.byte_at(c.i + 1);
            c.i += 2;
            if (v < 0x100ULL) return std::unexpected(EcfError::NonCanonicalEcf);
            return v;
        }
        case 26: {
            if (c.remaining() < 4) return std::unexpected(EcfError::Truncated);
            std::uint64_t v = 0;
            for (int k = 0; k < 4; ++k) v = (v << 8) | c.byte_at(c.i + k);
            c.i += 4;
            if (v < 0x10000ULL) return std::unexpected(EcfError::NonCanonicalEcf);
            return v;
        }
        case 27: {
            if (c.remaining() < 8) return std::unexpected(EcfError::Truncated);
            std::uint64_t v = 0;
            for (int k = 0; k < 8; ++k) v = (v << 8) | c.byte_at(c.i + k);
            c.i += 8;
            if (v < 0x100000000ULL) return std::unexpected(EcfError::NonCanonicalEcf);
            return v;
        }
        default:  // 28,29,30 reserved; 31 indefinite — both non-canonical
            return std::unexpected(EcfError::NonCanonicalEcf);
    }
}

Result<std::size_t> dec_len(Cursor& c, int info) {
    auto v = dec_arg(c, info);
    if (!v) return std::unexpected(v.error());
    if (*v > std::numeric_limits<std::size_t>::max())
        return std::unexpected(EcfError::NonCanonicalEcf);
    return static_cast<std::size_t>(*v);
}

// major 7 simple/float decode.
Result<EcfValue> dec_simple(Cursor& c, int info) {
    switch (info) {
        case 20: return EcfValue::boolean(false);
        case 21: return EcfValue::boolean(true);
        case 22: return EcfValue::null();
        case 25: {  // f16
            if (c.remaining() < 2) return std::unexpected(EcfError::Truncated);
            const int h = (c.byte_at(c.i) << 8) | c.byte_at(c.i + 1);
            c.i += 2;
            const int s = (h >> 15) & 1, e = (h >> 10) & 0x1f, m = h & 0x3ff;
            if (e == 0x1f)
                return m == 0 ? EcfValue::special(s ? FloatSpecial::NegInf : FloatSpecial::PosInf)
                              : EcfValue::special(FloatSpecial::NaN);
            if (e == 0 && m == 0)
                return s ? EcfValue::special(FloatSpecial::NegZero) : EcfValue::real(0.0);
            return EcfValue::real(f16_to_double(h));
        }
        case 26: {  // f32
            if (c.remaining() < 4) return std::unexpected(EcfError::Truncated);
            std::uint32_t bits = 0;
            for (int k = 0; k < 4; ++k) bits = (bits << 8) | c.byte_at(c.i + k);
            c.i += 4;
            const int s = static_cast<int>((bits >> 31) & 1), e = static_cast<int>((bits >> 23) & 0xff);
            const std::uint32_t mm = bits & 0x7fffff;
            if (e == 0xff)
                return mm == 0 ? EcfValue::special(s ? FloatSpecial::NegInf : FloatSpecial::PosInf)
                               : EcfValue::special(FloatSpecial::NaN);
            if (e == 0 && mm == 0)
                return s ? EcfValue::special(FloatSpecial::NegZero) : EcfValue::real(0.0);
            return EcfValue::real(static_cast<double>(std::bit_cast<float>(bits)));
        }
        case 27: {  // f64
            if (c.remaining() < 8) return std::unexpected(EcfError::Truncated);
            std::uint64_t bits = 0;
            for (int k = 0; k < 8; ++k) bits = (bits << 8) | c.byte_at(c.i + k);
            c.i += 8;
            const int s = static_cast<int>((bits >> 63) & 1), e = static_cast<int>((bits >> 52) & 0x7ff);
            const std::uint64_t mm = bits & 0xfffffffffffffULL;
            if (e == 0x7ff)
                return mm == 0 ? EcfValue::special(s ? FloatSpecial::NegInf : FloatSpecial::PosInf)
                               : EcfValue::special(FloatSpecial::NaN);
            if (e == 0 && mm == 0)
                return s ? EcfValue::special(FloatSpecial::NegZero) : EcfValue::real(0.0);
            return EcfValue::real(std::bit_cast<double>(bits));
        }
        default:  // incl. f7 undefined, simple-value bytes
            return std::unexpected(EcfError::NonCanonicalEcf);
    }
}

bool key_equal(const EcfValue& a, const EcfValue& b) {
    if (const auto* ta = a.get_if<Text>()) {
        const auto* tb = b.get_if<Text>();
        return tb && *ta == *tb;
    }
    if (const auto* ba = a.get_if<Bytes>()) {
        const auto* bb = b.get_if<Bytes>();
        return bb && *ba == *bb;
    }
    return false;
}

Result<EcfValue> dec_value(Cursor& c, int depth) {
    if (depth > kMaxDepth) return std::unexpected(EcfError::DepthExceeded);
    if (c.remaining() < 1) return std::unexpected(EcfError::Truncated);
    const int ib = c.byte_at(c.i);
    const int major = ib >> 5;
    const int info = ib & 0x1f;
    c.i++;

    switch (major) {
        case 0: {
            auto arg = dec_arg(c, info);
            if (!arg) return std::unexpected(arg.error());
            return EcfValue::uint(*arg);
        }
        case 1: {
            auto arg = dec_arg(c, info);
            if (!arg) return std::unexpected(arg.error());
            return EcfValue::nint(*arg);
        }
        case 2: {
            auto len = dec_len(c, info);
            if (!len) return std::unexpected(len.error());
            if (c.remaining() < *len) return std::unexpected(EcfError::Truncated);
            EcfValue v = EcfValue::bytes(c.in.subspan(c.i, *len));
            c.i += *len;
            return v;
        }
        case 3: {
            auto len = dec_len(c, info);
            if (!len) return std::unexpected(len.error());
            if (c.remaining() < *len) return std::unexpected(EcfError::Truncated);
            const auto* p = reinterpret_cast<const char8_t*>(c.in.data() + c.i);
            EcfValue v = EcfValue::text(Text(p, *len));
            c.i += *len;
            return v;
        }
        case 4: {
            auto len = dec_len(c, info);
            if (!len) return std::unexpected(len.error());
            Array arr;
            arr.reserve(*len);
            for (std::size_t k = 0; k < *len; ++k) {
                auto item = dec_value(c, depth + 1);
                if (!item) return std::unexpected(item.error());
                arr.emplace_back(std::move(*item));
            }
            return EcfValue::array(std::move(arr));
        }
        case 5: {
            auto len = dec_len(c, info);
            if (!len) return std::unexpected(len.error());
            Map map;
            map.reserve(*len);
            for (std::size_t k = 0; k < *len; ++k) {
                auto key = dec_value(c, depth + 1);
                if (!key) return std::unexpected(key.error());
                if (!key->is<Text>() && !key->is<Bytes>())
                    return std::unexpected(EcfError::NonTextByteKey);
                for (const auto& e : map) {
                    if (key_equal(*e.key, *key)) return std::unexpected(EcfError::DuplicateKey);
                }
                auto val = dec_value(c, depth + 1);
                if (!val) return std::unexpected(val.error());
                map.push_back(MapEntry{Box{std::move(*key)}, Box{std::move(*val)}});
            }
            return EcfValue::map(std::move(map));
        }
        case 6:
            // N2: major-type-6 tag rejected anywhere, any depth.
            return std::unexpected(EcfError::TagRejected);
        case 7:
            return dec_simple(c, info);
        default:
            return std::unexpected(EcfError::NonCanonicalEcf);
    }
}

}  // namespace

Result<EcfValue> decode(std::span<const std::byte> in) {
    Cursor c{in, 0};
    auto v = dec_value(c, 0);
    if (!v) return v;
    if (c.i < in.size()) return std::unexpected(EcfError::NonCanonicalEcf);  // trailing bytes
    return v;
}

}  // namespace entity_core::ecf
