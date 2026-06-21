// ffi_xcheck.cpp — free byte-for-byte cross-check of THIS native C++ codec against
// the sibling C-ABI FFI codec libentitycore_codec (entity-core-codec-ffi-c), the
// independent oracle the profile names (A-CPP-001). NOT the conformance gate (the
// 69/69 corpus vs the Go×Rust×Python byte-lock is that) — this is extra assurance
// that the two impls agree byte-for-byte on entity encoding + content_hash across a
// battery that includes ranges the corpus does NOT cover (the full u64 / -2^64 band,
// float-ladder edges — codec-review-heuristic.md). The FFI ec_encode_ecf takes
// pre-encoded {type,data} byte slices and re-emits the canonical {type,data} entity;
// we feed it OUR sub-encodings and compare the whole-entity bytes + content_hash.
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/protocol.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

extern "C" {
int32_t ec_encode_ecf(const uint8_t* type_ptr, size_t type_len, const uint8_t* data_ptr,
                      size_t data_len, uint8_t* out_ptr, size_t out_cap, size_t* out_len);
int32_t ec_content_hash(const uint8_t* type_ptr, size_t type_len, const uint8_t* data_ptr,
                        size_t data_len, uint8_t* out_ptr /* 33 */);
}

namespace ec = entity_core;
using ec::ecf::EcfValue;

namespace {
int g_pass = 0, g_fail = 0;

std::string hx(std::span<const std::byte> p) {
    static constexpr char H[] = "0123456789abcdef";
    std::string s;
    for (auto b : p) {
        const auto u = static_cast<std::uint8_t>(b);
        s.push_back(H[u >> 4]);
        s.push_back(H[u & 0xf]);
    }
    return s;
}

// Encode {type,data} two ways (ours + FFI) and compare. Per the C-ABI §4.1, the
// FFI takes `type` as RAW UTF-8 text bytes and `data` as a PRE-ENCODED ECF value
// slice; it wraps them as {type:<text>, data:<value>}. We mirror that: our type
// node is a text value, our data node is an arbitrary value.
void check_entity(const char* label, std::string_view type_text, const EcfValue& data) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("type"), EcfValue::text(type_text));
    m.put(EcfValue::text("data"), data);
    auto ours = ec::ecf::encode(m);

    auto de = ec::ecf::encode(data);  // pre-encoded data value for the FFI
    if (!ours || !de) { std::printf("FAIL %s: our encode err\n", label); ++g_fail; return; }

    const auto* tp = reinterpret_cast<const std::uint8_t*>(type_text.data());
    std::vector<std::uint8_t> out(4096);
    std::size_t out_len = 0;
    int rc = ec_encode_ecf(tp, type_text.size(),
                           reinterpret_cast<const std::uint8_t*>(de->data()), de->size(),
                           out.data(), out.size(), &out_len);
    if (rc != 0) { std::printf("FAIL %s: ffi encode rc=%d\n", label, rc); ++g_fail; return; }
    std::span<const std::byte> ffi{reinterpret_cast<const std::byte*>(out.data()), out_len};
    if (ours->size() == out_len && std::memcmp(ours->data(), out.data(), out_len) == 0) {
        ++g_pass;
    } else {
        std::printf("FAIL %s entity: ours=%s ffi=%s\n", label, hx(*ours).c_str(), hx(ffi).c_str());
        ++g_fail;
    }

    // content_hash cross-check (format 0x00).
    auto our_ch = ec::identity::content_hash(EcfValue::text(type_text), data, 0x00);
    std::uint8_t ffi_ch[33];
    int rc2 = ec_content_hash(tp, type_text.size(),
                              reinterpret_cast<const std::uint8_t*>(de->data()), de->size(), ffi_ch);
    if (!our_ch || rc2 != 0) { std::printf("FAIL %s: content_hash err\n", label); ++g_fail; return; }
    if (our_ch->size() == 33 && std::memcmp(our_ch->data(), ffi_ch, 33) == 0) {
        ++g_pass;
    } else {
        std::printf("FAIL %s content_hash mismatch\n", label);
        ++g_fail;
    }
}
}  // namespace

int main() {
    if (auto r = ec::crypto::init(); !r) { std::printf("FATAL: sodium init\n"); return 1; }

    // type is always a text label; data spans the value-model surface incl. the
    // uncovered u64 / -2^64 band and float-ladder edges (corpus tops out at i64max).
    check_entity("uint_small", "t/v1", EcfValue::uint(1));
    check_entity("u64_max", "t/v1", EcfValue::uint(0xffffffffffffffffULL));
    check_entity("u63", "t/v1", EcfValue::uint(0x8000000000000000ULL));
    check_entity("nint_min", "t/v1", EcfValue::nint(0xffffffffffffffffULL));
    check_entity("float_half", "t/v1", EcfValue::real(1.5));
    check_entity("float_f16max", "t/v1", EcfValue::real(65504.0));
    check_entity("float_f32", "t/v1", EcfValue::real(65503.0));
    check_entity("float_f64", "t/v1", EcfValue::real(1.1));
    check_entity("neg_zero", "t/v1", EcfValue::special(ec::ecf::FloatSpecial::NegZero));
    check_entity("nan", "t/v1", EcfValue::special(ec::ecf::FloatSpecial::NaN));
    check_entity("text", "t/v1", EcfValue::text("hello"));
    check_entity("bytes", "t/v1", EcfValue::bytes(ec::ecf::Bytes{std::byte{1}, std::byte{2}}));
    {
        auto m = EcfValue::map();
        m.put(EcfValue::text("z"), EcfValue::uint(1));
        m.put(EcfValue::text("a"), EcfValue::uint(2));
        m.put(EcfValue::text("mm"), EcfValue::uint(3));  // exercises length-then-lex sort
        check_entity("nested_map", "t/v1", m);
    }
    {
        auto a = EcfValue::array();
        a.push(EcfValue::uint(1));
        a.push(EcfValue::real(2.5));
        a.push(EcfValue::boolean(true));
        check_entity("array", "t/v1", a);
    }

    std::printf("== FFI cross-check: %d PASS, %d FAIL ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
