// conformance.cpp — ECF wire-conformance harness (the codec gate) + uncovered-
// range / Ed25519 RFC-8032 self-tests, hand-rolled assert/count driver (no test
// framework, A-CPP-004), built + run under ASan/LSan/UBSan.
//
// The normative fixture conformance-vectors-v1.cbor is itself a canonical-ECF
// array of vector maps, each carrying its own cross-blessed `canonical` bytes
// (the Go wire-conformance oracle output, 3-way Go × Rust × Python byte-locked).
// The harness decodes the fixture with THIS peer's OWN decoder (a decoder bug is
// itself a conformance failure per ENTITY-CBOR-ENCODING.md §E.3), runs each
// vector through the codec, and byte-compares against the embedded `canonical`.
//
// Dispatch by `kind` + `id` category prefix:
//   decode_reject -> the decoder MUST reject the `canonical` wire bytes
//   encode_equal, category:
//     content_hash -> varint(format_code) || SHA-256(ECF({type,data}))
//     peer_id      -> CBOR-text(Base58(varint(kt)||varint(ht)||digest))
//     signature    -> Ed25519_sign(seed, ECF({type,data}))
//     else         -> plain ECF encode(input)
//
// Usage:  conformance <fixture.cbor>            # full gate (corpus + selftests)
//         conformance <fixture.cbor> --spike    # S2 spike (float + map_keys only)
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/protocol.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ec = entity_core;
using ec::ecf::EcfValue;

namespace {

int g_pass = 0;
int g_fail = 0;

std::string to_hex(std::span<const std::byte> p) {
    static constexpr char H[] = "0123456789abcdef";
    std::string s;
    s.reserve(p.size() * 2);
    for (auto b : p) {
        const auto u = static_cast<std::uint8_t>(b);
        s.push_back(H[u >> 4]);
        s.push_back(H[u & 0xf]);
    }
    return s;
}

std::vector<std::byte> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::vector<char> raw((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
    std::vector<std::byte> out(raw.size());
    std::memcpy(out.data(), raw.data(), raw.size());
    return out;
}

std::string_view as_sv(const EcfValue& v) {
    if (const auto* t = v.get_if<ec::ecf::Text>())
        return std::string_view(reinterpret_cast<const char*>(t->data()), t->size());
    return {};
}

const std::string_view vec_text(const EcfValue& m, std::string_view key) {
    const EcfValue* v = m.find(key);
    return v ? as_sv(*v) : std::string_view{};
}

// Read a small non-negative integer field. Returns true + value if present.
bool vec_uint(const EcfValue& m, std::string_view key, std::uint64_t& out) {
    const EcfValue* v = m.find(key);
    if (!v) return false;
    if (const auto* i = v->get_if<ec::ecf::Int>(); i && !i->negative) {
        out = i->arg;
        return true;
    }
    return false;
}

std::string_view id_category(std::string_view id) {
    const auto dot = id.find('.');
    return dot == std::string_view::npos ? id : id.substr(0, dot);
}

void pass() { ++g_pass; }
void fail(std::string_view id, std::string_view detail) {
    ++g_fail;
    std::printf("FAIL %.*s: %.*s\n", static_cast<int>(id.size()), id.data(),
                static_cast<int>(detail.size()), detail.data());
}

// Produce the canonical output for an `encode_equal` vector.
ec::ecf::Result<std::vector<std::byte>> produce(std::string_view id,
                                                const EcfValue& input) {
    const auto cat = id_category(id);

    if (cat == "content_hash") {
        const EcfValue* type = input.find("type");
        const EcfValue* data = input.find("data");
        if (!type || !data) return std::unexpected(ec::ecf::EcfError::BadInput);
        std::uint64_t fc = 0;
        vec_uint(input, "format_code", fc);  // default 0
        return ec::identity::content_hash(*type, *data, fc);
    }
    if (cat == "peer_id") {
        std::uint64_t kt = 0, ht = 0;
        if (!vec_uint(input, "key_type", kt) || !vec_uint(input, "hash_type", ht))
            return std::unexpected(ec::ecf::EcfError::BadInput);
        const EcfValue* digv = input.find("digest");
        const auto* dig = digv ? digv->get_if<ec::ecf::Bytes>() : nullptr;
        if (!dig) return std::unexpected(ec::ecf::EcfError::BadInput);
        std::string pid = ec::identity::peer_id_format(kt, ht, *dig);
        // canonical = the peer_id string encoded as a CBOR text string
        return ec::ecf::encode(EcfValue::text(pid));
    }
    if (cat == "signature") {
        const EcfValue* seedv = input.find("seed");
        const EcfValue* entity = input.find("entity");
        const auto* seed = seedv ? seedv->get_if<ec::ecf::Bytes>() : nullptr;
        if (!seed || !entity) return std::unexpected(ec::ecf::EcfError::BadInput);
        const EcfValue* type = entity->find("type");
        const EcfValue* data = entity->find("data");
        if (!type || !data) return std::unexpected(ec::ecf::EcfError::BadInput);
        auto sig = ec::crypto::sign_entity(*seed, *type, *data);
        if (!sig) return std::unexpected(sig.error());
        return std::vector<std::byte>(sig->begin(), sig->end());
    }
    // default: plain ECF encode of the input
    return ec::ecf::encode(input);
}

// Run the corpus. If `spike` is set, only float.* and map_keys.* vectors run.
int run_corpus(const char* path, bool spike) {
    auto fbuf = read_file(path);
    if (fbuf.empty()) {
        std::printf("FATAL: cannot read fixture %s\n", path);
        return 1;
    }
    auto top = ec::ecf::decode(fbuf);
    if (!top) {
        std::printf("FATAL: fixture decode failed: %.*s\n",
                    static_cast<int>(ec::ecf::to_string(top.error()).size()),
                    ec::ecf::to_string(top.error()).data());
        return 1;
    }
    const auto* arr = top->get_if<ec::ecf::Array>();
    if (!arr) {
        std::printf("FATAL: fixture top-level is not an array\n");
        return 1;
    }

    int total = 0;
    for (const ec::ecf::Box& mb : *arr) {
        const EcfValue& m = *mb;
        if (!m.is<ec::ecf::Map>()) continue;  // meta / non-vector
        const auto kind = vec_text(m, "kind");
        if (kind.empty()) continue;  // meta entry without a kind
        const auto id = vec_text(m, "id");

        if (spike) {
            const auto cat = id_category(id);
            if (cat != "float" && cat != "map_keys") continue;
        }

        const EcfValue* canonv = m.find("canonical");
        const auto* canon = canonv ? canonv->get_if<ec::ecf::Bytes>() : nullptr;
        if (!canon) {
            fail(id, "missing/invalid canonical bytes");
            ++total;
            continue;
        }

        if (kind == "decode_reject") {
            ++total;
            auto d = ec::ecf::decode(*canon);
            if (d)
                fail(id, "decoder ACCEPTED a reject vector");
            else
                pass();
            continue;
        }
        if (kind == "encode_equal") {
            ++total;
            const EcfValue* input = m.find("input");
            if (!input) {
                fail(id, "missing input");
                continue;
            }
            auto got = produce(id, *input);
            if (!got) {
                std::string d = "produce failed: ";
                d += ec::ecf::to_string(got.error());
                fail(id, d);
                continue;
            }
            if (*got == *canon) {
                pass();
            } else {
                std::string d = "want=" + to_hex(*canon) + " got=" + to_hex(*got);
                fail(id, d);
            }
            continue;
        }
        // unknown kind -> not a testable vector (skip, uncounted)
    }

    if (spike)
        std::printf("== ECF spike: %d/%d PASS, %d FAIL ==\n", g_pass, total, g_fail);
    else
        std::printf("== ECF conformance: %d/%d PASS, %d FAIL ==\n", g_pass, total, g_fail);
    return g_fail == 0 ? 0 : 1;
}

// ── uncovered-range self-tests + Ed25519 RFC-8032 KAT ──────────────────────
bool hexcmp_encode(std::string_view label, const EcfValue& v, std::string_view want) {
    auto enc = ec::ecf::encode(v);
    if (!enc) {
        std::printf("FAIL selftest %.*s: encode err\n", (int)label.size(), label.data());
        ++g_fail;
        return false;
    }
    auto gh = to_hex(*enc);
    if (gh == want) {
        ++g_pass;
        return true;
    }
    std::printf("FAIL selftest %.*s: want=%.*s got=%s\n", (int)label.size(), label.data(),
                (int)want.size(), want.data(), gh.c_str());
    ++g_fail;
    return false;
}

bool roundtrip(std::string_view label, const EcfValue& v) {
    auto e1 = ec::ecf::encode(v);
    if (!e1) { std::printf("FAIL rt %.*s enc1\n", (int)label.size(), label.data()); ++g_fail; return false; }
    auto d = ec::ecf::decode(*e1);
    if (!d) { std::printf("FAIL rt %.*s dec\n", (int)label.size(), label.data()); ++g_fail; return false; }
    auto e2 = ec::ecf::encode(*d);
    if (!e2) { std::printf("FAIL rt %.*s enc2\n", (int)label.size(), label.data()); ++g_fail; return false; }
    if (*e1 == *e2) { ++g_pass; return true; }
    std::printf("FAIL rt %.*s not identical\n", (int)label.size(), label.data());
    ++g_fail;
    return false;
}

void run_selftests() {
    // uint64 = 2^64-1 and 2^63 (above signed-i64 max; native uint64_t carrier)
    hexcmp_encode("u64_max", EcfValue::uint(0xffffffffffffffffULL), "1bffffffffffffffff");
    hexcmp_encode("u63", EcfValue::uint(0x8000000000000000ULL), "1b8000000000000000");
    // nint min -2^64 => major 1, arg = 2^64-1
    hexcmp_encode("nint_min", EcfValue::nint(0xffffffffffffffffULL), "3bffffffffffffffff");

    // float ladder boundaries beyond the corpus
    hexcmp_encode("f16_max", EcfValue::real(65504.0), "f97bff");
    hexcmp_encode("subnormal_smallest_f16", EcfValue::real(5.960464477539063e-08), "f90001");
    hexcmp_encode("f32_not_f16", EcfValue::real(65503.0), "fa477fdf00");
    hexcmp_encode("f64_pi", EcfValue::real(1.1), "fb3ff199999999999a");

    // round-trips
    {
        auto m = EcfValue::map();
        m.put(EcfValue::text("z"), EcfValue::uint(1));
        m.put(EcfValue::text("a"), EcfValue::special(ec::ecf::FloatSpecial::NaN));
        m.put(EcfValue::text("bb"), EcfValue::boolean(true));
        roundtrip("mixed_map", m);
    }
    roundtrip("neg_zero", EcfValue::special(ec::ecf::FloatSpecial::NegZero));

    // N2: bare tag 55799 (d9 d9 f7) must reject even at top level
    {
        const std::uint8_t wire[] = {0xd9, 0xd9, 0xf7, 0xa0};
        std::span<const std::byte> sp{reinterpret_cast<const std::byte*>(wire), sizeof(wire)};
        auto d = ec::ecf::decode(sp);
        if (!d && d.error() == ec::ecf::EcfError::TagRejected) ++g_pass;
        else { std::printf("FAIL selftest bare_tag\n"); ++g_fail; }
    }

    // N1: synthetic varint 128 -> 0x80 0x01
    {
        auto b = ec::varint::encode(128);
        if (b.size() == 2 && static_cast<std::uint8_t>(b[0]) == 0x80 &&
            static_cast<std::uint8_t>(b[1]) == 0x01)
            ++g_pass;
        else { std::printf("FAIL selftest varint128\n"); ++g_fail; }
    }

    // base58 leading-zero preservation round-trip
    {
        const std::uint8_t raw[] = {0x00, 0x00, 0x01, 0x02, 0xff};
        std::span<const std::byte> sp{reinterpret_cast<const std::byte*>(raw), sizeof(raw)};
        auto s = ec::base58::encode(sp);
        auto back = ec::base58::decode(s);
        if (back && back->size() == sizeof(raw) &&
            std::memcmp(back->data(), raw, sizeof(raw)) == 0)
            ++g_pass;
        else { std::printf("FAIL selftest base58_rt\n"); ++g_fail; }
    }

    // peer_id from a 32-byte Ed25519 pubkey -> §1.5 (0x01, 0x00, raw pubkey)
    {
        std::array<std::byte, 32> pk{};
        for (int i = 0; i < 32; ++i) pk[i] = std::byte{static_cast<std::uint8_t>(i)};
        auto pid = ec::identity::peer_id_from_pubkey(ec::identity::kKeyTypeEd25519, pk);
        if (pid) {
            auto parts = ec::identity::peer_id_parse(*pid);
            if (parts && parts->key_type == 0x01 && parts->hash_type == 0x00 &&
                parts->digest.size() == 32 &&
                std::memcmp(parts->digest.data(), pk.data(), 32) == 0)
                ++g_pass;
            else { std::printf("FAIL selftest peer_id_canonical\n"); ++g_fail; }
        } else { std::printf("FAIL selftest peer_id_from_pubkey\n"); ++g_fail; }
    }

    // Ed25519 RFC-8032 TEST 1: all-zero seed -> known public key.
    {
        std::array<std::byte, 32> seed{};
        auto pk = ec::crypto::ed25519_pubkey(seed);
        const std::uint8_t want[32] = {
            0x3b,0x6a,0x27,0xbc,0xce,0xb6,0xa4,0x2d,0x62,0xa3,0xa8,0xd0,0x2a,0x6f,0x0d,0x73,
            0x65,0x32,0x15,0x77,0x1d,0xe2,0x43,0xa6,0x3a,0xc0,0x48,0xa1,0x8b,0x59,0xda,0x29};
        if (pk && std::memcmp(pk->data(), want, 32) == 0) ++g_pass;
        else { std::printf("FAIL selftest ed25519_rfc8032_pk\n"); ++g_fail; }
    }

    // Ed25519 sign/verify/tamper round-trip
    {
        std::array<std::byte, 32> seed{};
        for (int i = 0; i < 32; ++i) seed[i] = std::byte{static_cast<std::uint8_t>(i)};
        const std::uint8_t msg[] = {1, 2, 3, 4, 5};
        std::span<const std::byte> msgsp{reinterpret_cast<const std::byte*>(msg), sizeof(msg)};
        auto pk = ec::crypto::ed25519_pubkey(seed);
        auto sig = ec::crypto::ed25519_sign(seed, msgsp);
        if (pk && sig) {
            auto ok = ec::crypto::ed25519_verify(*pk, *sig, msgsp);
            auto tampered = *sig;
            tampered[0] = std::byte{static_cast<std::uint8_t>(~static_cast<std::uint8_t>(tampered[0]))};
            auto bad = ec::crypto::ed25519_verify(*pk, tampered, msgsp);
            if (ok && !bad) ++g_pass;
            else { std::printf("FAIL selftest ed25519_signverify\n"); ++g_fail; }
        } else { std::printf("FAIL selftest ed25519_signverify setup\n"); ++g_fail; }
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <fixture.cbor> [--spike]\n", argv[0]);
        return 2;
    }
    if (auto r = ec::crypto::init(); !r) {
        std::printf("FATAL: libsodium init failed\n");
        return 1;
    }
    const bool spike = (argc >= 3 && std::strcmp(argv[2], "--spike") == 0);

    int rc = run_corpus(argv[1], spike);
    if (!spike) {
        run_selftests();
        std::printf("== selftests: %d PASS, %d FAIL (total) ==\n", g_pass, g_fail);
        rc = g_fail == 0 ? 0 : 1;
    }
    return rc;
}
