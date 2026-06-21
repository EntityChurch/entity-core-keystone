// typereg.cpp — render-from-model byte-diff harness for the §9.5 53-type core floor.
// Builds each core type's `data` map (the GENERATED core_typedefs table), materializes a
// `system/type` entity (content_hash computed by our own S2-green codec), and diffs the
// 32-byte SHA-256 digest against the canonical type-registry-vectors-v1.cbor (decoded with
// our own decoder — a free cross-check of the decoder too). Argv[1] = the .cbor vectors.
//
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "entity_core/core_typedefs.hpp"
#include "entity_core/entity.hpp"

using namespace entity_core;

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: typereg <vectors.cbor>\n"); return 2; }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    std::vector<std::byte> buf;
    {
        std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        buf.resize(raw.size());
        std::memcpy(buf.data(), raw.data(), raw.size());
    }
    auto decoded = ecf::decode(buf);
    if (!decoded) {
        std::fprintf(stderr, "decode vectors failed: %s\n",
                     std::string(ecf::to_string(decoded.error())).c_str());
        return 2;
    }
    // Build name → expected lowercase-hex (strip the "ecf-sha256:" prefix).
    std::map<std::string, std::string> expected;
    if (decoded->is<ecf::Array>()) {
        for (const auto& box : std::get<ecf::Array>(decoded->as_variant())) {
            const auto& m = *box;
            if (auto n = value::text(m, "name")) {
                if (auto ch = value::text(m, "content_hash")) {
                    auto colon = ch->find(':');
                    expected[*n] = (colon == std::string::npos) ? *ch : ch->substr(colon + 1);
                }
            }
        }
    }

    int pass = 0, fail = 0;
    for (const auto& td : types::core_typedefs()) {
        auto e = Entity::make("system/type", td.build());
        if (!e) { std::fprintf(stderr, "make failed: %s\n", td.name.c_str()); fail++; continue; }
        // hash() is 33 bytes (0x00 || digest); the vectors carry the 32-byte digest.
        std::span<const std::byte> digest((*e)->hash().data() + 1, 32);
        std::string got = identity::hex_lower(digest);
        auto it = expected.find(td.name);
        bool ok = it != expected.end() && it->second == got;
        if (ok) pass++; else fail++;
        if (!ok) {
            std::printf("  [FAIL] %s\n    got      %s\n    expected %s\n", td.name.c_str(),
                        got.c_str(), it != expected.end() ? it->second.c_str() : "(absent)");
        }
    }
    std::printf("TYPE-REGISTRY: %s (%d/%d)\n", fail == 0 ? "PASS" : "FAIL", pass, pass + fail);
    return fail == 0 ? 0 : 1;
}
