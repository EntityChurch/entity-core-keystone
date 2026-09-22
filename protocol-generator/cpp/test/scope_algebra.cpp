// scope_algebra.cpp — unit gate for the §5 scope algebra as it stands at 0.8.2.25.
//
// WHAT THIS COVERS AND WHAT IT DOES NOT, stated rather than left to inference. These are
// the §5 PRIMITIVES driven directly: the §5.4 sentinel's scope-type scoping (RULE B /
// 0.8.2.24 N2/N3), §5.5a scope_subset's typing by scope kind (RULE E / F50), §5.2
// effective_targets' non-lossy pair (0.8.2.25 N11), §6.3 check_path_permission, and the
// §5.2a decode-boundary cause split (RULE C / 0.8.2.24 N4/N5). The §3.3 LADDER that
// consumes them is a handler-internal path reached only through an authenticated
// dispatch; it is driven end to end by test/smoke.cpp (scenario 4) and by
// tools/arc-probe, which is the cohort instrument for it.
//
// Built under ASan/LSan/UBSan like every other harness here.
//
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <string>
#include <vector>

#include "entity_core/capability.hpp"
#include "entity_core/crypto.hpp"
#include "entity_core/entity.hpp"

using namespace entity_core;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(const char* name, bool ok) {
    if (ok) g_pass++; else g_fail++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

const std::string kLocal = "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg";

EcfValue strlist(std::vector<std::string> items) {
    auto a = EcfValue::array();
    for (const auto& s : items) a.push(EcfValue::text(s));
    return a;
}

EcfValue scope_v(std::vector<std::string> inc, std::vector<std::string> exc) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("exclude"), strlist(std::move(exc)));
    m.put(EcfValue::text("include"), strlist(std::move(inc)));
    return m;
}

EcfValue grant_v(std::vector<std::string> h, std::vector<std::string> o,
                 std::vector<std::string> oe, std::vector<std::string> r,
                 std::vector<std::string> rx) {
    auto g = EcfValue::map();
    g.put(EcfValue::text("handlers"), scope_v(std::move(h), {}));
    g.put(EcfValue::text("operations"), scope_v(std::move(o), std::move(oe)));
    g.put(EcfValue::text("resources"), scope_v(std::move(r), std::move(rx)));
    return g;
}

EntityPtr token_one(EcfValue grant) {
    auto gs = EcfValue::array();
    gs.push(std::move(grant));
    auto m = EcfValue::map();
    m.put(EcfValue::text("grants"), std::move(gs));
    auto e = Entity::make("system/capability/token", std::move(m));
    return e ? *e : nullptr;
}

EntityPtr exec_of(bool have_resource, bool have_targets,
                  std::vector<std::string> targets, std::vector<std::string> excl,
                  bool targets_ill_typed = false) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("operation"), EcfValue::text("get"));
    if (have_resource) {
        auto r = EcfValue::map();
        if (!excl.empty()) r.put(EcfValue::text("exclude"), strlist(std::move(excl)));
        if (targets_ill_typed) {
            r.put(EcfValue::text("targets"), EcfValue::uint(42));
        } else if (have_targets) {
            r.put(EcfValue::text("targets"), strlist(std::move(targets)));
        }
        m.put(EcfValue::text("resource"), std::move(r));
    }
    auto e = Entity::make("system/protocol/execute", std::move(m));
    return e ? *e : nullptr;
}

// ── RULE B — the §5.4 sentinel is scoped to PATH-SCOPE (0.8.2.24 N2/N3) ──────────
void t_sentinel_scoping() {
    std::printf("RULE B: the section 5.4 sentinel is scoped to path-scope (0.8.2.24 N2/N3):\n");
    // THE DEFECT THE SCOPING REMOVES. A bare star, a slash and "apply" is an ordinary
    // namespaced OPERATION name; it path-canonicalizes to the sentinel, and under the
    // unconditional guard this whole dimension denied — over-denial, invisible on
    // well-formed grants. Driven through check_path_permission because matches_scope is
    // file-static; the operations dimension is the one under test.
    auto tok = token_one(grant_v({"system/tree"}, {"*"}, {"*/apply"}, {"*"}, {}));
    const std::string q = "/" + kLocal + "/app/q";
    check("an id-scope exclude that path-canonicalizes to the sentinel does NOT deny the dimension",
          cap::check_path_permission(kLocal, "get", q, *tok, "system/tree"));
    // ... and the id-scope exclude still EXCLUDES its own literal, which is the control
    // that says the dimension is being evaluated rather than waved through.
    check("the same id-scope exclude still denies its own literal operation",
          !cap::check_path_permission(kLocal, "*/apply", q, *tok, "system/tree"));

    // PATH-SCOPE keeps the guard: an unmatchable exclude there denies everything
    // (0.8.2.21), because a path exclude that carves out nothing is a grant silently
    // wider than its author wrote.
    auto t2 = token_one(grant_v({"system/tree"}, {"*"}, {}, {"*"}, {"../nope"}));
    check("a path-scope exclude that canonicalizes to the sentinel DENIES the dimension",
          !cap::check_path_permission(kLocal, "get", q, *t2, "system/tree"));
    // Control: the same dimension with a MATCHABLE exclude still grants elsewhere.
    auto t3 = token_one(grant_v({"system/tree"}, {"*"}, {}, {"*"}, {"app/secret"}));
    check("a matchable path exclude grants elsewhere",
          cap::check_path_permission(kLocal, "get", q, *t3, "system/tree"));
    check("... and denies the excluded path",
          !cap::check_path_permission(kLocal, "get", "/" + kLocal + "/app/secret", *t3,
                                      "system/tree"));
}

// ── RULE E — scope_subset is typed by scope kind (F50, 0.8.2.16) ─────────────────
void t_subset_typing() {
    std::printf("RULE E: scope_subset is typed by scope kind (F50, ruled 0.8.2.16):\n");
    // THE INCLUDE PAIR THAT DISAGREES. Child operations include a star-slash-apply form,
    // parent "*". Under section 3.6's literal matcher "*" covers it and the child is a
    // subset. Under the canonicalizing reading it becomes the sentinel, matches nothing,
    // and the pair is refused — fail-CLOSED, which is why no hand-tried example found it.
    auto child = grant_v({"system/tree"}, {"*/apply"}, {}, {"*"}, {});
    auto parent = grant_v({"system/tree"}, {"*"}, {}, {"*"}, {});
    check("an id-scope child include carrying path syntax is covered by the literal '*'",
          cap::grant_subset(kLocal, kLocal, kLocal, child, parent));

    // THE EXCLUDE PAIR. A parent exclude must be INHERITED by some child exclude; under
    // the canonicalizing reading an unmatchable exclude is not even inherited by an
    // identical copy of itself, so a scope stops being a subset of ITSELF.
    auto both1 = grant_v({"system/tree"}, {"*"}, {"*/apply"}, {"*"}, {});
    auto both2 = grant_v({"system/tree"}, {"*"}, {"*/apply"}, {"*"}, {});
    check("an id-scope exclude carrying path syntax is inherited by an identical copy",
          cap::grant_subset(kLocal, kLocal, kLocal, both1, both2));

    // THE CONTROL, and it is what makes the two above measurements rather than a claim
    // that the function says yes: a genuinely WIDER child is still refused on the id arm.
    auto wide = grant_v({"system/tree"}, {"*"}, {}, {"*"}, {});
    auto narrow = grant_v({"system/tree"}, {"get"}, {}, {"*"}, {});
    check("a wider id-scope child is still refused",
          !cap::grant_subset(kLocal, kLocal, kLocal, wide, narrow));

    // And the PATH arm is unchanged — it must still canonicalize, or section 5.5a's
    // per-link granter frames stop working.
    auto cp = grant_v({"system/tree"}, {"get"}, {}, {"app/q"}, {});
    auto pp = grant_v({"system/tree"}, {"get"}, {}, {"app/*"}, {});
    check("a path-scope child include is still covered by canonicalization",
          cap::grant_subset(kLocal, kLocal, kLocal, cp, pp));
    check("... and the reverse is still refused",
          !cap::grant_subset(kLocal, kLocal, kLocal, pp, cp));
}

// ── RULE A — effective_targets keeps the two empties apart (0.8.2.25 N11) ────────
void t_effective_targets() {
    std::printf("RULE A: effective_targets, the non-lossy pair (0.8.2.25 N11):\n");
    {   // ABSENT: no `resource` at all.
        auto e = exec_of(false, false, {}, {});
        auto eff = cap::effective_targets(kLocal, *e);
        check("no resource at all -> had_resource false",
              !eff.had_resource && eff.survivors.empty());
    }
    {   // PRESENT with survivors — the accept case, and the only one that says the
        // exclude loop is being run rather than short-circuited.
        auto e = exec_of(true, true, {"app/qA", "app/qB"}, {"app/qA"});
        auto eff = cap::effective_targets(kLocal, *e);
        check("the caller's own exclude removes a target, RAW spelling preserved",
              eff.had_resource && eff.survivors.size() == 1 && eff.survivors[0] == "app/qB");
    }
    {   // PRESENT and SELF-EXCLUDED. This is the cell N11 is about — a projection
        // returning only a list collapses it into the absent case above, and the
        // handler's refusal arm becomes dead code.
        auto e = exec_of(true, true, {"app/qA"}, {"app/qA"});
        auto eff = cap::effective_targets(kLocal, *e);
        check("a self-excluded resource is PRESENT with an empty survivor list",
              eff.had_resource && eff.survivors.empty());
    }
    {   // A `resource` map with NO `targets` key is ABSENT. (This case ran GREEN against
        // the pre-change peer on both vanguards — an inert control — so it is asserted
        // here rather than assumed.)
        auto e = exec_of(true, false, {}, {"app/qA"});
        auto eff = cap::effective_targets(kLocal, *e);
        check("a resource map with no `targets` key is the ABSENT case", !eff.had_resource);
    }
    {   // A PRESENT-BUT-ILL-TYPED `targets` is PRESENT, never absent: answering the
        // absent case here would be WIDER than the request, which §3.3 forbids.
        auto e = exec_of(true, true, {}, {}, /*ill_typed=*/true);
        auto eff = cap::effective_targets(kLocal, *e);
        check("a present-but-ill-typed `targets` is PRESENT with no survivors",
              eff.had_resource && eff.survivors.empty());
    }
    {   // The caller-exclude arm is fail-OPEN on an unmatchable pattern (section 5.4):
        // the target SURVIVES. The opposite of the grant arm, deliberately.
        auto e = exec_of(true, true, {"app/qA"}, {"../nope"});
        auto eff = cap::effective_targets(kLocal, *e);
        check("an unmatchable CALLER exclude carves out nothing (fail-open)",
              eff.had_resource && eff.survivors.size() == 1);
    }
}

// ── RULE A — check_path_permission: three dimensions, local frame ────────────────
void t_check_path_permission() {
    std::printf("RULE A: section 6.3 check_path_permission:\n");
    auto tok = token_one(grant_v({"system/tree"}, {"*"}, {}, {"app/*"}, {"app/secret"}));
    const std::string q = "/" + kLocal + "/app/q";
    const std::string secret = "/" + kLocal + "/app/secret";
    const std::string other = "/" + kLocal + "/other/q";

    // THE ACCEPT CASE, AND IT IS THE ONE THAT VALIDATES THE FIXTURE. A predicate test
    // built only from deny cases is indistinguishable from one asserting false == false
    // — a fixture that parses to an empty scope denies everything and every deny case
    // passes for free.
    check("a covered path is permitted",
          cap::check_path_permission(kLocal, "get", q, *tok, "system/tree"));

    // One deny per DIMENSION, because a single deny cannot distinguish "the predicate
    // checks the dimension I care about" from "the predicate denies".
    check("resources exclude denies",
          !cap::check_path_permission(kLocal, "get", secret, *tok, "system/tree"));
    check("resources include denies",
          !cap::check_path_permission(kLocal, "get", other, *tok, "system/tree"));
    check("handlers dimension denies",
          !cap::check_path_permission(kLocal, "get", q, *tok, "system/handler"));
    auto t2 = token_one(grant_v({"system/tree"}, {"put"}, {}, {"app/*"}, {}));
    check("operations dimension denies",
          !cap::check_path_permission(kLocal, "get", q, *t2, "system/tree"));

    // An empty `resources.include` is a legal grant shape (section 5.2: handlers that
    // touch no tree paths) and DENIES every path.
    auto t3 = token_one(grant_v({"system/tree"}, {"*"}, {}, {}, {}));
    check("an empty resources.include denies every path",
          !cap::check_path_permission(kLocal, "get", q, *t3, "system/tree"));

    // A malformed path canonicalizes to the sentinel, which matches no grant — so it
    // falls through to DENY rather than being matched against anything.
    auto t4 = token_one(grant_v({"system/tree"}, {"*"}, {}, {"app/*"}, {}));
    check("a malformed path falls through to DENY",
          !cap::check_path_permission(kLocal, "get", "../escape", *t4, "system/tree"));
}

// ── RULE C — the decode-boundary cause split (0.8.2.24 N4/N5) ────────────────────
EcfValue entity_v(const std::string& type, EcfValue data,
                  const std::byte* hash, std::size_t hlen) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("type"), EcfValue::text(type));
    m.put(EcfValue::text("data"), std::move(data));
    if (hash) m.put(EcfValue::text("content_hash"), value::bytes_value(std::span(hash, hlen)));
    return m;
}

void t_decode_cause_split() {
    std::printf("RULE C: the decode-boundary refusal names its CAUSE (0.8.2.24 N4/N5):\n");
    auto d = EcfValue::map();
    d.put(EcfValue::text("x"), EcfValue::uint(1));
    auto good = *Entity::make("primitive/any", std::move(d));
    auto rd = EcfValue::map();
    rd.put(EcfValue::text("request_id"), EcfValue::text("t1"));
    auto root = *Entity::make("system/protocol/execute", std::move(rd));

    auto wire_of = [](EcfValue m) -> Result<Envelope> {
        auto bytes = ecf::encode(m);
        if (!bytes) return std::unexpected(bytes.error());
        return Envelope::from_wire(*bytes);
    };

    // THE ACCEPT CONTROL FIRST. Without it every refusal below is satisfied by a decoder
    // that refuses everything, and the split says nothing.
    {
        auto m = EcfValue::map();
        m.put(EcfValue::text("root"),
              entity_v(root->type(), root->data(), root->hash().data(), root->hash().size()));
        auto inc = EcfValue::map();
        inc.put(value::bytes_value(good->hash()),
                entity_v(good->type(), good->data(), good->hash().data(), good->hash().size()));
        m.put(EcfValue::text("included"), std::move(inc));
        check("a well-formed envelope still decodes", wire_of(std::move(m)).has_value());
    }
    // §5.2a (N4/N5): "A peer that refuses at the decode boundary MUST answer `400
    // hash_mismatch` [MUST]" and, in the same breath, "`400 non_canonical_ecf` is NOT
    // conformant here [MUST]". A mis-keyed `included` entry carries no tag and its
    // encoding IS canonical; what is false is the claim the KEY makes. Both arms returned
    // NonCanonicalEcf until 0.8.2.24 — right property, wrong code.
    {
        std::array<std::byte, 33> bogus{};
        bogus.fill(std::byte{0x11});
        auto m = EcfValue::map();
        m.put(EcfValue::text("root"),
              entity_v(root->type(), root->data(), root->hash().data(), root->hash().size()));
        auto inc = EcfValue::map();
        inc.put(value::bytes_value(bogus),
                entity_v(good->type(), good->data(), good->hash().data(), good->hash().size()));
        m.put(EcfValue::text("included"), std::move(inc));
        auto r = wire_of(std::move(m));
        check("a mis-keyed `included` entry -> HashMismatch",
              !r && r.error() == ecf::EcfError::HashMismatch);
    }
    // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same class
    // (§1.8 item 1) and takes the same code.
    {
        std::array<std::byte, 33> bogus{};
        bogus.fill(std::byte{0x22});
        auto m = EcfValue::map();
        m.put(EcfValue::text("root"),
              entity_v(root->type(), root->data(), bogus.data(), bogus.size()));
        auto r = wire_of(std::move(m));
        check("a tampered root content_hash -> HashMismatch",
              !r && r.error() == ecf::EcfError::HashMismatch);
    }
    // STRUCTURAL faults stay BadInput -> invalid_request. This is the discriminator: if
    // both causes collapsed into one error value the split above would pass vacuously.
    {
        auto m = EcfValue::map();
        m.put(EcfValue::text("nope"), EcfValue::uint(1));
        auto r = wire_of(std::move(m));
        check("bytes that are not an envelope -> BadInput (not HashMismatch)",
              !r && r.error() == ecf::EcfError::BadInput);
    }
}

}  // namespace

int main() {
    if (auto i = crypto::init(); !i) { std::fprintf(stderr, "crypto init failed\n"); return 1; }
    std::printf("== scope algebra (0.8.2.24 / 0.8.2.25) ==\n");
    t_sentinel_scoping();
    t_subset_typing();
    t_effective_targets();
    t_check_path_permission();
    t_decode_cause_split();
    // The COUNT is asserted, not just the failure list: a gate that examined zero things
    // prints the same word as one that examined twenty-seven (AGENTS.md, ratified).
    const int kFloor = 27;
    if (g_pass + g_fail < kFloor) {
        std::printf("SCOPE-ALGEBRA: FAIL (only %d cases ran, floor is %d)\n",
                    g_pass + g_fail, kFloor);
        return 1;
    }
    std::printf("\nSCOPE-ALGEBRA: %s (%d/%d)\n", g_fail == 0 ? "PASS" : "FAIL",
                g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}
