// entity_core/ecf.hpp — Entity Canonical Form (ECF) codec: value model +
// canonical CBOR encoder + structural decoder, idiomatic C++.
//
// Peer: entity-core-protocol-cpp (release "reach" peer, C++20/23 idiom — RAII /
// std::expected / std::span / move semantics). Per ENTITY-CBOR-ENCODING.md v1.5
// (spec-data v7.71/v7.75 byte-stable). No C++ CBOR library gives ECF's
// guarantees (A-CPP-001), so the canonical layer is owned here:
//   - minimal integer encoding (Rule 1) — full uint64 / -2^64 head-form range,
//     carried natively in std::uint64_t (Int: negative flag + magnitude/argument);
//   - map keys sorted by ENCODED key bytes, length-FIRST then byte-lexicographic
//     (ECF Rule 2 / CTAP2 — DIFFERS from RFC-8949 §4.2 pure-bytewise);
//   - definite lengths only (Rule 3) — no 0x5f/0x7f/0x9f/0xbf;
//   - shortest float preserving value incl. f16 (Rule 4) + Rule-4a specials
//     (NaN f97e00 / +Inf f97c00 / -Inf f9fc00 / -0.0 f98000);
//   - recursive major-type-6 (tag) rejection on decode (N2; §6.3);
//   - empty map = the single byte 0xA0 (N3 — falls out of the generic encoder).
//
// Error model (A-CPP-007): value-based std::expected<T, EcfError>. NO exceptions
// on the codec hot path. Memory: RAII — EcfValue owns its children via value
// containers (std::vector / std::u8string); destructors free deterministically,
// no raw new/delete/free. Decode COPIES byte/text payloads into owned nodes, so
// the input span need not outlive the decoded tree (the zero-copy borrow variant
// is a peer-layer refinement, not needed for the codec gate; the decoder still
// bounds-checks every read via the size-carrying std::span — never UB).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_ECF_HPP
#define ENTITY_CORE_ECF_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace entity_core::ecf {

// ── error channel ───────────────────────────────────────────────────────────
// Scoped enum carried in the std::expected error channel for all fallible codec
// operations. The dispatcher (S3 peer layer) maps protocol-relevant cases to a
// wire status at the boundary; here they are codec-internal verdicts.
enum class EcfError {
    Truncated,         // input ran off the end
    NonCanonicalEcf,   // not minimal / not canonical / trailing bytes / bad form
    TagRejected,       // major-type-6 tag anywhere, any depth (N2)
    DuplicateKey,      // duplicate map key
    NonTextByteKey,    // map key not text/bytes (canonical keys only)
    DepthExceeded,     // nesting beyond the §10.2 limit
    BadInput,          // malformed caller arguments
};

std::string_view to_string(EcfError e) noexcept;

template <typename T>
using Result = std::expected<T, EcfError>;

// ── value model: a std::variant over the ECF major types ────────────────────
// The entity `data` field is a GENERAL EcfValue (P4 / A-JAVA-010: never a
// map-typed field), so a scalar-data entity round-trips correctly.
class EcfValue;

// Integer carrier — the full uint64 / -2^64 head-form range does not fit a
// signed 64-bit int. Mirrors the CBOR major-0/1 head argument directly (native
// std::uint64_t):
//   - non-negative integer n:   negative=false, arg = n    (0 .. 2^64-1)
//   - negative integer -1-arg:  negative=true,  arg        (value = -1 - arg)
struct Int {
    bool negative = false;
    std::uint64_t arg = 0;

    friend bool operator==(const Int&, const Int&) = default;
};

// Float-special tags (Rule 4a). Carried distinctly from a finite double so the
// four canonical specials emit their exact pinned bytes and a NaN compares equal.
enum class FloatSpecial { NaN, PosInf, NegInf, NegZero };

// Tags for the variant alternatives (used by the value-model helpers).
struct Null {
    friend bool operator==(const Null&, const Null&) = default;
};

using Bytes = std::vector<std::byte>;
using Text = std::u8string;  // UTF-8

// Recursive-value box: a heap-held EcfValue with value (copy/move) semantics.
// The variant's recursive alternatives (Array/Map elements) are stored behind a
// Box so the variant is instantiated over a COMPLETE pointer-holding type — this
// is the portable answer to the recursive-type cycle (libstdc++-with-GCC tolerates
// std::vector<incomplete>, but clang++/libstdc++ eagerly requires completeness in
// the variant; A-CPP-010). Deep value semantics keep EcfValue a regular value type.
class Box {
public:
    Box() = default;
    explicit Box(EcfValue v);
    Box(const Box& o);
    Box(Box&&) noexcept = default;
    Box& operator=(const Box& o);
    Box& operator=(Box&&) noexcept = default;
    ~Box();

    EcfValue& operator*() noexcept { return *p_; }
    const EcfValue& operator*() const noexcept { return *p_; }
    EcfValue* operator->() noexcept { return p_.get(); }
    const EcfValue* operator->() const noexcept { return p_.get(); }

    friend bool operator==(const Box& a, const Box& b);

private:
    std::unique_ptr<EcfValue> p_;
};

using Array = std::vector<Box>;

// A map entry: keys are ECF text or byte strings (canonical map keys). Insertion
// order is preserved in the model; the encoder sorts by encoded-key bytes.
struct MapEntry {
    Box key;
    Box value;

    friend bool operator==(const MapEntry&, const MapEntry&) = default;
};
using Map = std::vector<MapEntry>;

class EcfValue {
public:
    using Variant = std::variant<Int, double, FloatSpecial, bool, Null, Bytes,
                                 Text, Array, Map>;

    EcfValue() : v_(Null{}) {}
    EcfValue(Variant v) : v_(std::move(v)) {}

    // Constructors for the leaf types.
    static EcfValue uint(std::uint64_t n) { return EcfValue(Int{false, n}); }
    static EcfValue nint(std::uint64_t arg) { return EcfValue(Int{true, arg}); }
    static EcfValue integer(Int i) { return EcfValue(i); }
    static EcfValue real(double d) { return EcfValue(d); }
    static EcfValue special(FloatSpecial s) { return EcfValue(s); }
    static EcfValue boolean(bool b) { return EcfValue(b); }
    static EcfValue null() { return EcfValue(Null{}); }
    static EcfValue bytes(Bytes b) { return EcfValue(std::move(b)); }
    static EcfValue bytes(std::span<const std::byte> b) {
        return EcfValue(Bytes(b.begin(), b.end()));
    }
    static EcfValue text(Text t) { return EcfValue(std::move(t)); }
    static EcfValue text(std::string_view s) {
        return EcfValue(Text(reinterpret_cast<const char8_t*>(s.data()), s.size()));
    }
    static EcfValue array(Array a = {}) { return EcfValue(std::move(a)); }
    static EcfValue map(Map m = {}) { return EcfValue(std::move(m)); }

    // Ergonomic mutators for building Array/Map values.
    void push(EcfValue item);                  // requires *this is an Array
    void put(EcfValue key, EcfValue value);    // requires *this is a Map

    const Variant& as_variant() const noexcept { return v_; }
    Variant& as_variant() noexcept { return v_; }

    template <typename T>
    bool is() const noexcept { return std::holds_alternative<T>(v_); }
    template <typename T>
    const T* get_if() const noexcept { return std::get_if<T>(&v_); }
    template <typename T>
    T* get_if() noexcept { return std::get_if<T>(&v_); }

    // Map helper: look up a text key, returns nullptr if absent (borrow).
    const EcfValue* find(std::string_view text_key) const noexcept;

    friend bool operator==(const EcfValue&, const EcfValue&) = default;

private:
    Variant v_;
};

// Box methods (out-of-line now that EcfValue is complete).
inline Box::Box(EcfValue v) : p_(std::make_unique<EcfValue>(std::move(v))) {}
inline Box::Box(const Box& o)
    : p_(o.p_ ? std::make_unique<EcfValue>(*o.p_) : nullptr) {}
inline Box& Box::operator=(const Box& o) {
    p_ = o.p_ ? std::make_unique<EcfValue>(*o.p_) : nullptr;
    return *this;
}
inline Box::~Box() = default;
inline bool operator==(const Box& a, const Box& b) {
    if (!a.p_ || !b.p_) return a.p_.get() == b.p_.get();
    return *a.p_ == *b.p_;
}

inline void EcfValue::push(EcfValue item) {
    std::get<Array>(v_).emplace_back(std::move(item));
}
inline void EcfValue::put(EcfValue key, EcfValue value) {
    std::get<Map>(v_).push_back(MapEntry{Box{std::move(key)}, Box{std::move(value)}});
}

// ── canonical ECF encode / decode ───────────────────────────────────────────
// Encode `v` to canonical ECF bytes. The hot path never throws (std::bad_alloc
// from the vector is a programmer-error condition, not a protocol verdict).
Result<std::vector<std::byte>> encode(const EcfValue& v);

// Decode canonical ECF bytes from a borrowed span. On success the returned
// EcfValue owns a fresh tree (byte/text copied in). Rejects trailing bytes
// (non-canonical), tags (N2), indefinite lengths, non-minimal int/length args,
// duplicate map keys, non-text/byte map keys, and over-deep nesting.
Result<EcfValue> decode(std::span<const std::byte> in);

}  // namespace entity_core::ecf

#endif  // ENTITY_CORE_ECF_HPP
