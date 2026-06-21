// wire.cpp — message builders (§3.2 EXECUTE / §3.3 RESPONSE) + error / empty-params /
// resource-target. Framing (the 4-byte BE length prefix + body) lives in transport.cpp.
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/wire.hpp"

namespace entity_core::wire {

Result<EntityPtr> make_execute(const std::string& request_id, const std::string& uri,
                               const std::string& operation, const Entity& params,
                               std::optional<std::span<const std::byte>> author,
                               std::optional<std::span<const std::byte>> capability,
                               std::optional<EcfValue> resource) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("request_id"), EcfValue::text(request_id));
    m.put(EcfValue::text("uri"), EcfValue::text(uri));
    m.put(EcfValue::text("operation"), EcfValue::text(operation));
    m.put(EcfValue::text("params"), params.to_cbor());
    if (author) m.put(EcfValue::text("author"), EcfValue::bytes(*author));
    if (capability) m.put(EcfValue::text("capability"), EcfValue::bytes(*capability));
    if (resource) m.put(EcfValue::text("resource"), std::move(*resource));
    return Entity::make("system/protocol/execute", std::move(m));
}

Result<EntityPtr> make_response(const std::string& request_id, std::uint64_t status,
                               const Entity& result) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("request_id"), EcfValue::text(request_id));
    m.put(EcfValue::text("status"), EcfValue::uint(status));
    m.put(EcfValue::text("result"), result.to_cbor());
    return Entity::make("system/protocol/execute/response", std::move(m));
}

Result<EntityPtr> error_result(const std::string& code, std::optional<std::string> message) {
    auto m = EcfValue::map();
    m.put(EcfValue::text("code"), EcfValue::text(code));
    if (message) m.put(EcfValue::text("message"), EcfValue::text(*message));
    return Entity::make("system/protocol/error", std::move(m));
}

Result<EntityPtr> empty_params() {
    return Entity::make("primitive/any", EcfValue::map());  // empty → 0xA0 (N3)
}

EcfValue resource_target(const std::string& target) {
    auto m = EcfValue::map();
    auto arr = EcfValue::array();
    arr.push(EcfValue::text(target));
    m.put(EcfValue::text("targets"), std::move(arr));
    return m;
}

}  // namespace entity_core::wire
