// entity_core/wire.hpp — §1.6 framing bound + the two message builders (§3.2 EXECUTE /
// §3.3 EXECUTE_RESPONSE) + error result / empty-params / resource-target helpers. Only
// EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3); hello/authenticate are
// OPERATIONS on system/protocol/connect, not message types.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_WIRE_HPP
#define ENTITY_CORE_WIRE_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "entity_core/entity.hpp"

namespace entity_core::wire {

// §1.6 / §4.10(a) frame bound — 16 MiB. The length prefix is checked against this BEFORE
// the body is buffered (→ 413 payload_too_large / clean close at the transport layer).
inline constexpr std::uint32_t kMaxFrame = 16u * 1024u * 1024u;

// EXECUTE (§3.2). author/capability are 33-byte hashes or empty; resource is an EcfValue
// map or nullopt.
Result<EntityPtr> make_execute(const std::string& request_id, const std::string& uri,
                               const std::string& operation, const Entity& params,
                               std::optional<std::span<const std::byte>> author,
                               std::optional<std::span<const std::byte>> capability,
                               std::optional<EcfValue> resource);

// EXECUTE_RESPONSE (§3.3).
Result<EntityPtr> make_response(const std::string& request_id, std::uint64_t status,
                               const Entity& result);

// system/protocol/error {code[,message]}.
Result<EntityPtr> error_result(const std::string& code,
                               std::optional<std::string> message = std::nullopt);

// empty-params (§3.2): primitive/any whose data is the canonical empty map (0xA0).
Result<EntityPtr> empty_params();

// a resource cbor-map {targets:[t]} (single target).
EcfValue resource_target(const std::string& target);

}  // namespace entity_core::wire

#endif  // ENTITY_CORE_WIRE_HPP
