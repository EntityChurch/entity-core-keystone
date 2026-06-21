/*
 * wire.h — §1.6 framing + the two message builders (§3.2 EXECUTE / §3.3 RESPONSE) +
 * error result / empty-params / resource-target helpers. Only EXECUTE and
 * EXECUTE_RESPONSE are wire message types (§3.3); hello/authenticate are OPERATIONS on
 * system/protocol/connect, not message types.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_WIRE_H
#define EC_WIRE_H

#include "peer_internal.h"

/* §1.6 / §4.10(a) frame bound — 16 MiB. The length prefix is checked against this
 * BEFORE the body is buffered (→ 413 payload_too_large at the dispatch layer). */
#define EC_MAX_FRAME (16u * 1024u * 1024u)

/* EXECUTE (§3.2). author/capability are 33-byte hashes or NULL; resource is a cbor
 * map value (owned, consumed) or NULL. +1 ref out. */
ec_status ec_make_execute(const char *request_id, const char *uri, const char *operation,
                          ec_entity *params, const uint8_t *author, const uint8_t *capability,
                          ec_value *resource, ec_entity **out);

/* EXECUTE_RESPONSE (§3.3). +1 ref out. */
ec_status ec_make_response(const char *request_id, uint64_t status, ec_entity *result,
                           ec_entity **out);

/* system/protocol/error {code[,message]}. +1 ref out. */
ec_status ec_error_result(const char *code, const char *message, ec_entity **out);

/* empty-params (§3.2): primitive/any whose data is the canonical empty map (0xA0). */
ec_status ec_empty_params(ec_entity **out);

/* a resource cbor-map {targets:[t]} (single target). owned value out (caller frees). */
ec_status ec_resource_target(const char *target, ec_value **out);

#endif /* EC_WIRE_H */
