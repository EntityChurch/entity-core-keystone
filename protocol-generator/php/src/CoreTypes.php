<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Core type floor (V7 §9.5) — render-from-model.
 *
 * Publishes the FULL 53-type §9.5 core floor as `system/type` entities under the
 * local namespace. The per-type `data` maps are the in-code override table (the
 * cross-impl Go-rendered type model, ported field-for-field from the cohort's
 * shared shapes); each entity's content_hash is computed by THIS peer's S2-green
 * codec over `{type, data}` (render-from-model, NOT ingest-bytes), and is the
 * surface the oracle's `type_system` category fetches at `system/type/<name>`
 * (the §9.5 53/53 floor). Non-floor type vocabularies are extension-owned and
 * intentionally absent.
 *
 * The byte-for-byte diff against the canonical type-registry vectors is the S4
 * `type_system` category; at S3 these are the bootstrapped floor (rendered,
 * bound, deterministic).
 */
final class CoreTypes
{
    /** Build a system/type `data` map from alternating key/value pairs. */
    private static function m(mixed ...$kvs): EcfMap
    {
        return Ecf::map(...$kvs);
    }

    /** A CBOR array (major 4). @param mixed ...$items @return list<mixed> */
    private static function arr(mixed ...$items): array
    {
        return \array_values($items);
    }

    /**
     * (type-name → `data` map) for the 53 §9.5 core types, in floor order.
     *
     * @return array<string,EcfMap>
     */
    public static function models(): array
    {
        $TRUE = true;
        $out = [];
        $out['primitive/any'] = self::m('name', 'primitive/any');
        $out['primitive/bool'] = self::m('name', 'primitive/bool');
        $out['primitive/bytes'] = self::m('name', 'primitive/bytes');
        $out['primitive/float'] = self::m('name', 'primitive/float');
        $out['primitive/int'] = self::m('name', 'primitive/int');
        $out['primitive/null'] = self::m('name', 'primitive/null');
        $out['primitive/string'] = self::m('name', 'primitive/string');
        $out['primitive/uint'] = self::m('name', 'primitive/uint');
        $out['entity'] = self::m('name', 'entity', 'fields', self::m('data', self::m('type_ref', 'primitive/any'), 'type', self::m('type_ref', 'primitive/string')));
        $out['core/entity'] = self::m('name', 'core/entity', 'fields', self::m('content_hash', self::m('type_ref', 'system/hash'), 'data', self::m('type_ref', 'primitive/any'), 'type', self::m('type_ref', 'primitive/string')));
        $out['core/envelope'] = self::m('name', 'core/envelope', 'fields', self::m('included', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'core/entity'), 'key_type', 'system/hash'), 'root', self::m('type_ref', 'core/entity')));
        $out['system/envelope'] = self::m('name', 'system/envelope', 'extends', 'core/envelope');
        $out['system/protocol/envelope'] = self::m('name', 'system/protocol/envelope', 'extends', 'core/envelope');
        $out['system/hash'] = self::m('name', 'system/hash', 'fields', self::m('digest', self::m('type_ref', 'primitive/bytes'), 'format_code', self::m('type_ref', 'primitive/uint', 'byte_size', 1)), 'extends', 'primitive/bytes', 'layout', self::arr('format_code', 'digest'));
        $out['system/peer'] = self::m('name', 'system/peer', 'fields', self::m('key_type', self::m('type_ref', 'primitive/string'), 'peer_id', self::m('type_ref', 'system/peer-id'), 'public_key', self::m('type_ref', 'primitive/bytes')));
        $out['system/peer-id'] = self::m('name', 'system/peer-id', 'extends', 'primitive/string');
        $out['system/signature'] = self::m('name', 'system/signature', 'fields', self::m('algorithm', self::m('type_ref', 'primitive/string'), 'signature', self::m('type_ref', 'primitive/bytes'), 'signer', self::m('type_ref', 'system/hash'), 'target', self::m('type_ref', 'system/hash')));
        $out['system/protocol/connect/authenticate'] = self::m('name', 'system/protocol/connect/authenticate', 'fields', self::m('key_type', self::m('type_ref', 'primitive/string'), 'nonce', self::m('type_ref', 'primitive/bytes'), 'peer_id', self::m('type_ref', 'system/peer-id'), 'public_key', self::m('type_ref', 'primitive/bytes')));
        $out['system/protocol/connect/hello'] = self::m('name', 'system/protocol/connect/hello', 'fields', self::m('compression', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'encryption', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'hash_formats', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'key_types', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'nonce', self::m('type_ref', 'primitive/bytes'), 'peer_id', self::m('type_ref', 'system/peer-id'), 'protocols', self::m('array_of', self::m('type_ref', 'primitive/string')), 'timestamp', self::m('type_ref', 'primitive/uint')));
        $out['system/protocol/error'] = self::m('name', 'system/protocol/error', 'fields', self::m('code', self::m('type_ref', 'primitive/string'), 'message', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'rejected_marker', self::m('type_ref', 'system/hash', 'optional', $TRUE)));
        $out['system/protocol/execute'] = self::m('name', 'system/protocol/execute', 'fields', self::m('author', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'bounds', self::m('type_ref', 'system/bounds', 'optional', $TRUE), 'capability', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'deliver_to', self::m('type_ref', 'system/delivery-spec', 'optional', $TRUE), 'deliver_token', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'durability_request', self::m('type_ref', 'system/durability-request', 'optional', $TRUE), 'operation', self::m('type_ref', 'primitive/string'), 'params', self::m('type_ref', 'core/entity'), 'request_id', self::m('type_ref', 'primitive/string'), 'resource', self::m('type_ref', 'system/protocol/resource-target', 'optional', $TRUE), 'uri', self::m('type_ref', 'system/tree/path')));
        $out['system/protocol/execute/response'] = self::m('name', 'system/protocol/execute/response', 'fields', self::m('durability', self::m('type_ref', 'system/durability-result', 'optional', $TRUE), 'request_id', self::m('type_ref', 'primitive/string'), 'result', self::m('type_ref', 'core/entity'), 'status', self::m('type_ref', 'primitive/uint')));
        $out['system/protocol/resource-target'] = self::m('name', 'system/protocol/resource-target', 'fields', self::m('exclude', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/tree/path')), 'targets', self::m('array_of', self::m('type_ref', 'system/tree/path'))));
        $out['system/capability/grant'] = self::m('name', 'system/capability/grant', 'fields', self::m('token', self::m('type_ref', 'system/hash')));
        $out['system/capability/grant-entry'] = self::m('name', 'system/capability/grant-entry', 'fields', self::m('allowances', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'primitive/any')), 'constraints', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'primitive/any')), 'handlers', self::m('type_ref', 'system/capability/path-scope'), 'operations', self::m('type_ref', 'system/capability/id-scope'), 'peers', self::m('type_ref', 'system/capability/id-scope', 'optional', $TRUE), 'resources', self::m('type_ref', 'system/capability/path-scope')));
        $out['system/capability/id-scope'] = self::m('name', 'system/capability/id-scope', 'fields', self::m('exclude', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'include', self::m('array_of', self::m('type_ref', 'primitive/string'))));
        $out['system/capability/path-scope'] = self::m('name', 'system/capability/path-scope', 'fields', self::m('exclude', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/tree/path')), 'include', self::m('array_of', self::m('type_ref', 'system/tree/path'))));
        $out['system/capability/request'] = self::m('name', 'system/capability/request', 'fields', self::m('grants', self::m('array_of', self::m('type_ref', 'system/capability/grant-entry')), 'ttl_ms', self::m('type_ref', 'primitive/uint', 'optional', $TRUE)));
        $out['system/capability/revocation'] = self::m('name', 'system/capability/revocation', 'fields', self::m('reason', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'revoked_at', self::m('type_ref', 'primitive/uint'), 'token', self::m('type_ref', 'system/hash')));
        $out['system/capability/revoke-request'] = self::m('name', 'system/capability/revoke-request', 'fields', self::m('reason', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'token', self::m('type_ref', 'system/hash')));
        $out['system/capability/delegate-request'] = self::m('name', 'system/capability/delegate-request', 'fields', self::m('grants', self::m('array_of', self::m('type_ref', 'system/capability/grant-entry')), 'parent', self::m('type_ref', 'system/hash'), 'ttl_ms', self::m('type_ref', 'primitive/uint', 'optional', $TRUE)));
        $out['system/capability/delegation-caveats'] = self::m('name', 'system/capability/delegation-caveats', 'fields', self::m('max_delegation_depth', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'max_delegation_ttl', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'no_delegation', self::m('type_ref', 'primitive/bool', 'optional', $TRUE)));
        $out['system/capability/policy-entry'] = self::m('name', 'system/capability/policy-entry', 'fields', self::m('grants', self::m('array_of', self::m('type_ref', 'system/capability/grant-entry')), 'notes', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'peer_pattern', self::m('type_ref', 'primitive/string'), 'ttl_ms', self::m('type_ref', 'primitive/uint', 'optional', $TRUE)));
        $out['system/capability/token'] = self::m('name', 'system/capability/token', 'fields', self::m('created_at', self::m('type_ref', 'primitive/uint'), 'delegation_caveats', self::m('type_ref', 'system/capability/delegation-caveats', 'optional', $TRUE), 'expires_at', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'grantee', self::m('type_ref', 'system/hash'), 'granter', self::m('union_of', self::arr(self::m('type_ref', 'system/hash'), self::m('type_ref', 'system/capability/multi-granter'))), 'grants', self::m('array_of', self::m('type_ref', 'system/capability/grant-entry')), 'not_before', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'parent', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'resource_limits', self::m('type_ref', 'system/resource-limits', 'optional', $TRUE)));
        $out['system/capability/multi-granter'] = self::m('name', 'system/capability/multi-granter', 'fields', self::m('signers', self::m('array_of', self::m('type_ref', 'system/hash')), 'threshold', self::m('type_ref', 'primitive/uint')));
        $out['system/handler'] = self::m('name', 'system/handler', 'fields', self::m('expression_path', self::m('type_ref', 'system/tree/path', 'optional', $TRUE), 'interface', self::m('type_ref', 'system/tree/path'), 'internal_scope', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/capability/grant-entry')), 'max_scope', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/capability/grant-entry'))));
        $out['system/handler/interface'] = self::m('name', 'system/handler/interface', 'fields', self::m('name', self::m('type_ref', 'primitive/string'), 'operations', self::m('map_of', self::m('type_ref', 'system/handler/operation-spec')), 'pattern', self::m('type_ref', 'system/tree/path')));
        $out['system/handler/manifest'] = self::m('name', 'system/handler/manifest', 'fields', self::m('expression_path', self::m('type_ref', 'system/tree/path', 'optional', $TRUE), 'internal_scope', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/capability/grant-entry')), 'max_scope', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/capability/grant-entry')), 'name', self::m('type_ref', 'primitive/string'), 'operations', self::m('map_of', self::m('type_ref', 'system/handler/operation-spec')), 'pattern', self::m('type_ref', 'system/tree/path')), 'extends', 'system/handler/interface');
        $out['system/handler/operation-spec'] = self::m('name', 'system/handler/operation-spec', 'fields', self::m('input_type', self::m('type_ref', 'system/type/name', 'optional', $TRUE), 'output_type', self::m('type_ref', 'system/type/name', 'optional', $TRUE)));
        $out['system/handler/register-request'] = self::m('name', 'system/handler/register-request', 'fields', self::m('manifest', self::m('type_ref', 'system/handler/manifest'), 'requested_scope', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/capability/grant-entry')), 'types', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'system/type'))));
        $out['system/handler/register-result'] = self::m('name', 'system/handler/register-result', 'fields', self::m('grant', self::m('type_ref', 'system/capability/token'), 'pattern', self::m('type_ref', 'system/tree/path')));
        $out['system/tree/get-request'] = self::m('name', 'system/tree/get-request', 'fields', self::m('limit', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'mode', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'offset', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'tree_id', self::m('type_ref', 'primitive/string', 'optional', $TRUE)));
        $out['system/tree/put-request'] = self::m('name', 'system/tree/put-request', 'fields', self::m('entity', self::m('type_ref', 'core/entity', 'optional', $TRUE), 'expected_hash', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'tree_id', self::m('type_ref', 'primitive/string', 'optional', $TRUE)));
        $out['system/tree/listing'] = self::m('name', 'system/tree/listing', 'fields', self::m('count', self::m('type_ref', 'primitive/uint'), 'entries', self::m('map_of', self::m('type_ref', 'system/tree/listing-entry')), 'next_page', self::m('type_ref', 'system/hash', 'optional', $TRUE), 'offset', self::m('type_ref', 'primitive/uint'), 'path', self::m('type_ref', 'system/tree/path')));
        $out['system/tree/listing-entry'] = self::m('name', 'system/tree/listing-entry', 'fields', self::m('has_children', self::m('type_ref', 'primitive/bool'), 'hash', self::m('type_ref', 'system/hash', 'optional', $TRUE)));
        $out['system/tree/path'] = self::m('name', 'system/tree/path', 'extends', 'primitive/string');
        $out['system/type'] = self::m('name', 'system/type', 'fields', self::m('extends', self::m('type_ref', 'system/type/name', 'optional', $TRUE), 'fields', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'system/type/field-spec')), 'layout', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string')), 'name', self::m('type_ref', 'system/type/name'), 'type_args', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'system/type/name')), 'type_params', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'primitive/string'))));
        $out['system/type/field-spec'] = self::m('name', 'system/type/field-spec', 'fields', self::m('array_of', self::m('type_ref', 'system/type/field-spec', 'optional', $TRUE), 'byte_size', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'constraints', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'core/entity')), 'default', self::m('type_ref', 'primitive/any', 'optional', $TRUE), 'key_type', self::m('type_ref', 'system/type/name', 'optional', $TRUE), 'map_of', self::m('type_ref', 'system/type/field-spec', 'optional', $TRUE), 'optional', self::m('type_ref', 'primitive/bool', 'optional', $TRUE), 'type_args', self::m('optional', $TRUE, 'map_of', self::m('type_ref', 'system/type/name')), 'type_param', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'type_ref', self::m('type_ref', 'system/type/name', 'optional', $TRUE), 'union_of', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/type/field-spec'))));
        $out['system/type/name'] = self::m('name', 'system/type/name', 'extends', 'primitive/string');
        $out['system/bounds'] = self::m('name', 'system/bounds', 'fields', self::m('budget', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'cascade_depth', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'chain_id', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'parent_chain_id', self::m('type_ref', 'primitive/string', 'optional', $TRUE), 'ttl', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'visited', self::m('optional', $TRUE, 'array_of', self::m('type_ref', 'system/tree/path'))));
        $out['system/resource-limits'] = self::m('name', 'system/resource-limits', 'fields', self::m('max_budget', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'max_ttl', self::m('type_ref', 'primitive/uint', 'optional', $TRUE), 'max_visited_length', self::m('type_ref', 'primitive/uint', 'optional', $TRUE)));
        $out['system/delivery-spec'] = self::m('name', 'system/delivery-spec', 'fields', self::m('operation', self::m('type_ref', 'primitive/string'), 'uri', self::m('type_ref', 'system/tree/path')));
        $out['system/deletion-marker'] = self::m('name', 'system/deletion-marker');
        return $out;
    }

    /** Publish every core type at /{peer}/system/type/{name}. */
    public static function publish(Store $store, string $localPeer): void
    {
        foreach (self::models() as $name => $data) {
            $store->bind("/{$localPeer}/system/type/{$name}", Entity::make('system/type', $data));
        }
    }
}
