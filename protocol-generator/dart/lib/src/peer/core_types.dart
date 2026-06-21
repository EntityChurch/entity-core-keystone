import '../codec/ecf_value.dart';
import 'cbor.dart';
import 'entity.dart';
import 'store.dart';

/// Core type floor (V7 §9.5) — render-from-model.
///
/// Publishes the FULL 53-type §9.5 core floor as `system/type` entities under the
/// local namespace. The per-type `data` maps come from the in-code override table
/// [coreTypeModels] (the cross-impl Go-rendered type model); each entity's
/// content_hash is computed by our OWN S2-green codec over `{type, data}`
/// (render-from-model, not ingest-bytes), and is the surface the oracle's
/// `type_system` category fetches at `system/type/<name>` (the §9.5 53/53 floor).
/// Non-floor type vocabularies are extension-owned and intentionally absent.
///
/// The byte-identity check against the canonical type-registry vectors is an S4
/// item; at S3 these are the bootstrapped floor.

const _t = EcfBool.trueValue;

EcfMap _m(List<Object?> kvs) => cmap(kvs);
EcfArray _arr(List<EcfValue> items) => cArray(items);
EcfArray _strArr(List<String> items) => textArray(items);

/// (type-name → data-map) for the 53 §9.5 core types, in floor order. Ported from
/// the cross-impl type model (the shared Go-rendered shapes the cohort diffs
/// byte-for-byte).
Map<String, EcfMap> coreTypeModels() {
  final out = <String, EcfMap>{};
  out['primitive/any'] = _m(['name', 'primitive/any']);
  out['primitive/bool'] = _m(['name', 'primitive/bool']);
  out['primitive/bytes'] = _m(['name', 'primitive/bytes']);
  out['primitive/float'] = _m(['name', 'primitive/float']);
  out['primitive/int'] = _m(['name', 'primitive/int']);
  out['primitive/null'] = _m(['name', 'primitive/null']);
  out['primitive/string'] = _m(['name', 'primitive/string']);
  out['primitive/uint'] = _m(['name', 'primitive/uint']);
  out['entity'] = _m([
    'name', 'entity',
    'fields', _m([
      'data', _m(['type_ref', 'primitive/any']),
      'type', _m(['type_ref', 'primitive/string']),
    ]),
  ]);
  out['core/entity'] = _m([
    'name', 'core/entity',
    'fields', _m([
      'content_hash', _m(['type_ref', 'system/hash']),
      'data', _m(['type_ref', 'primitive/any']),
      'type', _m(['type_ref', 'primitive/string']),
    ]),
  ]);
  out['core/envelope'] = _m([
    'name', 'core/envelope',
    'fields', _m([
      'included', _m([
        'optional', _t,
        'map_of', _m(['type_ref', 'core/entity']),
        'key_type', 'system/hash',
      ]),
      'root', _m(['type_ref', 'core/entity']),
    ]),
  ]);
  out['system/envelope'] =
      _m(['name', 'system/envelope', 'extends', 'core/envelope']);
  out['system/protocol/envelope'] =
      _m(['name', 'system/protocol/envelope', 'extends', 'core/envelope']);
  out['system/hash'] = _m([
    'name', 'system/hash',
    'fields', _m([
      'digest', _m(['type_ref', 'primitive/bytes']),
      'format_code', _m(['type_ref', 'primitive/uint', 'byte_size', 1]),
    ]),
    'extends', 'primitive/bytes',
    'layout', _strArr(['format_code', 'digest']),
  ]);
  out['system/peer'] = _m([
    'name', 'system/peer',
    'fields', _m([
      'key_type', _m(['type_ref', 'primitive/string']),
      'peer_id', _m(['type_ref', 'system/peer-id']),
      'public_key', _m(['type_ref', 'primitive/bytes']),
    ]),
  ]);
  out['system/peer-id'] =
      _m(['name', 'system/peer-id', 'extends', 'primitive/string']);
  out['system/signature'] = _m([
    'name', 'system/signature',
    'fields', _m([
      'algorithm', _m(['type_ref', 'primitive/string']),
      'signature', _m(['type_ref', 'primitive/bytes']),
      'signer', _m(['type_ref', 'system/hash']),
      'target', _m(['type_ref', 'system/hash']),
    ]),
  ]);
  out['system/protocol/connect/authenticate'] = _m([
    'name', 'system/protocol/connect/authenticate',
    'fields', _m([
      'key_type', _m(['type_ref', 'primitive/string']),
      'nonce', _m(['type_ref', 'primitive/bytes']),
      'peer_id', _m(['type_ref', 'system/peer-id']),
      'public_key', _m(['type_ref', 'primitive/bytes']),
    ]),
  ]);
  out['system/protocol/connect/hello'] = _m([
    'name', 'system/protocol/connect/hello',
    'fields', _m([
      'compression', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'encryption', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'hash_formats', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'key_types', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'nonce', _m(['type_ref', 'primitive/bytes']),
      'peer_id', _m(['type_ref', 'system/peer-id']),
      'protocols', _m(['array_of', _m(['type_ref', 'primitive/string'])]),
      'timestamp', _m(['type_ref', 'primitive/uint']),
    ]),
  ]);
  out['system/protocol/error'] = _m([
    'name', 'system/protocol/error',
    'fields', _m([
      'code', _m(['type_ref', 'primitive/string']),
      'message', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'rejected_marker', _m(['type_ref', 'system/hash', 'optional', _t]),
    ]),
  ]);
  out['system/protocol/execute'] = _m([
    'name', 'system/protocol/execute',
    'fields', _m([
      'author', _m(['type_ref', 'system/hash', 'optional', _t]),
      'bounds', _m(['type_ref', 'system/bounds', 'optional', _t]),
      'capability', _m(['type_ref', 'system/hash', 'optional', _t]),
      'deliver_to', _m(['type_ref', 'system/delivery-spec', 'optional', _t]),
      'deliver_token', _m(['type_ref', 'system/hash', 'optional', _t]),
      'durability_request', _m(['type_ref', 'system/durability-request', 'optional', _t]),
      'operation', _m(['type_ref', 'primitive/string']),
      'params', _m(['type_ref', 'core/entity']),
      'request_id', _m(['type_ref', 'primitive/string']),
      'resource', _m(['type_ref', 'system/protocol/resource-target', 'optional', _t]),
      'uri', _m(['type_ref', 'system/tree/path']),
    ]),
  ]);
  out['system/protocol/execute/response'] = _m([
    'name', 'system/protocol/execute/response',
    'fields', _m([
      'durability', _m(['type_ref', 'system/durability-result', 'optional', _t]),
      'request_id', _m(['type_ref', 'primitive/string']),
      'result', _m(['type_ref', 'core/entity']),
      'status', _m(['type_ref', 'primitive/uint']),
    ]),
  ]);
  out['system/protocol/resource-target'] = _m([
    'name', 'system/protocol/resource-target',
    'fields', _m([
      'exclude', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/tree/path'])]),
      'targets', _m(['array_of', _m(['type_ref', 'system/tree/path'])]),
    ]),
  ]);
  out['system/capability/grant'] = _m([
    'name', 'system/capability/grant',
    'fields', _m(['token', _m(['type_ref', 'system/hash'])]),
  ]);
  out['system/capability/grant-entry'] = _m([
    'name', 'system/capability/grant-entry',
    'fields', _m([
      'allowances', _m(['optional', _t, 'map_of', _m(['type_ref', 'primitive/any'])]),
      'constraints', _m(['optional', _t, 'map_of', _m(['type_ref', 'primitive/any'])]),
      'handlers', _m(['type_ref', 'system/capability/path-scope']),
      'operations', _m(['type_ref', 'system/capability/id-scope']),
      'peers', _m(['type_ref', 'system/capability/id-scope', 'optional', _t]),
      'resources', _m(['type_ref', 'system/capability/path-scope']),
    ]),
  ]);
  out['system/capability/id-scope'] = _m([
    'name', 'system/capability/id-scope',
    'fields', _m([
      'exclude', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'include', _m(['array_of', _m(['type_ref', 'primitive/string'])]),
    ]),
  ]);
  out['system/capability/path-scope'] = _m([
    'name', 'system/capability/path-scope',
    'fields', _m([
      'exclude', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/tree/path'])]),
      'include', _m(['array_of', _m(['type_ref', 'system/tree/path'])]),
    ]),
  ]);
  out['system/capability/request'] = _m([
    'name', 'system/capability/request',
    'fields', _m([
      'grants', _m(['array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'ttl_ms', _m(['type_ref', 'primitive/uint', 'optional', _t]),
    ]),
  ]);
  out['system/capability/revocation'] = _m([
    'name', 'system/capability/revocation',
    'fields', _m([
      'reason', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'revoked_at', _m(['type_ref', 'primitive/uint']),
      'token', _m(['type_ref', 'system/hash']),
    ]),
  ]);
  out['system/capability/revoke-request'] = _m([
    'name', 'system/capability/revoke-request',
    'fields', _m([
      'reason', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'token', _m(['type_ref', 'system/hash']),
    ]),
  ]);
  out['system/capability/delegate-request'] = _m([
    'name', 'system/capability/delegate-request',
    'fields', _m([
      'grants', _m(['array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'parent', _m(['type_ref', 'system/hash']),
      'ttl_ms', _m(['type_ref', 'primitive/uint', 'optional', _t]),
    ]),
  ]);
  out['system/capability/delegation-caveats'] = _m([
    'name', 'system/capability/delegation-caveats',
    'fields', _m([
      'max_delegation_depth', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'max_delegation_ttl', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'no_delegation', _m(['type_ref', 'primitive/bool', 'optional', _t]),
    ]),
  ]);
  out['system/capability/policy-entry'] = _m([
    'name', 'system/capability/policy-entry',
    'fields', _m([
      'grants', _m(['array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'notes', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'peer_pattern', _m(['type_ref', 'primitive/string']),
      'ttl_ms', _m(['type_ref', 'primitive/uint', 'optional', _t]),
    ]),
  ]);
  out['system/capability/token'] = _m([
    'name', 'system/capability/token',
    'fields', _m([
      'created_at', _m(['type_ref', 'primitive/uint']),
      'delegation_caveats', _m(['type_ref', 'system/capability/delegation-caveats', 'optional', _t]),
      'expires_at', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'grantee', _m(['type_ref', 'system/hash']),
      'granter', _m(['union_of', _arr([
        _m(['type_ref', 'system/hash']),
        _m(['type_ref', 'system/capability/multi-granter']),
      ])]),
      'grants', _m(['array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'not_before', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'parent', _m(['type_ref', 'system/hash', 'optional', _t]),
      'resource_limits', _m(['type_ref', 'system/resource-limits', 'optional', _t]),
    ]),
  ]);
  out['system/capability/multi-granter'] = _m([
    'name', 'system/capability/multi-granter',
    'fields', _m([
      'signers', _m(['array_of', _m(['type_ref', 'system/hash'])]),
      'threshold', _m(['type_ref', 'primitive/uint']),
    ]),
  ]);
  out['system/handler'] = _m([
    'name', 'system/handler',
    'fields', _m([
      'expression_path', _m(['type_ref', 'system/tree/path', 'optional', _t]),
      'interface', _m(['type_ref', 'system/tree/path']),
      'internal_scope', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'max_scope', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
    ]),
  ]);
  out['system/handler/interface'] = _m([
    'name', 'system/handler/interface',
    'fields', _m([
      'name', _m(['type_ref', 'primitive/string']),
      'operations', _m(['map_of', _m(['type_ref', 'system/handler/operation-spec'])]),
      'pattern', _m(['type_ref', 'system/tree/path']),
    ]),
  ]);
  out['system/handler/manifest'] = _m([
    'name', 'system/handler/manifest',
    'fields', _m([
      'expression_path', _m(['type_ref', 'system/tree/path', 'optional', _t]),
      'internal_scope', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'max_scope', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'name', _m(['type_ref', 'primitive/string']),
      'operations', _m(['map_of', _m(['type_ref', 'system/handler/operation-spec'])]),
      'pattern', _m(['type_ref', 'system/tree/path']),
    ]),
    'extends', 'system/handler/interface',
  ]);
  out['system/handler/operation-spec'] = _m([
    'name', 'system/handler/operation-spec',
    'fields', _m([
      'input_type', _m(['type_ref', 'system/type/name', 'optional', _t]),
      'output_type', _m(['type_ref', 'system/type/name', 'optional', _t]),
    ]),
  ]);
  out['system/handler/register-request'] = _m([
    'name', 'system/handler/register-request',
    'fields', _m([
      'manifest', _m(['type_ref', 'system/handler/manifest']),
      'requested_scope', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/capability/grant-entry'])]),
      'types', _m(['optional', _t, 'map_of', _m(['type_ref', 'system/type'])]),
    ]),
  ]);
  out['system/handler/register-result'] = _m([
    'name', 'system/handler/register-result',
    'fields', _m([
      'grant', _m(['type_ref', 'system/capability/token']),
      'pattern', _m(['type_ref', 'system/tree/path']),
    ]),
  ]);
  out['system/tree/get-request'] = _m([
    'name', 'system/tree/get-request',
    'fields', _m([
      'limit', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'mode', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'offset', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'tree_id', _m(['type_ref', 'primitive/string', 'optional', _t]),
    ]),
  ]);
  out['system/tree/put-request'] = _m([
    'name', 'system/tree/put-request',
    'fields', _m([
      'entity', _m(['type_ref', 'core/entity', 'optional', _t]),
      'expected_hash', _m(['type_ref', 'system/hash', 'optional', _t]),
      'tree_id', _m(['type_ref', 'primitive/string', 'optional', _t]),
    ]),
  ]);
  out['system/tree/listing'] = _m([
    'name', 'system/tree/listing',
    'fields', _m([
      'count', _m(['type_ref', 'primitive/uint']),
      'entries', _m(['map_of', _m(['type_ref', 'system/tree/listing-entry'])]),
      'next_page', _m(['type_ref', 'system/hash', 'optional', _t]),
      'offset', _m(['type_ref', 'primitive/uint']),
      'path', _m(['type_ref', 'system/tree/path']),
    ]),
  ]);
  out['system/tree/listing-entry'] = _m([
    'name', 'system/tree/listing-entry',
    'fields', _m([
      'has_children', _m(['type_ref', 'primitive/bool']),
      'hash', _m(['type_ref', 'system/hash', 'optional', _t]),
    ]),
  ]);
  out['system/tree/path'] =
      _m(['name', 'system/tree/path', 'extends', 'primitive/string']);
  out['system/type'] = _m([
    'name', 'system/type',
    'fields', _m([
      'extends', _m(['type_ref', 'system/type/name', 'optional', _t]),
      'fields', _m(['optional', _t, 'map_of', _m(['type_ref', 'system/type/field-spec'])]),
      'layout', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
      'name', _m(['type_ref', 'system/type/name']),
      'type_args', _m(['optional', _t, 'map_of', _m(['type_ref', 'system/type/name'])]),
      'type_params', _m(['optional', _t, 'array_of', _m(['type_ref', 'primitive/string'])]),
    ]),
  ]);
  out['system/type/field-spec'] = _m([
    'name', 'system/type/field-spec',
    'fields', _m([
      'array_of', _m(['type_ref', 'system/type/field-spec', 'optional', _t]),
      'byte_size', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'constraints', _m(['optional', _t, 'array_of', _m(['type_ref', 'core/entity'])]),
      'default', _m(['type_ref', 'primitive/any', 'optional', _t]),
      'key_type', _m(['type_ref', 'system/type/name', 'optional', _t]),
      'map_of', _m(['type_ref', 'system/type/field-spec', 'optional', _t]),
      'optional', _m(['type_ref', 'primitive/bool', 'optional', _t]),
      'type_args', _m(['optional', _t, 'map_of', _m(['type_ref', 'system/type/name'])]),
      'type_param', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'type_ref', _m(['type_ref', 'system/type/name', 'optional', _t]),
      'union_of', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/type/field-spec'])]),
    ]),
  ]);
  out['system/type/name'] =
      _m(['name', 'system/type/name', 'extends', 'primitive/string']);
  out['system/bounds'] = _m([
    'name', 'system/bounds',
    'fields', _m([
      'budget', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'cascade_depth', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'chain_id', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'parent_chain_id', _m(['type_ref', 'primitive/string', 'optional', _t]),
      'ttl', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'visited', _m(['optional', _t, 'array_of', _m(['type_ref', 'system/tree/path'])]),
    ]),
  ]);
  out['system/resource-limits'] = _m([
    'name', 'system/resource-limits',
    'fields', _m([
      'max_budget', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'max_ttl', _m(['type_ref', 'primitive/uint', 'optional', _t]),
      'max_visited_length', _m(['type_ref', 'primitive/uint', 'optional', _t]),
    ]),
  ]);
  out['system/delivery-spec'] = _m([
    'name', 'system/delivery-spec',
    'fields', _m([
      'operation', _m(['type_ref', 'primitive/string']),
      'uri', _m(['type_ref', 'system/tree/path']),
    ]),
  ]);
  out['system/deletion-marker'] = _m(['name', 'system/deletion-marker']);
  return out;
}

/// (type-name → rendered system/type entity) for the full §9.5 53-type floor.
Map<String, Entity> coreTypeEntities() => {
      for (final e in coreTypeModels().entries)
        e.key: Entity.make('system/type', e.value),
    };

/// Publish every core type at /{peer}/system/type/{name}.
void publishCoreTypes(Store store, String localPeer) {
  coreTypeEntities().forEach((name, e) {
    store.bind('/$localPeer/system/type/$name', e);
  });
}
