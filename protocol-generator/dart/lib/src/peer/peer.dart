import 'dart:math';
import 'dart:typed_data';

import '../codec/ecf_value.dart';
import '../crypto/peer_id.dart';
import 'capability.dart' as cap;
import 'cbor.dart';
import 'core_types.dart';
import 'dispatch.dart';
import 'entity.dart';
import 'envelope.dart';
import 'identity.dart';
import 'store.dart';
import 'wire.dart' as wire;

/// Peer assembly: bootstrap (§6.9 / §6.9a), the MUST system handlers (§6.2:
/// connect, tree, handler, capability, type), the §6.5 dispatch chain, §6.6
/// resolution, and per-connection state. The pure protocol brain — an `async`
/// function from inbound envelope to outbound response envelope. Transport lives
/// in `Transport`.
///
/// Spec-first: the handshake (§4.1/§4.6 three-check PoP), the dispatch chain
/// order (verify → resolve → check-permission → handler), and §4.4 initial-grant
/// delivery are derived from V7.
///
/// **Idiom (the verdict/dispatch axis).** Each handler is a [Handler] whose
/// `handle(op, ctx)` is a `switch` over the operation string — the mainstream
/// `match op` ladder with the "unknown operation → 501" arm as `default`. The
/// §5.2/§5.10 verdicts are Dart `enum`s matched EXHAUSTIVELY by `switch` at the
/// dispatch site (profile `pattern_matching`). Handlers are `async` (a handler
/// that originates an outbound EXECUTE — §6.13(b)/§6.11 reentry — awaits the
/// response via the Future seam, never blocking the event loop).
final class Peer {
  Peer._(this.identity, this.store, this.localPeer, this._openGrants,
      this._conformance);

  final Identity identity;
  final Store store;
  final String localPeer;
  final bool _openGrants; // --debug-open-grants: degenerate wide admin cap
  final bool _conformance; // --validate: §7a system/validate/* handlers

  final Map<String, Handler> _handlers = {}; // pattern → handler
  final Random _rng = Random.secure();

  /// Construct + bootstrap a peer from a 32-byte Ed25519 seed.
  static Future<Peer> create(Uint8List seed,
      {bool openGrants = false, bool conformance = false}) async {
    final identity = await Identity.ofSeed(seed);
    final peer = Peer._(identity, Store(), identity.peerId, openGrants, conformance);
    await peer._bootstrap();
    return peer;
  }

  // ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ───────────────────────────

  Uint8List _randomBytes(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
    return b;
  }

  // ── grant construction (§4.4 / §5.4) ───────────────────────────────────────────

  /// The §4.4 discovery floor: every authenticated identity gets at least this.
  List<EcfMap> _discoveryFloor() => [
        grant(['system/tree'], ['system/type/*', 'system/handler/*'], ['get'], null),
        grant(['system/capability'], const [], ['request'], null),
      ];

  /// Wide-open admin scope — the degenerate [default → *] (= --debug-open-grants).
  List<EcfMap> _openGrantsScope() =>
      [grant(['*'], ['*', '/*/*'], ['*'], ['*'])];

  /// Full owner authority over the local namespace /{peer_id}/* (§6.9a).
  List<EcfMap> _ownerGrants() => [grant(['*'], ['*'], ['*'], [localPeer])];

  // ── token mint (§4.4 / §6.9a) ───────────────────────────────────────────────────

  Future<_Minted> _mintToken(
      Uint8List granteeHash, List<EcfMap> grants, Uint8List? parent) async {
    final pairs = <EcfEntry>[
      EcfEntry(const EcfText('granter'), EcfBytes(identity.identityHash())),
      EcfEntry(const EcfText('grantee'), EcfBytes(granteeHash)),
      EcfEntry(const EcfText('grants'), _grantsArray(grants)),
      EcfEntry(const EcfText('created_at'), EcfInt.of(cap.nowMs())),
    ];
    if (parent != null) {
      pairs.add(EcfEntry(const EcfText('parent'), EcfBytes(parent)));
    }
    final token = Entity.make('system/capability/token', EcfMap(pairs));
    final signature = await identity.sign(token);
    return _Minted(token, signature);
  }

  List<Included> _capIncluded(_Minted m) => [
        Included(m.token.hash(), m.token),
        Included(identity.identityHash(), identity.peerEntity),
        Included(m.signature.hash(), m.signature),
      ];

  // ── §6.9a seed policy (authenticate-time grant derivation) ────────────────────────

  Future<List<EcfMap>> _seedEntryGrants(Entity e) async {
    switch (e.type) {
      case 'system/capability/token':
        final sigPath =
            '/$localPeer/system/signature/${hexEncode(e.rawHash)}';
        final sgn = store.getAt(sigPath);
        if (sgn != null &&
            await Identity.verifySignature(sgn, identity.peerEntity)) {
          return mapList(e.data(), 'grants') ?? const [];
        }
        return const [];
      case 'system/capability/policy-entry':
        return mapList(e.data(), 'grants') ?? const [];
      default:
        return const [];
    }
  }

  /// §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 →
  /// default), then UNION the matched scope with the §4.4 discovery floor.
  Future<List<EcfMap>> _deriveSeedGrants(
      Entity remotePeer, String remotePeerId) async {
    final base = '/$localPeer/system/capability/policy/';
    final entry = store.getAt(base + hexEncode(remotePeer.rawHash)) ??
        store.getAt(base + remotePeerId) ??
        store.getAt('${base}default');
    final floor = _discoveryFloor();
    if (entry == null) return floor;
    final policy = await _seedEntryGrants(entry);
    if (policy.isEmpty) return floor;
    return [...floor, ...policy];
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // Handlers (single-dispatch operation `switch` ladders)
  // ══════════════════════════════════════════════════════════════════════════════

  List<String>? _strArray(Entity exec, String key) {
    final p = exec.entityField('params');
    return p == null ? null : textList(p.data(), key);
  }

  // ── §4.1 / §4.6 connect (hello / authenticate) ──

  Future<Outcome> _hello(HandlerContext ctx) async {
    final conn = ctx.conn;
    final exec = ctx.exec;
    if (conn.established) return Outcome.err(409, 'connection_already_established');
    // §4.5 negotiation: reject disjoint hash_formats / key_types up front.
    final hf = _strArray(exec, 'hash_formats');
    final kt = _strArray(exec, 'key_types');
    if (hf != null && !hf.contains('ecfv1-sha256')) {
      return Outcome.err(400, 'incompatible_hash_format');
    }
    if (kt != null && !kt.contains('ed25519')) {
      return Outcome.err(400, 'unsupported_key_type');
    }
    final params = exec.entityField('params');
    conn.helloPeerId = params?.text('peer_id');
    final nonce = _randomBytes(32);
    conn.issuedNonce = nonce;
    return Outcome.ok(Entity.make(
      'system/protocol/connect/hello',
      cmap([
        'peer_id', localPeer,
        'nonce', cbytes(nonce),
        'protocols', textArray(['entity-core/1.0']),
        'timestamp', EcfInt.of(cap.nowMs()),
        'hash_formats', textArray(['ecfv1-sha256']),
        'key_types', textArray(['ed25519']),
      ]),
    ));
  }

  Future<Outcome> _authenticate(HandlerContext ctx) async {
    final conn = ctx.conn;
    final exec = ctx.exec;
    if (conn.established) return Outcome.err(409, 'connection_already_established');
    final issuedNonce = conn.issuedNonce;
    if (issuedNonce == null) return Outcome.err(401, 'invalid_nonce'); // before hello
    final auth = exec.entityField('params');
    if (auth == null) return Outcome.err(401, 'authentication_failed');
    // §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-0x01.
    var badKt = (auth.text('key_type') ?? 'ed25519') != 'ed25519';
    final pub = auth.bytes('public_key');
    if (!badKt && pub != null && pub.length != 32) badKt = true;
    final claimed = auth.text('peer_id');
    if (!badKt && claimed != null) {
      try {
        if (PeerId.parse(claimed).keyType != PeerId.keyTypeEd25519) badKt = true;
      } catch (_) {
        // unparseable peer_id → fall through to the step checks below
      }
    }
    if (badKt) return Outcome.err(400, 'unsupported_key_type');
    // step 1: nonce-echo
    final echoed = auth.bytes('nonce');
    if (!(echoed != null && octetsEqual(echoed, issuedNonce))) {
      return Outcome.err(401, 'invalid_nonce');
    }
    if (pub == null) return Outcome.err(401, 'authentication_failed');
    // step 2: proof of possession
    final sgn = cap.findSignature(auth.rawHash, ctx.included);
    final sb = sgn?.bytes('signature');
    final sigOk = sb != null &&
        await Identity.verifySignature(sgn!, Identity.peerEntityOfPublicKey(pub));
    if (!sigOk) return Outcome.err(401, 'authentication_failed');
    // step 3: identity binding
    if (claimed != Identity.peerIdOfPublicKey(pub)) {
      return Outcome.err(401, 'identity_mismatch');
    }
    if (conn.helloPeerId != null && conn.helloPeerId != claimed) {
      return Outcome.err(401, 'identity_mismatch');
    }
    // success: mint the initial capability for the remote (§4.4 / §6.9a)
    final remotePeer = Identity.peerEntityOfPublicKey(pub);
    final grants = await _deriveSeedGrants(remotePeer, claimed!);
    final m = await _mintToken(remotePeer.hash(), grants, null);
    conn.established = true;
    return Outcome.ok(
      Entity.make('system/capability/grant',
          cmap(['token', cbytes(m.token.hash())])),
      _capIncluded(m),
    );
  }

  // ── §6.3 tree (get / put) ──

  Future<Outcome> _treeGet(HandlerContext ctx) async {
    final exec = ctx.exec;
    final target = _execResourceTarget(exec);
    if (target != null && !_pathFlexOk(target)) {
      return Outcome.err(400, 'invalid_path', target);
    }
    if (target == null) return _buildListing('/$localPeer/');
    if (target.isEmpty || target.endsWith('/')) {
      return _buildListing(cap.canonicalize(localPeer, target));
    }
    final path = cap.canonicalize(localPeer, target);
    final e = store.getAt(path);
    if (e == null) return Outcome.err(404, 'not_found', path);
    final mode = exec.entityField('params')?.text('mode');
    if (mode == 'hash') {
      return Outcome.ok(Entity.make(
          'system/hash', cmap(['hash', cbytes(e.hash())])));
    }
    return Outcome.ok(e);
  }

  Future<Outcome> _treePut(HandlerContext ctx) async {
    final exec = ctx.exec;
    final target = _execResourceTarget(exec);
    if (target == null) {
      return Outcome.err(400, 'ambiguous_resource', 'tree: missing resource target');
    }
    if (!_pathFlexOk(target)) return Outcome.err(400, 'invalid_path', target);
    final path = cap.canonicalize(localPeer, target);
    final params = exec.entityField('params');
    final entity = params?.entityField('entity');
    final expected = params?.bytes('expected_hash');
    final current = store.hashAt(path);
    final bool casOk;
    if (expected == null) {
      casOk = true;
    } else if (isZeroHash(expected)) {
      casOk = current == null;
    } else {
      casOk = current != null && current == hexEncode(expected);
    }
    if (!casOk) return Outcome.err(409, 'hash_mismatch', path);
    if (entity == null) {
      return Outcome.err(400, 'unexpected_params', 'put: missing entity');
    }
    store.bind(path, entity);
    return Outcome.ok(Entity.make(
        'system/hash', cmap(['hash', cbytes(entity.hash())])));
  }

  Outcome _buildListing(String path) {
    final entries = store.listing(path).where((row) {
      return !(row.hashHex != null &&
          !row.hasChildren &&
          _isDeletionMarker(hexDecode(row.hashHex!)));
    }).toList();
    final entryPairs = <EcfEntry>[];
    for (final row in entries) {
      final data = row.hashHex != null
          ? cmap(['has_children', row.hasChildren, 'hash', cbytes(hexDecode(row.hashHex!))])
          : cmap(['has_children', row.hasChildren]);
      final le = Entity.make('system/tree/listing-entry', data);
      entryPairs.add(EcfEntry(EcfText(row.segment), le.toCbor()));
    }
    return Outcome.ok(Entity.make(
      'system/tree/listing',
      cmap([
        'path', path,
        'entries', EcfMap(entryPairs),
        'count', EcfInt.of(entries.length),
        'offset', EcfInt.of(0),
      ]),
    ));
  }

  bool _isDeletionMarker(Uint8List h) =>
      store.getByHash(h)?.type == 'system/deletion-marker';

  // ── EXTENSION-TYPE system/type:validate ──

  Future<Outcome> _typeValidate(HandlerContext ctx) async {
    final req = ctx.params();
    if (req == null) {
      return Outcome.err(400, 'invalid_params', 'validate requires a params entity');
    }
    final subject = req.entityField('entity');
    if (subject == null) {
      return Outcome.err(400, 'unexpected_params', 'validate-request missing entity');
    }
    final typeName = req.text('type_path') ?? subject.type;
    final typeDef = store.getAt(_abs('system/type/$typeName'));
    if (typeDef == null) {
      final vs = <EcfValue>[
        cmap([
          'kind', 'unknown_type',
          'field', typeName,
          'message', 'no registered type definition for $typeName',
        ]),
      ];
      return Outcome.ok(Entity.make('system/type/validate-result',
          cmap(['valid', false, 'violations', cArray(vs)])));
    }
    final fields = typeDef.mapField('fields');
    final subjData = asMap(subject.rawData());
    final violations = <EcfValue>[];
    final unevaluated = <String>[];
    final declared = <String>{};
    if (fields != null) {
      for (final fe in fields.entries) {
        final fk = fe.key;
        if (fk is! EcfText) continue;
        declared.add(fk.value);
        final spec = asMap(fe.value);
        final optional = spec != null && ecfIsTrue(spec['optional']);
        final present = subjData != null && subjData[fk.value] != null;
        if (!optional && !present) {
          violations.add(cmap([
            'kind', 'missing_required_field',
            'field', fk.value,
            'message', 'required field absent',
          ]));
        }
      }
    }
    if (subjData != null) {
      for (final se in subjData.entries) {
        final sk = se.key;
        if (sk is EcfText && !declared.contains(sk.value)) {
          unevaluated.add(sk.value);
        }
      }
    }
    final valid = violations.isEmpty;
    final result = <EcfEntry>[
      EcfEntry(const EcfText('valid'),
          valid ? EcfBool.trueValue : EcfBool.falseValue),
    ];
    if (violations.isNotEmpty) {
      result.add(EcfEntry(const EcfText('violations'), cArray(violations)));
    }
    if (unevaluated.isNotEmpty) {
      result.add(EcfEntry(
          const EcfText('unevaluated_fields'), textArray(unevaluated)));
    }
    return Outcome.ok(Entity.make('system/type/validate-result', EcfMap(result)));
  }

  // ── §6.2 capability (request / delegate / revoke / configure) ──

  Future<Outcome> _capRequest(HandlerContext ctx) async {
    final params = ctx.exec.entityField('params');
    final author = ctx.exec.bytes('author');
    if (author == null) return Outcome.err(403, 'capability_denied');
    return _mintBounded(ctx.callerCap, _reqGrants(params), author, null);
  }

  Future<Outcome> _capDelegate(HandlerContext ctx) async {
    final params = ctx.exec.entityField('params');
    final author = ctx.exec.bytes('author');
    final ph = params?.bytes('parent');
    if (ph == null) {
      return Outcome.err(400, 'unexpected_params', 'delegate: parent required');
    }
    if (isZeroHash(ph)) {
      return Outcome.err(400, 'unexpected_params', 'delegate: zero parent');
    }
    if (!(author != null && octetsEqual(author, identity.identityHash()))) {
      return Outcome.err(501, 'unsupported_operation', 'delegate: same-peer-only in v1');
    }
    return _mintBounded(ctx.callerCap, _reqGrants(params), author, ph);
  }

  Future<Outcome> _capRevoke(HandlerContext ctx) async {
    final params = ctx.exec.entityField('params');
    final tokenH = params?.bytes('token');
    if (tokenH == null) {
      return Outcome.err(400, 'unexpected_params', 'revoke: missing token');
    }
    if (isZeroHash(tokenH)) {
      return Outcome.err(400, 'unexpected_params', 'revoke: zero token');
    }
    final marker = Entity.make('system/capability/revocation',
        cmap(['token', cbytes(tokenH), 'revoked_at', EcfInt.of(cap.nowMs())]));
    store.bind(
        '/$localPeer/system/capability/revocations/${hexEncode(tokenH)}', marker);
    return Outcome.ok(wire.emptyParams());
  }

  Future<Outcome> _capConfigure(HandlerContext ctx) async {
    final params = ctx.exec.entityField('params');
    final pp = params?.text('peer_pattern');
    if (pp == null) {
      return Outcome.err(400, 'unexpected_params', 'configure: missing peer_pattern');
    }
    final isHex = pp.length == 66 &&
        pp.split('').every((c) =>
            (c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39) ||
            (c.codeUnitAt(0) >= 0x61 && c.codeUnitAt(0) <= 0x66));
    if (!(pp == 'default' || isHex || cap.isPeerId(pp))) {
      return Outcome.err(400, 'invalid_peer_pattern', pp);
    }
    store.bind('/$localPeer/system/capability/policy/$pp', params!);
    return Outcome.ok(wire.emptyParams());
  }

  Future<Outcome> _mintBounded(Entity? callerCap, List<EcfMap> reqGrants,
      Uint8List granteeHash, Uint8List? parent) async {
    var bounded = false;
    if (callerCap != null) {
      final parentGrants = cap.grantsOfToken(callerCap);
      bounded = true;
      for (final cgRaw in reqGrants) {
        final c = cap.parseGrant(cgRaw);
        // self-issued mint: granter = local → both frames local.
        if (!parentGrants.any((g) =>
            cap.grantSubset(localPeer, localPeer, localPeer, c, g))) {
          bounded = false;
          break;
        }
      }
    }
    if (!bounded) return Outcome.err(403, 'scope_exceeds_authority');
    final m = await _mintToken(granteeHash, reqGrants, parent);
    return Outcome.ok(
      Entity.make('system/capability/grant',
          cmap(['token', cbytes(m.token.hash())])),
      _capIncluded(m),
    );
  }

  // ── §6.2 / §6.13(a) handlers (register / unregister) ──

  Future<Outcome> _handlerRegister(HandlerContext ctx) async {
    final exec = ctx.exec;
    final pattern = _registerPattern(exec);
    if (pattern == null) return _registerPatternError(exec);
    final req = exec.entityField('params');
    if (req == null) {
      return Outcome.err(400, 'unexpected_params', 'register: missing params');
    }
    if (req.type != 'system/handler/register-request') {
      return Outcome.err(400, 'unexpected_params',
          'register expects register-request, got ${req.type}');
    }
    final manifest = req.mapField('manifest') ?? emptyMap();
    final name = mtext(manifest, 'name') ?? pattern;
    final operations = asMap(manifest['operations']) ?? emptyMap();
    final exprPath = mtext(manifest, 'expression_path');
    final internalScope = manifest['internal_scope'];
    var grantScope = mapList(req.data(), 'requested_scope');
    if (grantScope == null && internalScope is EcfArray) {
      grantScope = mapList(req.data(), 'internal_scope');
    }
    grantScope ??= const [];
    final interfaceRel = 'system/handler/$pattern';
    // (1) handler manifest at the pattern path
    final hp = <EcfEntry>[
      EcfEntry(const EcfText('interface'), EcfText(interfaceRel)),
    ];
    if (exprPath != null) {
      hp.add(EcfEntry(const EcfText('expression_path'), EcfText(exprPath)));
    }
    if (internalScope != null) {
      hp.add(EcfEntry(const EcfText('internal_scope'), internalScope));
    }
    store.bind(_abs(pattern), Entity.make('system/handler', EcfMap(hp)));
    // (2) associated types at system/type/{type_name}
    final types = req.mapField('types');
    if (types != null) {
      for (final kv in types.entries) {
        final tk = kv.key;
        if (tk is! EcfText) continue;
        final v = kv.value;
        final td = v is EcfMap ? v : cmap(['def', v]);
        store.bind(_abs('system/type/${tk.value}'),
            Entity.make('system/type', td));
      }
    }
    // (3) self-issued signed handler grant + (4) grant-signature at §3.5
    final m = await _mintToken(identity.identityHash(), grantScope, null);
    store.bind(_abs('system/capability/grants/$pattern'), m.token);
    store.bind(
        _abs('system/signature/${hexEncode(m.token.rawHash)}'), m.signature);
    // (5) handler interface entity (discovery index)
    store.bind(
        _abs(interfaceRel),
        Entity.make('system/handler/interface',
            cmap(['pattern', pattern, 'name', name, 'operations', operations])));
    return Outcome.ok(Entity.make('system/handler/register-result',
        cmap(['pattern', pattern, 'grant', m.token.data()])));
  }

  Future<Outcome> _handlerUnregister(HandlerContext ctx) async {
    final exec = ctx.exec;
    final pattern = _registerPattern(exec);
    if (pattern == null) return _registerPatternError(exec);
    final g = store.getAt(_abs('system/capability/grants/$pattern'));
    if (g != null) {
      store.unbind(_abs('system/signature/${hexEncode(g.rawHash)}'));
      store.unbind(_abs('system/capability/grants/$pattern'));
    }
    store.unbind(_abs(pattern));
    store.unbind(_abs('system/handler/$pattern'));
    return Outcome.ok(wire.emptyParams());
  }

  // ── §7a conformance: echo (the §6.13(a) resolve→dispatch half) ──

  Future<Outcome> _echo(HandlerContext ctx) async {
    final p = ctx.params();
    return p != null
        ? Outcome.ok(p)
        : Outcome.err(400, 'invalid_params', 'echo requires a params entity');
  }

  // ── §7a conformance: dispatch-outbound (the §6.13(b)/§6.11 outbound seam) ──

  Future<Outcome> _dispatchOutbound(HandlerContext ctx) async {
    final p = ctx.params();
    if (p == null) {
      return Outcome.err(400, 'invalid_params',
          'dispatch-outbound requires a params entity');
    }
    final target = p.text('target') ?? '';
    final operationField = p.text('operation') ?? '';
    final value = p.field('value');
    final capability = p.entityField('reentry_capability');
    final granterPeer = p.entityField('reentry_granter');
    final capSig = p.entityField('reentry_cap_signature');
    if (!(value != null &&
        capability != null &&
        granterPeer != null &&
        capSig != null)) {
      return Outcome.err(400, 'invalid_params',
          'dispatch-outbound requires value + reentry authority');
    }
    // §7a.1 generic relay: the `value` field is the bytes of the downstream's
    // params entity data and MUST be forwarded verbatim, never re-wrapped. The
    // validator already shaped it as echo's {value: X} params; a faithful relay
    // passes the map through as the outbound EXECUTE's params data (re-wrapping
    // double-nests — the non-conformant party the keystone matrix caught).
    final valueMap = asMap(value);
    final innerData = valueMap ?? cmap(['value', value]);
    final inner = Entity.make('primitive/any', innerData);
    final resource = wire.resourceTarget(['system/handler/$target']);
    final env = await _outboundDispatch(ctx.conn, target, operationField, inner,
        capability, granterPeer, capSig, resource);
    if (env == null) {
      return Outcome.err(503, 'no_outbound_seam',
          'no live §6.11 reentry connection');
    }
    final status = env.root.uint('status') ?? BigInt.zero;
    final resultCbor = env.root.field('result') ?? emptyMap();
    return Outcome.ok(Entity.make(
        'primitive/any', cmap(['status', status, 'result', resultCbor])));
  }

  // ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────────

  Future<Envelope?> _outboundDispatch(
    Conn conn,
    String uri,
    String operation,
    Entity params,
    Entity capability,
    Entity granterPeer,
    Entity capSig,
    EcfMap resource,
  ) async {
    final send = conn.outbound;
    if (send == null) return null;
    final requestId = 'out-${conn.nextOutCounter()}';
    final exec = wire.makeExecute(requestId, uri, operation, params,
        author: identity.identityHash(),
        capability: capability.hash(),
        resource: resource);
    final execSig = await identity.sign(exec);
    final included = [
      Included(capability.hash(), capability),
      Included(granterPeer.hash(), granterPeer),
      Included(identity.identityHash(), identity.peerEntity),
      Included(capSig.hash(), capSig),
      Included(execSig.hash(), execSig),
    ];
    return send(Envelope(exec, included));
  }

  // ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────────

  void _ingestSignatures(Envelope env) {
    for (final pair in env.included) {
      final e = pair.entity;
      if (e.type != 'system/signature') continue;
      store.putEntity(e);
      final signerH = e.bytes('signer');
      if (signerH == null) continue;
      final signerPeer = env.includedGet(signerH);
      if (signerPeer == null) continue;
      store.putEntity(signerPeer);
      final target = e.bytes('target');
      final pk = signerPeer.bytes('public_key');
      if (target != null && pk != null) {
        final pid = Identity.peerIdOfPublicKey(pk);
        store.bind('/$pid/system/signature/${hexEncode(target)}', e);
      }
    }
  }

  // ── handler resolution (§6.6) — backward tree-walk ─────────────────────────────────

  /// Return the longest prefix of [path] bound to a system/handler entity, else
  /// null.
  String? _resolveHandler(String path) {
    final segs = path.split('/');
    for (var i = segs.length; i >= 1; i--) {
      final prefix = segs.sublist(0, i).join('/');
      final e = store.getAt(prefix);
      if (e != null && e.type == 'system/handler') return prefix;
    }
    return null;
  }

  String _stripLocal(String pattern) {
    final prefix = '/$localPeer/';
    return pattern.startsWith(prefix) ? pattern.substring(prefix.length) : pattern;
  }

  // ── entity-native dispatch (v7.74 §6.13(a)) ─────────────────────────────────────────

  Outcome _entityNativeDispatch(String handlerPath) {
    final he = store.getAt(handlerPath);
    if (he == null) return Outcome.err(404, 'handler_not_found', handlerPath);
    final exprPath = he.text('expression_path');
    if (exprPath == null) return Outcome.err(501, 'no_handler_body', handlerPath);
    final abs = cap.canonicalize(localPeer, exprPath);
    final expr = store.getAt(abs);
    if (expr == null) return Outcome.err(404, 'expression_not_found', abs);
    if (expr.type == 'compute/literal') {
      final value = expr.field('value');
      if (value == null) {
        return Outcome.err(400, 'unexpected_params', 'compute/literal missing value');
      }
      return Outcome.ok(Entity.make('compute/result',
          cmap(['value', value, 'expression', cbytes(expr.hash())])));
    }
    return Outcome.err(501, 'unsupported_expression', expr.type);
  }

  // ── dispatch chain (§6.5) ──────────────────────────────────────────────────────────

  /// The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or null for a
  /// non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
  Future<Envelope?> dispatch(Conn conn, Envelope env) async {
    final exec = env.root;
    if (exec.type != 'system/protocol/execute') return null;
    final requestId = exec.text('request_id') ?? '';
    Outcome outcome;
    try {
      outcome = await _dispatchInner(conn, env, exec);
    } on cap.UnresolvableGrantee {
      outcome = Outcome.err(401, 'unresolvable_grantee');
    } catch (_) {
      outcome = Outcome.err(500, 'internal_error');
    }
    return Envelope(wire.makeResponse(requestId, outcome.status, outcome.result),
        outcome.included);
  }

  Future<Outcome> _dispatchInner(Conn conn, Envelope env, Entity exec) async {
    final uri = exec.text('uri') ?? '';
    final operation = exec.text('operation') ?? '';
    if (uri == 'system/protocol/connect') {
      return _handlers['system/protocol/connect']!
          .handle(operation, HandlerContext(exec, conn, env.included, null, env));
    }
    _ingestSignatures(env);
    // §5.2 three-way request verdict (+ §4.10(b) chain-depth) — exhaustive switch.
    switch (await cap.verifyRequest(localPeer, store, env)) {
      case cap.RequestVerdict.authnFail:
        return Outcome.err(401, 'authentication_failed');
      case cap.RequestVerdict.authzDeny:
        return Outcome.err(403, 'capability_denied');
      case cap.RequestVerdict.chainTooDeep:
        return Outcome.err(400, 'chain_depth_exceeded');
      case cap.RequestVerdict.allow:
        break; // fall through
    }
    final path = cap.canonicalize(localPeer, cap.normalizeUri(uri));
    // §1.4: inbound dispatch must target the local peer.
    if (cap.extractPeer(localPeer, path) != localPeer) {
      return Outcome.err(404, 'handler_not_found', 'not local peer');
    }
    final pattern = _resolveHandler(path);
    if (pattern == null) return Outcome.err(404, 'handler_not_found', path);
    final capH = exec.bytes('capability');
    final callerCap = capH == null ? null : env.includedGet(capH);
    if (callerCap == null) return Outcome.err(403, 'capability_denied');
    Entity? resolveFn(Uint8List h) => cap.capResolve(env.included, store, h);
    final granterPeer =
        cap.resolveGranterPeerId(resolveFn, callerCap) ?? localPeer;
    if (cap.checkPermission(localPeer, granterPeer, exec, callerCap, pattern) ==
        cap.Verdict.deny) {
      return Outcome.err(403, 'capability_denied');
    }
    final stripped = _stripLocal(pattern);
    final inst = _handlers[stripped];
    if (inst != null) {
      return inst.handle(
          operation, HandlerContext(exec, conn, env.included, callerCap, env));
    }
    return _entityNativeDispatch(pattern);
  }

  // ── bootstrap (§6.9) ──────────────────────────────────────────────────────────────

  EcfMap _opSpec(String? input, String? output) {
    final pairs = <EcfEntry>[];
    if (input != null) {
      pairs.add(EcfEntry(const EcfText('input_type'), EcfText(input)));
    }
    if (output != null) {
      pairs.add(EcfEntry(const EcfText('output_type'), EcfText(output)));
    }
    return EcfMap(pairs);
  }

  Future<void> _bootstrapHandlerEntities(
      String pattern, String name, List<List<String?>> ops) async {
    final opPairs = <EcfEntry>[
      for (final op in ops)
        EcfEntry(EcfText(op[0]!), _opSpec(op[1], op[2])),
    ];
    final operations = EcfMap(opPairs);
    store.bind('/$localPeer/$pattern',
        Entity.make('system/handler', cmap(['interface', 'system/handler/$pattern'])));
    store.bind(
        '/$localPeer/system/handler/$pattern',
        Entity.make('system/handler/interface',
            cmap(['pattern', pattern, 'name', name, 'operations', operations])));
    final m = await _mintToken(identity.identityHash(), const [], null);
    store.bind('/$localPeer/system/capability/grants/$pattern', m.token);
  }

  Future<void> _bootstrap() async {
    // local identity entity in the store (root-granter resolution)
    store.putEntity(identity.peerEntity);
    // publish the §9.5 core type floor
    publishCoreTypes(store, localPeer);

    // instantiate + register the MUST handler instances (the §6.6 → instance map)
    final bootstrap = <_HandlerSpec>[
      _HandlerSpec('system/tree', _OpsHandler({'get': _treeGet, 'put': _treePut}),
          'Tree', [['get', null, null], ['put', null, null]]),
      _HandlerSpec(
          'system/handler',
          _OpsHandler({'register': _handlerRegister, 'unregister': _handlerUnregister}),
          'Handlers',
          [
            ['register', 'system/handler/register-request', 'system/handler/register-result'],
            ['unregister', 'system/handler/unregister-request', null],
          ]),
      _HandlerSpec('system/type', _OpsHandler({'validate': _typeValidate}), 'Types',
          [['validate', 'system/type/validate-request', 'system/type/validate-result']]),
      _HandlerSpec(
          'system/capability',
          _OpsHandler({
            'request': _capRequest,
            'revoke': _capRevoke,
            'configure': _capConfigure,
            'delegate': _capDelegate,
          }),
          'Capability',
          [
            ['request', 'system/capability/request', 'system/capability/grant'],
            ['revoke', 'system/capability/revoke-request', null],
            ['configure', 'system/capability/policy-entry', null],
            ['delegate', 'system/capability/delegate-request', 'system/capability/grant'],
          ]),
      _HandlerSpec(
          'system/protocol/connect',
          _OpsHandler({'hello': _hello, 'authenticate': _authenticate}),
          'Connect',
          [['hello', null, null], ['authenticate', null, null]]),
    ];
    for (final spec in bootstrap) {
      _handlers[spec.pattern] = spec.handler;
      await _bootstrapHandlerEntities(spec.pattern, spec.name, spec.ops);
    }

    // §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap (root, full
    // scope over /{peer}/*, grantee = own identity; §6.9a.0 detached-sig shape) +
    // default scope-template entry. Read back by authenticate (dual-form lookup).
    final policyBase = '/$localPeer/system/capability/policy/';
    final owner = await _mintToken(identity.identityHash(), _ownerGrants(), null);
    store.bind(policyBase + hexEncode(identity.identityHash()), owner.token);
    store.bind(
        '/$localPeer/system/signature/${hexEncode(owner.token.rawHash)}',
        owner.signature);
    final defaultGrants = _openGrants ? _openGrantsScope() : _discoveryFloor();
    final defaultEntry = Entity.make('system/capability/policy-entry',
        cmap(['peer_pattern', 'default', 'grants', _grantsArray(defaultGrants)]));
    store.bind('${policyBase}default', defaultEntry);

    // §7a conformance handlers — only bootstrapped under --validate
    if (_conformance) {
      final conf = <_HandlerSpec>[
        _HandlerSpec('system/validate/echo', _OpsHandler({'echo': _echo}),
            'validate-echo', [['echo', null, null]]),
        _HandlerSpec(
            'system/validate/dispatch-outbound',
            _OpsHandler({'dispatch': _dispatchOutbound}),
            'validate-dispatch-outbound',
            [['dispatch', null, null]]),
      ];
      for (final spec in conf) {
        _handlers[spec.pattern] = spec.handler;
        await _bootstrapHandlerEntities(spec.pattern, spec.name, spec.ops);
      }
    }
  }

  // ── small helpers ────────────────────────────────────────────────────────────────

  String _abs(String rel) => '/$localPeer/$rel';

  EcfValue _grantsArray(List<EcfMap> grants) => EcfArray(List.of(grants));

  /// Build a grant cbor-map. [peers] null → omit (defaults to local at check).
  static EcfMap grant(List<String> handlers, List<String> resources,
      List<String> operations, List<String>? peers) {
    final pairs = <EcfEntry>[
      EcfEntry(const EcfText('handlers'), _scopeCbor(handlers)),
      EcfEntry(const EcfText('resources'), _scopeCbor(resources)),
      EcfEntry(const EcfText('operations'), _scopeCbor(operations)),
    ];
    if (peers != null) {
      pairs.add(EcfEntry(const EcfText('peers'), _scopeCbor(peers)));
    }
    return EcfMap(pairs);
  }

  static EcfMap _scopeCbor(List<String> incl) =>
      EcfMap.of({'include': textArray(incl)});

  static String? _execResourceTarget(Entity exec) {
    final r = exec.mapField('resource');
    if (r == null) return null;
    final targets = textList(r, 'targets');
    return (targets == null || targets.isEmpty) ? null : targets.first;
  }

  static bool _pathFlexOk(String target) {
    if (target.contains(' ')) return false;
    final segs0 = target.split('/');
    final bool absOk;
    List<String> body;
    if (target.startsWith('/')) {
      if (segs0.length >= 2 && segs0[0].isEmpty) {
        absOk = cap.isPeerId(segs0[1]);
        body = segs0.sublist(1);
      } else {
        absOk = false;
        body = segs0;
      }
    } else {
      absOk = true;
      body = segs0;
    }
    if (!absOk) return false;
    if (body.isNotEmpty && body.last.isEmpty) {
      body = body.sublist(0, body.length - 1);
    }
    return !body.any((s) => s.isEmpty || s == '.' || s == '..');
  }

  static List<EcfMap> _reqGrants(Entity? params) =>
      params == null ? const [] : (mapList(params.data(), 'grants') ?? const []);

  static String? _registerPattern(Entity exec) {
    final target = _execResourceTarget(exec);
    if (target == null) return null;
    const prefix = 'system/handler/';
    if (!target.startsWith(prefix) || target.length == prefix.length) return null;
    return target.substring(prefix.length);
  }

  static Outcome _registerPatternError(Entity exec) {
    if (_execResourceTarget(exec) == null) {
      return Outcome.err(400, 'ambiguous_resource',
          'register/unregister require exactly one resource target');
    }
    return Outcome.err(400, 'invalid_resource',
        'resource target MUST be system/handler/{pattern}');
  }
}

// ── internal helpers ────────────────────────────────────────────────────────────

final class _Minted {
  const _Minted(this.token, this.signature);
  final Entity token;
  final Entity signature;
}

final class _HandlerSpec {
  const _HandlerSpec(this.pattern, this.handler, this.name, this.ops);
  final String pattern;
  final Handler handler;
  final String name;
  final List<List<String?>> ops;
}

/// A [Handler] backed by an op→function table; the single-dispatch `switch`
/// ladder is the table lookup, with the "unknown op → 501" arm as the absent-key
/// fallthrough — the Dart-idiomatic shape for the §6.2 handler op routing.
final class _OpsHandler implements Handler {
  const _OpsHandler(this._ops);
  final Map<String, Future<Outcome> Function(HandlerContext)> _ops;

  @override
  Future<Outcome> handle(String operation, HandlerContext ctx) {
    final fn = _ops[operation];
    if (fn == null) {
      return Future.value(Outcome.err(501, 'unsupported_operation', operation));
    }
    return fn(ctx);
  }
}
