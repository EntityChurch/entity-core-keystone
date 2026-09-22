import 'dart:math';
import 'dart:typed_data';

import '../codec/ecf_value.dart';
import '../codec/varint.dart';
import '../crypto/content_hash.dart';
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

  /// Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
  ///
  /// [expiresAt] null means no term was defined and the token genuinely has no
  /// expiry (the ONLY "no bound" spelling). A non-null value is emitted verbatim —
  /// including one equal to [createdAt], which §5.6 rule 2 requires for
  /// ttl_ms == 0 and which means "already expired at every observable instant",
  /// not "unbounded".
  ///
  /// [createdAt] is supplied rather than sampled here so a computed expiry is
  /// guaranteed to be relative to the SAME instant that lands in the token;
  /// sampling the clock twice skews the two.
  Future<_Minted> _mintTokenAt(int createdAt, Uint8List granteeHash,
      List<EcfMap> grants, Uint8List? parent, BigInt? expiresAt) async {
    final pairs = <EcfEntry>[
      EcfEntry(const EcfText('granter'), EcfBytes(identity.identityHash())),
      EcfEntry(const EcfText('grantee'), EcfBytes(granteeHash)),
      EcfEntry(const EcfText('grants'), _grantsArray(grants)),
      EcfEntry(const EcfText('created_at'), EcfInt.of(createdAt)),
    ];
    if (expiresAt != null) {
      pairs.add(EcfEntry(const EcfText('expires_at'), EcfInt(expiresAt)));
    }
    if (parent != null) {
      pairs.add(EcfEntry(const EcfText('parent'), EcfBytes(parent)));
    }
    final token = Entity.make('system/capability/token', EcfMap(pairs));
    final signature = await identity.sign(token);
    return _Minted(token, signature);
  }

  /// _mintTokenAt at the current instant with no §5.6 ceiling. Used by the paths
  /// that mint a self-issued grant from local authority (bootstrap, handler
  /// registration, the §4.4 handshake), where no MIN_DEFINED term is in play.
  Future<_Minted> _mintToken(
          Uint8List granteeHash, List<EcfMap> grants, Uint8List? parent) =>
      _mintTokenAt(cap.nowMs(), granteeHash, grants, parent, null);

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
    // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
    // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
    // implement arriving in a state that forbids it — the same class as
    // connection_already_established above, taking the same 409. A half-open
    // connection is NOT established, so the guard above cannot reach it; §4.7
    // names this gap explicitly because two adjacent rules each look like they
    // cover it and neither does.
    if (conn.issuedNonce != null) {
      return Outcome.err(409, 'connection_sequence_error');
    }
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
    final helloPid = params?.text('peer_id');
    // §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
    // is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in its
    // `peer_id` — so a hello may advertise a perfectly good accept-set and still
    // name an identity we cannot verify. Checking only the array leaves that MUST
    // unenforced at hello, which is where §4.5 wants it; authenticate catches it
    // one leg later, which is conformant but non-canonical.
    //
    // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed field,
    // not a key_type we lack, and authenticate already refuses it.
    if (helloPid != null) {
      var badKt = false;
      try {
        badKt = PeerId.parse(helloPid).keyType != PeerId.keyTypeEd25519;
      } catch (_) {
        badKt = false;
      }
      if (badKt) return Outcome.err(400, 'unsupported_key_type');
    }
    // §4.5 `protocols` — the one negotiated field Required with NO default, so
    // there is no floor to fall back to, and its two failure modes carry different
    // codes on purpose (§4.5 table row / §4.7 row 1):
    //
    //   absent or empty     -> 400 invalid_request       (a malformed hello)
    //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
    //
    // "a caller that named no version cannot be told the comparison failed" — the
    // remedies differ (send the field vs change the version) and §4.7 exists so the
    // code selects the remedy. The vocabulary is §8.4's protocol version
    // identifiers, today the single entity-core/1.0.
    //
    // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
    // precedence between the three, so a hello disjoint in more than one dimension
    // may be refused on any of them — but the choice is OBSERVABLE, and the
    // reference peer refuses key_types first. Checking protocols first is equally
    // spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol, because
    // that probe's own hello carries protocols ["entity-core/v7"] — a spec-line
    // name, not a §8.4 identifier (F56).
    final protos = _strArray(exec, 'protocols');
    if (protos == null || protos.isEmpty) {
      return Outcome.err(
          400, 'invalid_request', 'hello: protocols absent or empty');
    }
    if (!protos.contains('entity-core/1.0')) {
      return Outcome.err(400, 'incompatible_protocol');
    }
    conn.helloPeerId = helloPid;
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
    // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
    // single-use nonce. The anti-replay property is the MUST and the mechanism
    // (established-state tracking) is impl-defined, but the STATUS is pinned to
    // 401 invalid_nonce — a 409 state-conflict under-signals the replay.
    if (conn.established) return Outcome.err(401, 'invalid_nonce');
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
    final rawEntity = params?.field('entity');
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
    if (rawEntity == null) {
      return Outcome.err(400, 'unexpected_params', 'put: missing entity');
    }
    final admitted = _admitPut(rawEntity);
    if (admitted is Outcome) return admitted;
    final entity = admitted as Entity;
    store.bind(path, entity);
    return Outcome.ok(Entity.make(
        'system/hash', cmap(['hash', cbytes(entity.hash())])));
  }

  /// Digest byte length for a `content_hash_format` code per the §1.2 seed
  /// table, or null when this peer cannot VERIFY that code. The total wire
  /// length is this plus the varint prefix, which is not a constant of the code
  /// (§7.3): codes >= 0x80 occupy more than one byte.
  static const Map<int, int> _hashDigestLen = {0x00: 32, 0x01: 48};

  /// §6.3's `put` admission ladder (normative, 0.8.2.11).
  ///
  /// `put` is a RECEIPT path: the submitter authors the entity, the peer
  /// validates what it received (§1.8 item 1) and MUST NOT author a submitted
  /// entity's `content_hash` on the submitter's behalf. Two ordered steps:
  ///
  /// 1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data`
  ///    (any CBOR value; null is a legal payload), and a `content_hash` that is
  ///    a well-formed `system/hash` whose total byte length matches its format
  ///    code (§1.2). Any failure -> 400 `invalid_request`. A well-formed hash
  ///    naming a format code this peer cannot verify is the separate §1.2
  ///    ingest-dispatch case -> 400 `unsupported_content_hash_format`.
  /// 2. HASH — carried `content_hash` vs `content_hash({type, data})`.
  ///    Disagreement -> 400 `hash_mismatch`.
  ///
  /// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
  /// 2's inputs are exactly what step 1 establishes, so a submission that is
  /// both malformed and mis-hashed is step 1's and answers `invalid_request`.
  ///
  /// Structural admission is not semantic validation: `data` is never checked
  /// against the type named by `type`.
  ///
  /// Returns the admitted [Entity], or the [Outcome] it was refused with.
  Object _admitPut(EcfValue v) {
    Outcome refuse(String code, String message) => Outcome.err(400, code, message);

    if (v is! EcfMap) return refuse('invalid_request', 'put: entity is not a map');
    final typeV = v['type'];
    if (typeV is! EcfText || typeV.value.isEmpty) {
      return refuse('invalid_request',
          'put: entity.type absent, empty or not a text string');
    }
    // Presence, not truthiness: a CBOR null is a legal `data` payload and is a
    // NODE here, so a non-null lookup is exactly the presence test §6.3 wants.
    final dataV = v['data'];
    if (dataV == null) return refuse('invalid_request', 'put: entity.data absent');
    final chV = v['content_hash'];
    if (chV is! EcfBytes || chV.octets.isEmpty) {
      return refuse('invalid_request',
          'put: entity.content_hash absent or not a byte string');
    }
    final carried = chV.octets;
    final VarintDecoded decoded;
    try {
      decoded = Varint.decode(carried, 0);
    } catch (_) {
      return refuse('invalid_request',
          'put: entity.content_hash is not a well-formed system/hash');
    }
    if (!decoded.value.isValidInt) {
      return refuse('unsupported_content_hash_format',
          'put: unsupported content_hash_format');
    }
    final digestLen = _hashDigestLen[decoded.value.toInt()];
    if (digestLen == null) {
      // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
      // invalid_request: the shape is fine, the algorithm is what we lack.
      return refuse('unsupported_content_hash_format',
          'put: unsupported content_hash_format');
    }
    if (carried.length != decoded.next + digestLen) {
      return refuse('invalid_request',
          'put: content_hash length does not match its format code');
    }
    final Uint8List computed;
    try {
      computed = ContentHash.compute(EcfMap.of({'type': typeV, 'data': dataV}),
          formatCode: decoded.value.toInt());
    } catch (_) {
      return refuse('hash_mismatch',
          'put: content_hash does not match content_hash({type, data})');
    }
    if (!octetsEqual(computed, carried)) {
      return refuse('hash_mismatch',
          'put: content_hash does not match content_hash({type, data})');
    }
    // The carried hash IS the entity's address; recomputing it into the store
    // would be the authoring arm §6.3 forbids.
    return Entity.admitted(typeV.value, dataV, carried);
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
    return _mintBounded(ctx.env, ctx.callerCap, params, _reqGrants(params), author, null);
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
    return _mintBounded(ctx.env, ctx.callerCap, params, _reqGrants(params), author, ph);
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

  Future<Outcome> _mintBounded(Envelope env, Entity? callerCap, Entity? params,
      List<EcfMap> reqGrants, Uint8List granteeHash, Uint8List? parent) async {
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

    // §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
    // convert the duration term against that same instant.
    //
    // Note what this is NOT: an authorization decision. An over-long ttl_ms from a
    // bounded caller MINTS a clamped token and returns 200 — "rejecting it is
    // non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
    // (parent: null), so §5.6's parent-child attenuation never reaches it; without
    // this clamp, temporal attenuation is the one dimension a requester could
    // escape, and policy withdrawal would have no bounded latency.
    final createdAt = cap.nowMs();
    BigInt? ceiling;
    void fold(BigInt? term) {
      if (term != null && (ceiling == null || term < ceiling!)) ceiling = term;
    }

    if (parent != null) {
      final pt = env.includedGet(parent) ?? store.getByHash(parent);
      if (pt != null) fold(pt.uint('expires_at')); // absolute
    }
    if (callerCap != null) fold(callerCap.uint('expires_at')); // absolute
    final ttl = params?.uint('ttl_ms');
    if (ttl != null) fold(cap.addTtl(createdAt, ttl)); // duration

    final m =
        await _mintTokenAt(createdAt, granteeHash, reqGrants, parent, ceiling);
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
    if (pattern == 'system' || pattern.startsWith('system/')) {
      return Outcome.err(403, 'forbidden_pattern',
          '§6.2: user-installed handlers MUST NOT register at system/* paths: $pattern');
    }
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
    // §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
    // sit below the verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace took
    // the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the caller
    // to authenticate and retry, and for a foreign-namespace address that retry cannot
    // succeed at any authentication state — so the 401 names a remedy that does not exist."
    // §6.5 step 3 calls it "a gate, not an ordering preference" and §1.4 makes the downstream
    // permission check unreachable here.
    final path = cap.canonicalize(localPeer, cap.normalizeUri(uri));
    if (cap.extractPeer(localPeer, path) != localPeer) {
      return Outcome.err(400, 'invalid_request', 'not local peer');
    }
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
    // (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
    // 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
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
          _OpsHandler({'hello': _hello, 'authenticate': _authenticate},
              unknownOpIsInvalidRequest: true),
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
    if (target.contains('\u0000')) return false;
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
  const _OpsHandler(this._ops, {this.unknownOpIsInvalidRequest = false});
  final Map<String, Future<Outcome> Function(HandlerContext)> _ops;

  /// §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
  /// 400 invalid_request, not the 501 every other handler answers. The table
  /// separates a STATE conflict from an UNKNOWN operation because they select
  /// different remedies — "an unknown connect operation is not out of order at
  /// all; it exists in no state", so connection_sequence_error would point the
  /// caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
  /// scoped "in any state", so this arm covers pre-handshake AND established;
  /// the genuine sequence cases are refused in _hello/_authenticate, with 409.
  ///
  /// A FLAG ON THE SHARED TABLE RATHER THAN A CHANGE TO IT. The generic
  /// registered-handler rule (§3.3's 501 row, §6.2) is a different contract and
  /// is separately gated; moving the shared 501 would trade one green check for
  /// another, so exactly one construction site sets this.
  final bool unknownOpIsInvalidRequest;

  @override
  Future<Outcome> handle(String operation, HandlerContext ctx) {
    final fn = _ops[operation];
    if (fn == null) {
      return Future.value(unknownOpIsInvalidRequest
          ? Outcome.err(
              400, 'invalid_request', 'connect: unknown operation $operation')
          : Outcome.err(501, 'unsupported_operation', operation));
    }
    return fn(ctx);
  }
}
