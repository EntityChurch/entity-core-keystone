import 'dart:typed_data';

import 'package:entity_core_protocol/entity_core_peer.dart';
import 'package:entity_core_protocol/src/codec/ecf_value.dart';
import 'package:entity_core_protocol/src/peer/wire.dart' as wire;
import 'package:test/test.dart';

/// §3.3's effective-targets ladder, the §6.3 path check it gates, and the §6.3
/// listing filter (RULE A, 0.8.2.20/.21/.22 + N7/N10/N11 at .24/.25).
///
/// EVERY LADDER CASE GOES THROUGH THE REAL DISPATCH CHAIN with a fully signed
/// envelope, not through the tree handler directly. That is not ceremony: it is what
/// makes the RULE G ordering claim an ordering claim at all, since a test that
/// resolves the operation itself cannot see a handler that validates the resource
/// first. It also means the §6.3 check runs on the authority the DISPATCH check
/// resolved, which is the property §6.8 names.
void main() {
  Uint8List seed(int b) => Uint8List(32)..fillRange(0, 32, b);

  late Peer peer;
  late String local;

  setUp(() async {
    // The discovery floor, NOT open grants: the §6.3 path check is only observable
    // where the caller's grant is narrower than the request.
    peer = await Peer.create(seed(0x5a), openGrants: false, conformance: false);
    local = peer.localPeer;
    peer.store.bind('/$local/app/a', Entity.make('primitive/any', cmap(['v', 1])));
    peer.store.bind('/$local/app/b', Entity.make('primitive/any', cmap(['v', 2])));
  });

  EcfMap scopeOf(List<String> incl, [List<String> excl = const []]) => EcfMap.of({
        'include': textArray(incl),
        if (excl.isNotEmpty) 'exclude': textArray(excl),
      });

  /// A SELF-ISSUED ROOT capability whose three dimensions move independently.
  ///
  /// granter == grantee == this peer's identity hash, which is what §5.5's root arm
  /// requires ("root must be self-issued by the local peer") and what makes the token
  /// usable through the real dispatch chain.
  Entity token({
    List<String> handlers = const ['*'],
    List<String> operations = const ['*'],
    List<String> resources = const ['*'],
    List<String> resourcesExcl = const [],
  }) {
    final idh = peer.identity.identityHash();
    return Entity.make(
      'system/capability/token',
      cmap([
        'granter', cbytes(idh),
        'grantee', cbytes(idh),
        'created_at', EcfInt.of(1700000000000),
        'grants', EcfArray([
          EcfMap.of({
            'handlers': scopeOf(handlers),
            'operations': scopeOf(operations),
            'resources': scopeOf(resources, resourcesExcl),
          }),
        ]),
      ]),
    );
  }

  EcfMap? resourceOf(List<String>? targets, [List<String> excl = const []]) =>
      targets == null
          ? null
          : EcfMap.of({
              'targets': textArray(targets),
              if (excl.isNotEmpty) 'exclude': textArray(excl),
            });

  /// Drive one request through `Peer.dispatch`. Returns (status, code, result).
  Future<(int, String, Entity?)> drive(
    String operation,
    EcfMap? resource, {
    Entity? cap,
    Entity? params,
    bool withCap = true,
  }) async {
    final id = peer.identity;
    final t = cap ?? token();
    final exec = wire.makeExecute(
      'r1',
      'system/tree',
      operation,
      params ?? wire.emptyParams(),
      author: withCap ? id.identityHash() : null,
      capability: withCap ? t.hash() : null,
      resource: resource,
    );
    // §5.2 demands a system/signature over the EXECUTE whose signer binds to
    // `author`, and a chain whose root is self-issued by this peer. Anything less is
    // refused at the verdict and every ladder assertion below would be reading a 401
    // rather than the handler.
    final included = withCap
        ? [t, id.peerEntity, await id.sign(t), await id.sign(exec)]
        : <Entity>[];
    final env = Envelope(
        exec, [for (final e in included) Included(e.rawHash, e)]);
    final resp = await peer.dispatch(Conn(), env);
    expect(resp, isNotNull, reason: 'every inbound root is answered (N12/N17)');
    final status = wire.responseStatus(resp!);
    final res = wire.responseResult(resp);
    return (status, res?.text('code') ?? '', res);
  }

  group('effective_targets: the two-empties discriminator (N11, 0.8.2.25)', () {
    // N11 makes the discriminator a [MUST]: "that projection MUST NOT be lossy about
    // its own emptiness — narrow when narrowing leaves something, and retain the raw
    // pair when narrowing would empty it." This peer carries it as a two-field record
    // rather than a nullable list, so the collapse is not one `?? const []` away.
    EffectiveTargets eff(EcfMap? r) => effectiveTargets(
        local,
        wire.makeExecute(
            'r1', 'system/tree', 'get', wire.emptyParams(), resource: r));

    test('an ABSENT resource reports absent', () {
      expect(eff(null).hadResource, isFalse);
    });

    test('a resource map with no `targets` key reports absent (an OPEN question)', () {
      // PINS THE SHIPPED ANSWER rather than endorsing it. Every 0.8.2.25 peer reports
      // this absent, so `get` serves it the root listing; §3.2 says `targets` "MUST
      // contain at least one entry", which makes the shape MALFORMED rather than
      // absent, and N10's point is that a PRESENT `resource` must not be served the
      // wider absent-case answer. Nothing in the 778-check set drives it and no
      // disposition is pinned, so the behaviour is HELD rather than changed; this
      // case exists so that changing it is a DECISION.
      expect(eff(EcfMap.of({'exclude': textArray(['a'])})).hadResource, isFalse);
    });

    test('a PRESENT but fully-excluded resource is present with an empty list', () {
      final e = eff(resourceOf(['a'], ['a']));
      expect(e.hadResource, isTrue);
      expect(e.survivors, isEmpty);
    });

    test("survivors keep the caller's OWN SPELLING", () {
      // 0.8.2.21: `effective_targets` yields RAW survivors, not canonical forms — the
      // value flows on to the store lookup, which canonicalizes for itself.
      expect(eff(resourceOf(['app/x', 'app/y'], ['app/y'])).survivors,
          equals(['app/x']));
    });

    test('an unmatchable CALLER exclude is fail-OPEN: the target survives', () {
      // §5.4's table rules the caller-exclude arm SEPARATELY from the grant arm and in
      // the opposite direction: canonicalize answers the sentinel, matchesPattern
      // answers false, and the target survives. INHERITED from the primitives here
      // rather than restated — restating it is how the two readings drift.
      expect(eff(resourceOf(['app/a'], ['../nope'])).survivors, equals(['app/a']));
      // The accept-side control: without it a peer that ignored `exclude` entirely
      // would pass the row above for the wrong reason.
      expect(eff(resourceOf(['app/a'], ['app/a'])).survivors, isEmpty);
    });
  });

  group('RULE G: operation resolution precedes resource validation', () {
    // "Resolve the operation first; only then run the §3.3 ladder." A peer that
    // validates the resource first answers a RESOURCE fault for an OPERATION fault on
    // every unknown operation — measured independently by `entity-system-conformance`
    // (X9 / F52) on the peers whose tree handler is one match over
    // (operation, resource).
    //
    // ON THIS SUBSTRATE THE ORDERING IS STRUCTURAL AND THAT IS THE FINDING, not a
    // fix: `_OpsHandler.handle` looks the operation up in a map and answers 501 on a
    // miss, and the §3.3 ladder lives inside `_treeGet`/`_treePut`, which only a known
    // operation reaches. The pair is asserted anyway because "it cannot happen" is a
    // claim about today's dispatcher, and this is what keeps it one.

    test('an unknown operation is 501 WITH and WITHOUT a resource', () async {
      final without = await drive('bogusop', null);
      expect(without.$1, equals(501));
      expect(without.$2, equals('unsupported_operation'));
      // THE CONTROL that makes this an ORDERING claim rather than a missing-501
      // claim: on the peers that had the defect, these two answered DIFFERENTLY.
      final with_ = await drive('bogusop', resourceOf(['app/a']));
      expect(with_.$1, equals(501));
      expect(with_.$2, equals('unsupported_operation'));
      // ...and a KNOWN operation still routes, or the two above are satisfied by a
      // handler that answers 501 to everything.
      expect((await drive('get', resourceOf(['app/a']))).$1, equals(200));
    });
  });

  group('the ladder, get (resource-OPTIONAL, BROAD-RESULT)', () {
    // EXTENSION-TREE §2.2a (v4.11) declares `get` resource-OPTIONAL and BROAD-RESULT:
    // absent-case answer "the root listing", self-excluded case "400 path_required".
    // 0.8.2.24 (N7) scopes §3.3's "an empty effective list IS the absent case" to "an
    // operation that REQUIRES a resource", and 0.8.2.25 (N10) decides the
    // present-but-empty case by whether the absent case is WIDER than the request.

    test('an ABSENT resource serves the root listing', () async {
      final (status, _, res) = await drive('get', null);
      expect(status, equals(200));
      expect(res!.type, equals('system/tree/listing'));
      expect(res.text('path'), equals('/$local/'));
    });

    test('a PRESENT but self-excluded resource is 400 path_required', () async {
      // THE TWO EMPTIES ARE DISTINCT, and this is the pair that says so. Collapsing
      // them serves the ROOT LISTING to a request that named one excluded path — the
      // wider-than-the-request answer §3.3 forbids.
      final (status, code, _) = await drive('get', resourceOf(['app/a'], ['app/a']));
      expect(status, equals(400));
      expect(code, equals('path_required'));
    });

    test('more than one EFFECTIVE target is 400 ambiguous_resource', () async {
      final (status, code, _) = await drive('get', resourceOf(['app/a', 'app/b']));
      expect(status, equals(400));
      expect(code, equals('ambiguous_resource'));
      // ...and the exclude is what makes the COUNT an effective-set count rather than
      // a raw `targets` count: two targets, one excluded, ONE survivor -> it proceeds.
      expect((await drive('get', resourceOf(['app/a', 'app/b'], ['app/b']))).$1,
          equals(200));
    });

    test('the selection is the SURVIVOR, never targets[0]', () async {
      // THE MUST 0.8.2.20 NAMES: a handler that counts the effective list and then
      // indexes `targets[0]` has implemented the arithmetic completely and is still
      // reading a path no authorization covered. `targets[0]` is EXCLUDED here and the
      // single survivor is `targets[1]`, so the two readings return DIFFERENT
      // entities.
      final (status, _, res) =
          await drive('get', resourceOf(['app/a', 'app/b'], ['app/a']));
      expect(status, equals(200));
      expect(res!.uint('v')?.toInt(), equals(2), reason: 'the survivor app/b, not app/a');
    });

    test('a PATTERN target is 400 malformed_resource; a trailing slash is a listing',
        () async {
      // 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A trailing "/"
      // is a listing request and is NOT a pattern — only a star makes it one.
      final pat = await drive('get', resourceOf(['app/*']));
      expect(pat.$1, equals(400));
      expect(pat.$2, equals('malformed_resource'));
      final lst = await drive('get', resourceOf(['app/']));
      expect(lst.$1, equals(200));
      expect(lst.$3!.type, equals('system/tree/listing'));
    });
  });

  group('the ladder, put (resource-REQUIRED)', () {
    test('a MISSING put target is 400 path_required, not ambiguous_resource', () async {
      // THE CODE CHANGE 0.8.2.20 FORCED. This branch answered `ambiguous_resource` for
      // a MISSING target, which 0.8.2.20 names as the exact inversion it forbids: the
      // remedies differ — supply a resource is not disambiguate your request — and the
      // code is what selects the remedy.
      final miss = await drive('put', null);
      expect(miss.$1, equals(400));
      expect(miss.$2, equals('path_required'));
      // BOTH empties collapse here, because §2.2a declares `put` resource-REQUIRED:
      expect((await drive('put', resourceOf(['app/a'], ['app/a']))).$2,
          equals('path_required'));
      // ...and more than one survivor is still `ambiguous_resource`, which says the
      // two codes have not simply been swapped.
      expect((await drive('put', resourceOf(['app/a', 'app/b']))).$2,
          equals('ambiguous_resource'));
    });
  });

  group('section 6.3: the handler-level path check (0.8.2.20)', () {
    // THE F84 LAYER. §6.3: "not a secondary check ... the sole enforcement wherever
    // the subject is derived after dispatch."
    //
    // WHICH RUNG ANSWERS THE SCALAR 403 IS BOTH, and that was measured rather than
    // assumed: this peer's dispatch-level `checkResourceScope` requires every
    // non-caller-excluded target to be covered, so for a SCALAR get the handler's
    // derived path is always a path dispatch already saw, and the two rungs are
    // independently sufficient. The arm where §6.3 is the ONLY thing standing is the
    // LISTING, whose entries the dispatch check never sees — measured below, and that
    // is where a plant on the filter bites.

    test('a GET on a path the caller capability excludes is 403', () async {
      final narrow = token(resources: ['*'], resourcesExcl: ['app/b']);
      final denied = await drive('get', resourceOf(['app/b']), cap: narrow);
      expect(denied.$1, equals(403));
      expect(denied.$2, equals('capability_denied'));
      // CONTROL, in the SAME capability: a path the same grant covers is served.
      expect((await drive('get', resourceOf(['app/a']), cap: narrow)).$1, equals(200));
    });

    test('a PUT on an excluded path is 403 and writes nothing', () async {
      final narrow = token(resources: ['*'], resourcesExcl: ['app/b']);
      final e = Entity.make('primitive/any', cmap(['v', 9]));
      final params = Entity.make('primitive/any', cmap(['entity', e.toCbor()]));
      final out =
          await drive('put', resourceOf(['app/b']), cap: narrow, params: params);
      expect(out.$1, equals(403));
      expect(out.$2, equals('capability_denied'));
      // ...and nothing was written: `app/b` still holds what setUp bound. A 403 whose
      // refusal arrives AFTER the store write would satisfy the status assertion on
      // its own, which is why the store is read here.
      expect(peer.store.getAt('/$local/app/b')!.uint('v')?.toInt(), equals(2));
    });

    test('checkPathPermission moves one dimension at a time', () {
      // The unit-level form. A predicate test built only from DENY cases is
      // indistinguishable from one asserting `false == false`, so the ACCEPT case is
      // what validates the fixture; one deny per DIMENSION is what says the predicate
      // checks the dimension rather than merely denying.
      final wide = token();
      expect(checkPathPermission(local, 'get', 'app/a', wide, 'system/tree'), isTrue);
      expect(
          checkPathPermission(local, 'get', 'app/a', token(operations: ['put']),
              'system/tree'),
          isFalse);
      expect(
          checkPathPermission(local, 'get', 'app/a',
              token(handlers: ['system/other']), 'system/tree'),
          isFalse);
      // An empty `resources.include` is a LEGAL grant shape (§5.2: handlers that touch
      // no tree paths) and DENIES every path here, which is what that note says it
      // should — `covered` over an empty include list is false.
      expect(
          checkPathPermission(
              local, 'get', 'app/a', token(resources: const []), 'system/tree'),
          isFalse);
      // canonicalize is TOTAL and answers the sentinel, which matches no grant, so a
      // malformed path falls through to DENY rather than being matched.
      expect(checkPathPermission(local, 'get', '../escape', wide, 'system/tree'),
          isFalse);
    });
  });

  group('section 6.3: the listing filter (0.8.2.21/.22)', () {
    // "Entries for which check_path_permission returns DENY MUST be omitted. The
    // result's `count` field MUST reflect the FILTERED entry count, not the source
    // tree's total count." A count that still reports the source total IS the
    // disclosure the rule exists to prevent, so it is asserted separately from the
    // entry map: a filter that omits the entry and leaves the count names how many
    // bindings the caller was not allowed to see.

    List<String> segmentsOf(Entity listing) {
      final m = listing.mapField('entries')!;
      return m.entries.map((e) => (e.key as EcfText).value).toList()..sort();
    }

    test('the listing omits an entry the caller cap excludes, and count follows',
        () async {
      final narrow = token(resources: ['*'], resourcesExcl: ['app/b']);
      final (status, _, res) = await drive('get', resourceOf(['app/']), cap: narrow);
      expect(status, equals(200));
      expect(segmentsOf(res!), equals(['a']));
      expect(res.uint('count')?.toInt(), equals(1));
    });

    test('a wide capability sees both entries', () async {
      // The differential that attributes the row above to the FILTER rather than to
      // the store or the directory being wrong: same directory, a grant that covers
      // both, both entries.
      final (_, __, res) = await drive('get', resourceOf(['app/']));
      expect(segmentsOf(res!), equals(['a', 'b']));
      expect(res.uint('count')?.toInt(), equals(2));
    });

    test('the filter narrows on an INCLUDE as well as on an exclude', () async {
      // Both rows above narrow with `exclude`, and a filter that only consulted the
      // exclude list would pass both. This one covers the directory and one child and
      // says nothing about the other.
      //
      // SAY WHAT IS NOT ASSERTED HERE. §6.3's "the DIRECTORY itself is deliberately
      // not checked — each ENTRY is the subject" is NOT separately observable through
      // the dispatch chain on this peer: the dispatch-level check already requires the
      // caller's grant to cover the listing TARGET, so a grant covering only `app/a`
      // is refused at §5.2 before any listing is built, and a grant that does cover
      // `app/` cannot distinguish a filter that checks the prefix from one that does
      // not. The property is real and enforced in `_entryVisible` (the per-entry call
      // is on the CHILD path); it is recorded here as not-driven rather than asserted
      // by a case that would pass either way.
      final dirAndA = token(resources: ['app/', 'app/a']);
      final (status, _, res) = await drive('get', resourceOf(['app/']), cap: dirAndA);
      expect(status, equals(200));
      expect(segmentsOf(res!), equals(['a']));
      expect(res.uint('count')?.toInt(), equals(1));
    });
  });
}
