import 'dart:typed_data';

import '../codec/ecf_value.dart';
import 'cbor.dart';
import 'entity.dart';
import 'envelope.dart';
import 'identity.dart';
import 'store.dart';

/// §5.10 Layer-1 verdict.
enum Verdict { allow, deny }

/// §5.2 three-way request verdict (+ §4.10(b) structural chain-depth case).
enum RequestVerdict { allow, authnFail, authzDeny, chainTooDeep }

/// §5.5 carve-out: a grantee that cannot be resolved → 401, not 403. Carried as
/// a thrown sentinel (the unresolvable-grantee control-flow edge), caught at the
/// dispatch boundary — the recoverable path stays in the [Verdict] value model.
final class UnresolvableGrantee implements Exception {
  const UnresolvableGrantee();
  @override
  String toString() => 'unresolvable grantee';
}

/// A parsed scope (include/exclude pattern lists).
final class Scope {
  const Scope(this.incl, this.excl);
  final List<String> incl;
  final List<String> excl;
}

/// A parsed grant record (the four §5.4 dimensions; peers optional).
final class GrantRec {
  const GrantRec(this.handlers, this.resources, this.operations, this.peers);
  final Scope handlers;
  final Scope resources;
  final Scope operations;
  final Scope? peers;
}

/// A parsed multi-sig granter descriptor: the signer identity hashes + the k
/// threshold.
final class MultiGranter {
  const MultiGranter(this.signers, this.threshold);
  final List<Uint8List> signers;
  final BigInt threshold;
}

/// A resolver: content_hash → Entity (or null). Synchronous (resolution is a
/// map/included lookup; only signature VERIFY is async).
typedef Resolve = Entity? Function(Uint8List h);

/// Capability system (L3): the §5 verification core — pattern matching (§5.4),
/// request verification (§5.2 [verifyRequest] / [checkPermission]),
/// delegation-chain verification (§5.5), attenuation (§5.6), caveats (§5.7),
/// revocation (§5.1), and genuine §3.6 M3 multi-signature K-of-N
/// ([verifyMultiSigRoot]).
///
/// Derived from the §5 pseudocode directly. The verdict is a Dart `enum`
/// ([Verdict] allow/deny — §5.10 Layer-1 determinism) matched exhaustively by a
/// `switch`; the dispatcher maps deny → 403, with the §5.5 unresolvable-grantee
/// → 401 carve-out carried as [UnresolvableGrantee]. The three-way request
/// verdict ([RequestVerdict]) folds in the §4.10(b) `chainTooDeep` (→ 400).
///
/// Chain verification is `async` because the per-link signature checks await
/// Ed25519 verify (profile [async]). The depth pre-check + structural M3 checks
/// are sync (no signature work).
///
/// The §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension's patterns
/// canonicalize against the GRANTER's peer_id; handlers/operations/peers stay on
/// the local frame. For the self-issued dominant path (granter = local) this is
/// byte-identical to the pre-fix behavior; only the foreign-granter cross-peer
/// case flips (exercised at S4 against the oracle).

// ── grant / scope parse ───────────────────────────────────────────────────────

Scope parseScope(EcfMap? m) {
  if (m == null) return const Scope([], []);
  return Scope(textList(m, 'include') ?? const [], textList(m, 'exclude') ?? const []);
}

GrantRec parseGrant(EcfMap? m) {
  final peers = (m?['peers'] != null) ? parseScope(asMap(m!['peers'])) : null;
  return GrantRec(
    parseScope(asMap(m?['handlers'])),
    parseScope(asMap(m?['resources'])),
    parseScope(asMap(m?['operations'])),
    peers,
  );
}

List<GrantRec> grantsOfToken(Entity token) =>
    (mapList(token.data(), 'grants') ?? const []).map(parseGrant).toList();

// ── §5.4 pattern matching ─────────────────────────────────────────────────────

bool _startsWith(String prefix, String s) =>
    s.length >= prefix.length && s.startsWith(prefix);

String normalizeUri(String uri) =>
    _startsWith('entity://', uri) ? '/${uri.substring(9)}' : uri;

/// The unmatchable value (0.8.2.20). Unreachable as a canonical path by
/// CONSTRUCTION: its first segment cannot be a peer_id, since [isPeerId] requires
/// >= 46 Base58 characters and `-` is outside the Base58 alphabet.
const neverMatch = '/never-match';

/// Resolve peer-relative paths to absolute /{local}/... form.
///
/// TOTAL (0.8.2.20): the return domain is "a canonical path OR [neverMatch]". This
/// used to THROW, and the throw was reachable from the wire — every normative call
/// site is a matcher with no error channel to consume one, so the exception escaped
/// the matcher, the resilience frame caught it, and `../x` in a resource exclude
/// answered 500 (measured 2026-09-14). The diagnostic belongs at admission (§6.5),
/// which has a caller to answer.
String canonicalize(String localPeer, String path) {
  if (_startsWith('./', path) || _startsWith('../', path)) return neverMatch;
  if (_startsWith('*/', path)) return neverMatch;
  if (_startsWith('/', path)) return path;
  return '/$localPeer/$path';
}

bool matchesPattern(String path, String pattern) {
  // neverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
  // rule rather than a property of the string: the arm below returns true for a
  // bare '*', so safety must not rest on a value merely looking unmatchable.
  if (path == neverMatch || pattern == neverMatch) return false;
  if (pattern == '*') return true;
  if (_startsWith('/*/', pattern)) {
    final remainder = pattern.substring(3);
    if (path.isEmpty) return false;
    final i = path.indexOf('/', 1);
    return i >= 0 && matchesPattern(path.substring(i + 1), remainder);
  }
  if (pattern.length >= 2 && pattern.endsWith('/*')) {
    return _startsWith(pattern.substring(0, pattern.length - 1), path);
  }
  return path == pattern;
}

/// Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
/// call site — no default — so a new one cannot inherit the wrong matcher silently,
/// which is exactly the F40 defect.
enum ScopeKind {
  /// `operations`, `peers` — `system/capability/id-scope`.
  id,

  /// `handlers`, `resources` — `system/capability/path-scope`.
  path,
}

/// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
/// — bare `*` and a trailing slash-star segment-prefix. None of the §5.4 path transforms
/// apply, so a pattern carrying path syntax is matched as a literal string: a non-match,
/// never a fault.
bool matchesIdPattern(String value, String pattern) {
  if (pattern == '*') return true;
  if (pattern.length >= 2 && pattern.endsWith('/*')) {
    return value.startsWith(pattern.substring(0, pattern.length - 1));
  }
  return value == pattern;
}

bool _coveredId(List<String> pats, String value) =>
    pats.any((p) => matchesIdPattern(value, p));

/// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
/// fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
/// fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
/// its author wrote): same value, same matcher, opposite safety direction, so the
/// reading is chosen where the POSITION is known and [matchesPattern] stays uniform
/// over its operands. The guard sits outside the scope-type dispatch, transcribing
/// §5.2's loop literally.
bool _excludeIsUnmatchable(String frame, List<String> excl) =>
    excl.any((p) => canonicalize(frame, p) == neverMatch);

bool matchesScope(String localPeer, String value, Scope s, ScopeKind kind) {
  if (_excludeIsUnmatchable(localPeer, s.excl)) return false; // 0.8.2.21 — deny
  if (kind == ScopeKind.id) {
    return _coveredId(s.incl, value) && !_coveredId(s.excl, value);
  }
  final cv = canonicalize(localPeer, value);
  return _covered(localPeer, s.incl, cv) && !_covered(localPeer, s.excl, cv);
}

bool _covered(String frame, List<String> pats, String cv) =>
    pats.any((p) => matchesPattern(cv, canonicalize(frame, p)));

// ── §5.2 check-permission ──────────────────────────────────────────────────────

String firstSegment(String uri) {
  final u = _startsWith('/', uri) ? uri.substring(1) : uri;
  final i = u.indexOf('/');
  return i >= 0 ? u.substring(0, i) : u;
}

const _base58Alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

bool isPeerId(String seg) =>
    seg.length >= 46 && seg.split('').every((c) => _base58Alphabet.contains(c));

String extractPeer(String localPeer, String uri) {
  final first = firstSegment(normalizeUri(uri));
  return isPeerId(first) ? first : localPeer;
}

/// Concrete-target subset (the core surface the oracle exercises). The grant's
/// own resource patterns canonicalize against the GRANTER's peer_id (§PR-8); the
/// caller-supplied targets/exclude stay on the LOCAL frame (§5.4).
bool checkResourceScope(
    String localPeer, String granterPeer, EcfMap resource, Scope s) {
  final targets = textList(resource, 'targets');
  final callerExcl = textList(resource, 'exclude');
  if (targets == null || targets.isEmpty) return false;
  // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
  // target: the coverage test below is correct in isolation and is simply never
  // reached on a sentinel, because matchesPattern answers false.
  if (_excludeIsUnmatchable(granterPeer, s.excl)) return false;
  for (final tgt in targets) {
    final ct = canonicalize(localPeer, tgt);
    if (callerExcl != null && _coveredFrame(localPeer, callerExcl, ct)) {
      continue; // caller excluded → ok
    }
    if (!_coveredFrame(granterPeer, s.incl, ct)) return false;
    if (_coveredFrame(granterPeer, s.excl, ct)) return false;
  }
  return true;
}

bool _coveredFrame(String frame, List<String> pats, String v) =>
    pats.any((p) => matchesPattern(v, canonicalize(frame, p)));

/// §PR-8 — the frame for canonicalizing CAP's grant resource patterns is the
/// GRANTER's peer_id. Single-sig granter → derive peer_id from its public_key;
/// unresolvable → null (caller falls back to local).
String? resolveGranterPeerId(Resolve resolve, Entity cap) {
  final gh = cap.bytes('granter');
  if (gh == null) return null;
  final g = resolve(gh);
  if (g == null) return null;
  final pk = g.bytes('public_key');
  if (pk == null) return null;
  return Identity.peerIdOfPublicKey(pk);
}

/// Gate the wire request at the dispatch authorization boundary (§3.2.3 /
/// v7.73). [granterPeer] is the §PR-8 canonicalization frame for the cap's grant
/// resource patterns; every other dimension stays on the local frame.
Verdict checkPermission(
  String localPeer,
  String granterPeer,
  Entity exec,
  Entity token,
  String handlerPattern,
) {
  final operation = exec.text('operation') ?? '';
  final uri = exec.text('uri') ?? '';
  final targetPeer = extractPeer(localPeer, uri);
  final resource = exec.mapField('resource');
  for (final g in grantsOfToken(token)) {
    var ok = matchesScope(localPeer, operation, g.operations, ScopeKind.id) &&
        matchesScope(localPeer, handlerPattern, g.handlers, ScopeKind.path);
    if (ok) {
      final peers = g.peers ?? Scope([localPeer], const []);
      ok = matchesScope(localPeer, targetPeer, peers, ScopeKind.id);
    }
    if (ok && resource != null) {
      ok = checkResourceScope(localPeer, granterPeer, resource, g.resources);
    }
    if (ok) return Verdict.allow;
  }
  return Verdict.deny;
}

// ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ────────────────────

/// One past the largest uint64 the wire can carry.
final BigInt uint64Ceiling = BigInt.one << 64;

/// True when every CAP-6a temporal field on a RECEIVED token is either absent
/// (legal) or representable as a uint64.
///
/// This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Dart's
/// fail-open is the ARITHMETIC one, not the null-collapse one, and the distinction
/// matters because the grep that catches the other misses this: `muint` is
/// `v is EcfInt ? v.value : null`, so it returns the BigInt of ANY integer,
/// negative included. The expiry check therefore did NOT skip — it RAN and returned
/// the wrong answer. For a negative not_before, `tnow < nb` is simply false and the
/// capability passed. No null, no skip, nothing an Option-shaped audit would find.
///
/// BigInt is arbitrary-precision, so the >2^64 half is likewise a DELIBERATE range
/// check rather than an overflow trap.
///
/// §6.2 CAP-6a: such a token "is malformed. A verifier MUST refuse it and MUST NOT
/// treat the unrepresentable field as absent." An absent expires_at stays legal and
/// is NOT rejected here. Refusal must be the §5.2 capability_denied disposition,
/// never a decode-layer drop or a transport close.
bool temporalFieldsRepresentable(Entity tok) {
  for (final key in const ['expires_at', 'not_before', 'created_at']) {
    final v = tok.uint(key);
    if (v == null) continue; // absent is legal
    if (v.isNegative || v >= uint64Ceiling) return false;
  }
  return true;
}

// ── §5.5 / §5.6 chain verification + attenuation ──────────────────────────────

int nowMs() => DateTime.now().millisecondsSinceEpoch;

/// §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative
/// to [createdAt]. Rule 3: a conversion that is not representable is treated as
/// ABSENT (null) exactly as a null term is — it MUST NOT wrap and MUST NOT saturate
/// to a representable maximum, since saturation manufactures expires_at == 2^64-1,
/// a finite bound no reader can distinguish from a deliberate one. BigInt does not
/// wrap, so this is a deliberate range check.
///
/// ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED
/// value yielding createdAt (expire immediately). The absent field is the only
/// "no bound" spelling, and falling out of the arithmetic is what keeps the two
/// from ever collapsing into each other.
BigInt? addTtl(int createdAt, BigInt ttl) {
  if (ttl.isNegative) return null;
  final sum = BigInt.from(createdAt) + ttl;
  return sum >= uint64Ceiling ? null : sum;
}

Entity? findSignature(Uint8List target, List<Included> included) {
  for (final it in included) {
    final e = it.entity;
    if (e.type == 'system/signature' && octetsEqual(e.bytes('target'), target)) {
      return e;
    }
  }
  return null;
}

// ── §3.6 M3 multi-signature granter ─────────────────────────────────────────
// The capability `granter` field is a union (§3.6): a single system/hash (bytes,
// single-sig) OR a {signers: [system/hash], threshold: uint} map (multi-sig,
// ROOT-ONLY). A multi-sig root is verified by [verifyMultiSigRoot] — §3.6 M3
// structure first, then §5.5 M6 root-at-local + M4 k-of-n quorum.

/// Parse the `granter` union as a multi-sig descriptor, or null if it is a
/// single `system/hash` (bytes) or absent. Detection: granter is a CBOR map.
MultiGranter? multiGranterOf(Entity cap) {
  final m = cap.field('granter');
  if (m is! EcfMap) return null;
  final sv = m['signers'];
  final signers = <Uint8List>[];
  if (sv is EcfArray) {
    for (final it in sv.items) {
      if (it is EcfBytes) signers.add(it.octets);
    }
  }
  final threshold = muint(m, 'threshold') ?? BigInt.zero;
  return MultiGranter(signers, threshold);
}

bool isMultiSig(Entity cap) => cap.field('granter') is EcfMap;

bool _hasDuplicateSigners(List<Uint8List> signers) {
  for (var i = 0; i < signers.length; i++) {
    for (var j = i + 1; j < signers.length; j++) {
      if (octetsEqual(signers[i], signers[j])) return true;
    }
  }
  return false;
}

List<Entity> _signaturesTargeting(Uint8List target, List<Included> included) => [
      for (final it in included)
        if (it.entity.type == 'system/signature' &&
            octetsEqual(it.entity.bytes('target'), target))
          it.entity,
    ];

String? _peerIdOfSigner(Resolve resolve, Uint8List signerHash) {
  final p = resolve(signerHash);
  if (p == null) return null;
  final pk = p.bytes('public_key');
  if (pk == null) return null;
  return Identity.peerIdOfPublicKey(pk);
}

/// Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4·M6). Returns
/// true (ALLOW) only if the quorum is well-formed AND a threshold of DISTINCT
/// signers signed the cap's content hash. Structural validation (M3) precedes
/// signature counting (§3.6 precedence 25): a malformed quorum is denied on its
/// structure, not on missing/invalid sigs. Every failure path returns false →
/// the dispatcher maps it to 403 capability_denied (never a throw, never a hang).
Future<bool> _verifyMultiSigRoot(
  String localPeer,
  Resolve resolve,
  Entity cap,
  MultiGranter mg,
  List<Included> included,
) async {
  final n = mg.signers.length;
  // §3.6 M3 structure — root-only (parent null); a real quorum (n ≥ 2); a usable
  // threshold (2 ≤ threshold ≤ n); distinct signers. BEFORE any signature work
  // (precedence 25).
  if (cap.bytes('parent') != null) return false;
  if (n < 2) return false;
  if (mg.threshold < BigInt.two || mg.threshold > BigInt.from(n)) return false;
  if (_hasDuplicateSigners(mg.signers)) return false;

  // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
  final localInSigners =
      mg.signers.any((s) => _peerIdOfSigner(resolve, s) == localPeer);
  if (!localInSigners) return false;

  // Temporal validity + grantee resolution (as for any root).
  final now = nowMs();
  final nb = cap.uint('not_before');
  if (nb != null && BigInt.from(now) < nb) return false;
  final ex = cap.uint('expires_at');
  if (ex != null && ex < BigInt.from(now)) return false;
  final grantee = cap.bytes('grantee');
  if (grantee == null || resolve(grantee) == null) return false;

  // §5.5 M4 k-of-n: at least `threshold` DISTINCT quorum members produced a
  // valid signature over the cap's content hash. A duplicate signature from one
  // signer does NOT inflate the count (we count distinct signer hashes).
  final sigs = _signaturesTargeting(cap.rawHash, included);
  final validSigners = <Uint8List>[];
  for (final signerHash in mg.signers) {
    if (validSigners.any((v) => octetsEqual(v, signerHash))) continue;
    final signerPeer = resolve(signerHash);
    if (signerPeer == null) continue;
    var hasValid = false;
    for (final sgn in sigs) {
      if (octetsEqual(sgn.bytes('signer'), signerHash) &&
          await Identity.verifySignature(sgn, signerPeer)) {
        hasValid = true;
        break;
      }
    }
    if (hasValid) validSigners.add(signerHash);
  }
  return BigInt.from(validSigners.length) >= mg.threshold;
}

Entity? capResolve(List<Included> included, Store store, Uint8List h) =>
    includedGet(included, h) ?? store.getByHash(h);

Entity? includedGet(List<Included> included, Uint8List h) {
  for (final it in included) {
    if (octetsEqual(it.hash, h)) return it.entity;
  }
  return null;
}

/// §PR-8 / §5.5a per-link canonicalization frame for CAP's resource patterns =
/// its granter's peer_id. Multi-sig root (no granter hash) → localPeer.
/// Single-sig: derive from the resolved granter's public_key; unresolvable →
/// null (caller denies).
String? _linkGranterPeer(Resolve resolve, String localPeer, Entity cap) {
  final gh = cap.bytes('granter');
  if (gh == null) return localPeer;
  final g = resolve(gh);
  if (g == null) return null;
  final pk = g.bytes('public_key');
  if (pk == null) return null;
  return Identity.peerIdOfPublicKey(pk);
}

bool _scopeSubset(
    String childPeer, String parentPeer, Scope child, Scope parent) {
  for (final cp in child.incl) {
    final cc = canonicalize(childPeer, cp);
    if (!parent.incl.any((p) => matchesPattern(cc, canonicalize(parentPeer, p)))) {
      return false;
    }
  }
  for (final pe in parent.excl) {
    final cpe = canonicalize(parentPeer, pe);
    if (!child.excl.any((c) => matchesPattern(cpe, canonicalize(childPeer, c)))) {
      return false;
    }
  }
  return true;
}

bool grantSubset(String localPeer, String childPeer, String parentPeer,
    GrantRec child, GrantRec parent) {
  if (!_scopeSubset(localPeer, localPeer, child.handlers, parent.handlers)) {
    return false;
  }
  if (!_scopeSubset(localPeer, localPeer, child.operations, parent.operations)) {
    return false;
  }
  if (!_scopeSubset(childPeer, parentPeer, child.resources, parent.resources)) {
    return false;
  }
  final cp = child.peers ?? Scope([localPeer], const []);
  final pp = parent.peers ?? Scope([localPeer], const []);
  return _scopeSubset(localPeer, localPeer, cp, pp);
}

bool _isAttenuated(String localPeer, String childPeer, String parentPeer,
    Entity child, Entity parent) {
  final cg = grantsOfToken(child);
  final pg = grantsOfToken(parent);
  for (final c in cg) {
    if (!pg.any((p) => grantSubset(localPeer, childPeer, parentPeer, c, p))) {
      return false;
    }
  }
  final pe = parent.uint('expires_at');
  final ce = child.uint('expires_at');
  if (pe != null && ce == null) return false; // child infinite, parent finite
  if (pe != null) return ce! <= pe;
  return true;
}

bool _checkDelegationCaveats(Entity parent, Entity child, int depth) {
  final caveats = parent.mapField('delegation_caveats');
  if (caveats == null) return true;
  if (ecfIsTrue(caveats['no_delegation'])) return false;
  var depthOk = true;
  final m = muint(caveats, 'max_delegation_depth');
  if (m != null) depthOk = BigInt.from(depth) < m;
  var ttlOk = true;
  final maxTtl = muint(caveats, 'max_delegation_ttl');
  if (maxTtl != null) {
    final ex = child.uint('expires_at');
    final cr = child.uint('created_at');
    if (ex != null && cr != null) {
      ttlOk = (ex - cr) <= maxTtl;
    } else if (ex != null) {
      ttlOk = true; // created_at absent — can't bound, admit
    } else {
      ttlOk = false; // infinite child lifetime exceeds any limit
    }
  }
  return depthOk && ttlOk;
}

final class _Chain {
  const _Chain(this.chain, this.ok);
  final List<Entity>? chain;
  final bool ok;
}

_Chain _collectChain(Entity cap, Resolve resolve) {
  final acc = <Entity>[];
  var current = cap;
  var depth = 0;
  while (true) {
    if (depth > 64) return const _Chain(null, false);
    acc.add(current);
    final ph = current.bytes('parent');
    if (ph == null) return _Chain(acc, true);
    final parent = resolve(ph);
    if (parent == null) return const _Chain(null, false);
    current = parent;
    depth++;
  }
}

/// §4.10(b) structural-bound pre-check: true if the authority chain rooted at
/// [capability] exceeds the max depth (64). Walks parent pointers without
/// verifying signatures — depth is a purely structural property, gated BEFORE the
/// per-link authz walk so an over-deep chain is reported as 400
/// chain_depth_exceeded (structural excess), distinct from a 403
/// capability_denied authz failure (arch ruling, v7.75 §4.10(b)). An unreachable
/// parent is NOT a depth problem — it returns false here and is left for
/// [verifyCapabilityChain] to deny (403).
bool chainExceedsDepth(Store store, Entity capability, List<Included> included) {
  Entity? resolve(Uint8List h) => capResolve(included, store, h);
  var current = capability;
  var depth = 0;
  while (true) {
    if (depth > 64) return true;
    final ph = current.bytes('parent');
    if (ph == null) return false; // root reached within bound
    final parent = resolve(ph);
    if (parent == null) return false; // unreachable — not a depth problem
    current = parent;
    depth++;
  }
}

Future<Verdict> verifyCapabilityChain(
    String localPeer, Store store, Entity capability, List<Included> included) async {
  Entity? resolve(Uint8List h) => capResolve(included, store, h);
  final c = _collectChain(capability, resolve);
  if (!c.ok) return Verdict.deny;
  final chain = c.chain!;
  final root = chain.last;
  // Root authority: a single-sig root must root at the local peer; a §3.6 M3
  // multi-sig root (root-only) must pass k-of-n quorum validation.
  final rootMg = multiGranterOf(root);
  final bool rootOk;
  if (rootMg != null) {
    rootOk = await _verifyMultiSigRoot(localPeer, resolve, root, rootMg, included);
  } else {
    final rgh = root.bytes('granter');
    final g = rgh == null ? null : resolve(rgh);
    final pk = g?.bytes('public_key');
    rootOk = pk != null && Identity.peerIdOfPublicKey(pk) == localPeer;
  }
  if (!rootOk) return Verdict.deny;

  var good = true;
  final n = chain.length;
  var i = 0;
  while (i < n && good) {
    final current = chain[i];
    // A §3.6 M3 multi-sig token is root-only and fully verified above. A
    // multi-sig token anywhere but the chain root is rejected; otherwise skipped.
    if (isMultiSig(current)) {
      if (i != n - 1) good = false;
      i++;
      continue;
    }
    // signature: signer == granter, verify against granter identity
    final gh = current.bytes('granter');
    if (gh != null) {
      final sgn = findSignature(current.rawHash, included);
      final granter = resolve(gh);
      if (sgn != null && granter != null) {
        final signer = sgn.bytes('signer');
        if (!(signer != null &&
            octetsEqual(signer, gh) &&
            await Identity.verifySignature(sgn, granter))) {
          good = false;
        }
      } else {
        good = false;
      }
    } else {
      good = false;
    }
    // grantee resolution → 401 carve-out
    final geh = current.bytes('grantee');
    if (geh != null) {
      if (resolve(geh) == null) throw const UnresolvableGrantee();
    } else {
      throw const UnresolvableGrantee();
    }
    // temporal validity.
    //
    // CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
    // created_at is MALFORMED and must be refused outright. This has to run BEFORE
    // the two range checks below, because those are what the ambiguity defeats —
    // see temporalFieldsRepresentable for the mechanism, which in Dart is the
    // ARITHMETIC form rather than the null-collapse one.
    if (!temporalFieldsRepresentable(current)) good = false;
    final tnow = nowMs();
    final nb = current.uint('not_before');
    if (nb != null && BigInt.from(tnow) < nb) good = false;
    final ex = current.uint('expires_at');
    if (ex != null && ex < BigInt.from(tnow)) good = false;
    // delegation link
    if (i < n - 1) {
      final parent = chain[i + 1];
      final childPeer = _linkGranterPeer(resolve, localPeer, current);
      final parentPeer = _linkGranterPeer(resolve, localPeer, parent);
      if (childPeer == null || parentPeer == null) {
        good = false;
      } else {
        final pg = parent.bytes('grantee');
        final cg = current.bytes('granter');
        if (!(pg != null &&
            cg != null &&
            octetsEqual(pg, cg) &&
            _isAttenuated(localPeer, childPeer, parentPeer, current, parent) &&
            _checkDelegationCaveats(parent, current, i))) {
          good = false;
        }
      }
    }
    i++;
  }
  return good ? Verdict.allow : Verdict.deny;
}

bool isRevoked(
    String localPeer, Store store, Entity capability, List<Included> included) {
  Entity? resolve(Uint8List h) => capResolve(included, store, h);
  final c = _collectChain(capability, resolve);
  final rootHash = c.ok ? c.chain!.last.rawHash : capability.rawHash;
  return _revokeMarker(localPeer, store, capability.rawHash) != null ||
      _revokeMarker(localPeer, store, rootHash) != null;
}

Entity? _revokeMarker(String localPeer, Store store, Uint8List h) =>
    store.getAt('/$localPeer/system/capability/revocations/${hexEncode(h)}');

// ── §5.2 verify-request (3-way verdict) ───────────────────────────────────────

Future<RequestVerdict> verifyRequest(
    String localPeer, Store store, Envelope env) async {
  final exec = env.root;
  final included = env.included;
  final sgn = findSignature(exec.rawHash, included);
  if (sgn == null) return RequestVerdict.authnFail;
  final authorH = exec.bytes('author');
  final signer = sgn.bytes('signer');
  if (!(signer != null && authorH != null && octetsEqual(signer, authorH))) {
    return RequestVerdict.authnFail;
  }
  final author = includedGet(included, authorH);
  if (author == null) return RequestVerdict.authnFail;
  if (!await Identity.verifySignature(sgn, author)) {
    return RequestVerdict.authnFail;
  }
  final ch = exec.bytes('capability');
  final cap = ch == null ? null : includedGet(included, ch);
  if (cap == null) return RequestVerdict.authzDeny;
  // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
  // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk.
  if (chainExceedsDepth(store, cap, included)) return RequestVerdict.chainTooDeep;
  if (await verifyCapabilityChain(localPeer, store, cap, included) == Verdict.deny) {
    return RequestVerdict.authzDeny;
  }
  final grantee = cap.bytes('grantee');
  if (!(grantee != null && octetsEqual(grantee, authorH))) {
    return RequestVerdict.authzDeny;
  }
  if (isRevoked(localPeer, store, cap, included)) return RequestVerdict.authzDeny;
  return RequestVerdict.allow;
}
