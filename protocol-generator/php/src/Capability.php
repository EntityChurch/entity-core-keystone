<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Capability system (L3): the §5 verification core — pattern matching (§5.4),
 * request verification (§5.2 {@see verifyRequest} / {@see checkPermission}),
 * delegation-chain verification (§5.5), attenuation (§5.6), caveats (§5.7),
 * revocation (§5.1), and genuine §3.6 M3 multi-signature K-of-N
 * ({@see verifyMultiSigRoot}).
 *
 * Derived from the §5 pseudocode. The verdict is a PHP {@see Verdict} enum
 * (ALLOW/DENY — §5.10 Layer-1 determinism); DENY → 403, the §5.5
 * unresolvable-grantee carve-out → 401 ({@see UnresolvableGranteeException}). The
 * three-way request verdict ({@see RequestVerdict}) folds in §4.10(b)
 * CHAIN_TOO_DEEP (→ 400).
 *
 * §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension's patterns
 * canonicalize against the GRANTER's peer_id; handlers/operations/peers stay on
 * the local frame. For the self-issued dominant path (granter = local) this is
 * byte-identical to the pre-fix behavior; only the foreign-granter cross-peer
 * case flips (exercised at S4 against the oracle).
 *
 * Head-form note (A-PHP-003): thresholds, temporal bounds, and depth come off the
 * wire as `int` OR `\GMP`. {@see Ecf::uint} normalizes to {@see \GMP}; all
 * comparisons go through gmp_cmp — NEVER a blind (int) cast.
 */
final class Capability
{
    public const MAX_CHAIN_DEPTH = 64;

    public static function nowMs(): \GMP
    {
        return \gmp_init((int) (\microtime(true) * 1000));
    }

    // ── grant / scope parse ────────────────────────────────────────────────────

    /**
     * @return array{incl:list<string>,excl:list<string>}
     */
    public static function parseScope(?EcfMap $m): array
    {
        if ($m === null) {
            return ['incl' => [], 'excl' => []];
        }
        return [
            'incl' => Ecf::textList($m, 'include') ?? [],
            'excl' => Ecf::textList($m, 'exclude') ?? [],
        ];
    }

    /**
     * @return array{handlers:array,resources:array,operations:array,peers:?array}
     */
    public static function parseGrant(?EcfMap $m): array
    {
        $peers = ($m?->get('peers') !== null) ? self::parseScope(Ecf::asMap($m->get('peers'))) : null;
        return [
            'handlers' => self::parseScope(Ecf::asMap($m?->get('handlers'))),
            'resources' => self::parseScope(Ecf::asMap($m?->get('resources'))),
            'operations' => self::parseScope(Ecf::asMap($m?->get('operations'))),
            'peers' => $peers,
        ];
    }

    /** @return list<array{handlers:array,resources:array,operations:array,peers:?array}> */
    public static function grantsOfToken(Entity $token): array
    {
        $list = Ecf::mapList($token->data(), 'grants') ?? [];
        return \array_map(static fn (EcfMap $g) => self::parseGrant($g), $list);
    }

    // ── §5.4 pattern matching ─────────────────────────────────────────────────────

    public static function normalizeUri(string $uri): string
    {
        return \str_starts_with($uri, 'entity://') ? '/' . \substr($uri, 9) : $uri;
    }

    /**
     * The unmatchable value (0.8.2.20). Unreachable as a canonical path by
     * CONSTRUCTION: its first segment cannot be a peer_id, since isPeerId requires
     * >= 46 Base58 characters and `-` is outside the Base58 alphabet.
     */
    public const NEVER_MATCH = '/never-match';

    /**
     * Resolve peer-relative paths to absolute /{local}/... form.
     *
     * TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". This
     * used to THROW, and the throw was reachable from the wire — every normative call
     * site is a matcher with no error channel to consume one, so the exception escaped
     * the matcher, the resilience frame caught it, and `../x` in a resource exclude
     * answered 500 (measured 2026-09-14). The diagnostic belongs at admission (§6.5),
     * which has a caller to answer.
     */
    public static function canonicalize(string $localPeer, string $path): string
    {
        if (\str_starts_with($path, './') || \str_starts_with($path, '../')) {
            return self::NEVER_MATCH;
        }
        if (\str_starts_with($path, '*/')) {
            return self::NEVER_MATCH;
        }
        if (\str_starts_with($path, '/')) {
            return $path;
        }
        return "/{$localPeer}/{$path}";
    }

    public static function matchesPattern(string $path, string $pattern): bool
    {
        // NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
        // rule rather than a property of the string: the arm below returns true for a
        // bare '*', so safety must not rest on a value merely looking unmatchable.
        if ($path === self::NEVER_MATCH || $pattern === self::NEVER_MATCH) {
            return false;
        }
        if ($pattern === '*') {
            return true;
        }
        if (\str_starts_with($pattern, '/*/')) {
            $remainder = \substr($pattern, 3);
            if ($path === '') {
                return false;
            }
            $i = \strpos($path, '/', 1);
            return $i !== false && self::matchesPattern(\substr($path, $i + 1), $remainder);
        }
        if (\strlen($pattern) >= 2 && \str_ends_with($pattern, '/*')) {
            return \str_starts_with($path, \substr($pattern, 0, -1));
        }
        return $path === $pattern;
    }

    /**
     * §5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal comparison
     * with exactly two wildcard forms: bare `*` and a trailing slash-star segment-prefix.
     * None of the §5.4 path transforms apply, so a pattern carrying path syntax is
     * matched as a literal string: a non-match, never a fault.
     */
    public static function matchesIdPattern(string $value, string $pattern): bool
    {
        if ($pattern === '*') {
            return true;
        }
        if (\strlen($pattern) >= 2 && \str_ends_with($pattern, '/*')) {
            return \str_starts_with($value, \substr($pattern, 0, -1));
        }
        return $value === $pattern;
    }

    /** @param list<string> $pats */
    private static function coveredId(array $pats, string $value): bool
    {
        foreach ($pats as $p) {
            if (self::matchesIdPattern($value, $p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * §5.2 typed scope match. `$kind` is 'id' (operations, peers) or 'path' (handlers,
     * resources) and has no default — every call site names its dimension, so a new one
     * cannot silently inherit the wrong matcher, which is exactly the F40 defect.
     *
     * @param array{incl:list<string>,excl:list<string>} $s
     * @param 'id'|'path' $kind
     */
    /**
     * AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
     * fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
     * fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
     * its author wrote): same value, same matcher, opposite safety direction, so the
     * reading is chosen where the POSITION is known and matchesPattern stays uniform
     * over its operands.
     *
     * ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). NEVER_MATCH is a §5.4
     * PATH-canonicalization sentinel; an id-scope pattern is a literal identifier that
     * §5.2's own id-scope arm forbids putting through the §5.4 transforms. This guard
     * used to sit OUTSIDE the type dispatch, transcribing §5.2's loop as it read before
     * that loop grew one — which ran an id pattern through those transforms purely to
     * classify it and then DENIED THE WHOLE DIMENSION on a property unrelated to whether
     * the exclude carves anything out. An `operations` exclude of a star-slash-`apply`
     * form — an ordinary namespaced operation name, and a literal that matches nothing
     * under the id-scope grammar — canonicalized to the sentinel and denied every
     * operation. Over-denial, and invisible on any well-formed grant.
     *
     * (The witness is spelled out in words because this is a PHP docblock and the
     * canonical witness for this very rule ENDS A BLOCK COMMENT. Third format after Pd's
     * separators and Smalltalk's apostrophe: a comment delimiter is code, and the rule's
     * own example is what breaks its own explanation. The tests carry it as a string
     * literal, where it is safe and exact.)
     *
     * §5.4 says outright that the rule "does NOT reach `operations` or `peers` [MUST]",
     * and it does NOT leave the id-scope dimensions unprotected by oversight: under the
     * id-scope grammar every non-`*` pattern is a literal and a literal is never
     * structurally unmatchable, so there is nothing here for this sentinel to detect. A
     * scope boundary, not an omission.
     *
     * @param list<string> $excl
     */
    private static function excludeIsUnmatchable(string $frame, array $excl): bool
    {
        foreach ($excl as $p) {
            if (self::canonicalize($frame, $p) === self::NEVER_MATCH) {
                return true;
            }
        }
        return false;
    }

    public static function matchesScope(string $localPeer, string $value, array $s, string $kind): bool
    {
        // SCOPED TO PATH-SCOPE (0.8.2.24). §5.2's exclude loop tests the sentinel INSIDE
        // `if dimension_type == "system/capability/path-scope"`, and §5.4 scopes its own
        // invalid-capability rule the same way. `$kind` already names the dimension here,
        // so the scoping costs one term and cannot be got wrong by a new call site.
        if ($kind === 'path' && self::excludeIsUnmatchable($localPeer, $s['excl'])) {
            return false; // 0.8.2.21 — deny
        }
        if ($kind === 'id') {
            return self::coveredId($s['incl'], $value) && !self::coveredId($s['excl'], $value);
        }
        $cv = self::canonicalize($localPeer, $value);
        return self::covered($localPeer, $s['incl'], $cv) && !self::covered($localPeer, $s['excl'], $cv);
    }

    /** @param list<string> $pats */
    private static function covered(string $frame, array $pats, string $cv): bool
    {
        foreach ($pats as $p) {
            if (self::matchesPattern($cv, self::canonicalize($frame, $p))) {
                return true;
            }
        }
        return false;
    }

    // ── §5.2 check-permission ──────────────────────────────────────────────────────

    public static function firstSegment(string $uri): string
    {
        $u = \str_starts_with($uri, '/') ? \substr($uri, 1) : $uri;
        $i = \strpos($u, '/');
        return $i !== false ? \substr($u, 0, $i) : $u;
    }

    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    public static function isPeerId(string $seg): bool
    {
        if (\strlen($seg) < 46) {
            return false;
        }
        $len = \strlen($seg);
        for ($i = 0; $i < $len; $i++) {
            if (\strpos(self::BASE58_ALPHABET, $seg[$i]) === false) {
                return false;
            }
        }
        return true;
    }

    public static function extractPeer(string $localPeer, string $uri): string
    {
        $first = self::firstSegment(self::normalizeUri($uri));
        return self::isPeerId($first) ? $first : $localPeer;
    }

    /**
     * Concrete-target subset (the core surface the oracle exercises). The grant's
     * own resource patterns canonicalize against the GRANTER's peer_id (§PR-8 /
     * V2(a)); the caller-supplied targets/exclude stay on the LOCAL frame (§5.4).
     *
     * @param array{incl:list<string>,excl:list<string>} $s
     */
    public static function checkResourceScope(string $localPeer, string $granterPeer, EcfMap $resource, array $s): bool
    {
        $targets = Ecf::textList($resource, 'targets');
        $callerExcl = Ecf::textList($resource, 'exclude');
        if ($targets === null || $targets === []) {
            return false;
        }
        // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before
        // any target: the coverage test below is correct in isolation and is simply
        // never reached on a sentinel, because matchesPattern answers false.
        //
        // UNGUARDED ON PURPOSE, unlike matchesScope's (0.8.2.24): $s here is ALWAYS the
        // RESOURCES dimension, which §5.2 fixes as path-scope, so the type test that call
        // site performs would be a constant here. The single-dimension signature is what
        // makes that checkable — a granter frame reaching an id-scope call site is the
        // defect, and this method cannot be one.
        if (self::excludeIsUnmatchable($granterPeer, $s['excl'])) {
            return false;
        }
        foreach ($targets as $tgt) {
            $ct = self::canonicalize($localPeer, $tgt);
            if ($callerExcl !== null && self::coveredFrame($localPeer, $callerExcl, $ct)) {
                continue; // caller excluded → ok
            }
            if (!self::coveredFrame($granterPeer, $s['incl'], $ct)) {
                return false;
            }
            if (self::coveredFrame($granterPeer, $s['excl'], $ct)) {
                return false;
            }
        }
        return true;
    }

    /** @param list<string> $pats */
    private static function coveredFrame(string $frame, array $pats, string $v): bool
    {
        foreach ($pats as $p) {
            if (self::matchesPattern($v, self::canonicalize($frame, $p))) {
                return true;
            }
        }
        return false;
    }

    /**
     * §PR-8 — the frame for canonicalizing a cap's grant resource patterns is the
     * GRANTER's peer_id. Single-sig granter → derive from public_key; unresolvable
     * → null (caller falls back to local).
     *
     * @param callable(string):?Entity $resolve
     */
    public static function resolveGranterPeerId(callable $resolve, Entity $cap): ?string
    {
        $gh = $cap->bytes('granter');
        if ($gh === null) {
            return null;
        }
        $g = $resolve($gh);
        $pk = $g?->bytes('public_key');
        return $pk === null ? null : Identity::peerIdOfPublicKey($pk);
    }

    /**
     * Gate the wire request at the dispatch authorization boundary. $granterPeer
     * is the §PR-8 canonicalization frame for the cap's grant resource patterns;
     * every other dimension stays on the local frame.
     */
    public static function checkPermission(
        string $localPeer,
        string $granterPeer,
        Entity $exec,
        Entity $token,
        string $handlerPattern,
    ): Verdict {
        $operation = $exec->text('operation') ?? '';
        $uri = $exec->text('uri') ?? '';
        $targetPeer = self::extractPeer($localPeer, $uri);
        $resource = $exec->mapField('resource');
        foreach (self::grantsOfToken($token) as $g) {
            $ok = self::matchesScope($localPeer, $operation, $g['operations'], 'id')
                && self::matchesScope($localPeer, $handlerPattern, $g['handlers'], 'path');
            if ($ok) {
                $peers = $g['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
                $ok = self::matchesScope($localPeer, $targetPeer, $peers, 'id');
            }
            if ($ok && $resource !== null) {
                $ok = self::checkResourceScope($localPeer, $granterPeer, $resource, $g['resources']);
            }
            if ($ok) {
                return Verdict::Allow;
            }
        }
        return Verdict::Deny;
    }

    // ── §3.3 effective targets + §6.3 check_path_permission ──────────────────────────

    /**
     * §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude`
     * removes entries from `resource.targets` BEFORE anything else looks at the request.
     *
     * The survivors come back in the caller's OWN SPELLING, not canonicalized — 0.8.2.21
     * is explicit that `effective_targets` yields raw survivors, and the distinction is
     * load-bearing because the value flows on to the tree lookup, which canonicalizes for
     * itself.
     *
     * Returns `null` when the EXECUTE carries no `resource` at all, which is a DIFFERENT
     * input from "a resource whose every target was excluded" — and for a
     * resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with
     * different answers, not merely different inputs to one disposition.
     *
     * `null`-vs-`[]` IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
     * "where an implementation projects `resource.targets` onto the effective set ahead
     * of the handler, that projection MUST NOT be lossy about its own emptiness — narrow
     * when narrowing leaves something, and retain the raw pair when narrowing would empty
     * it." A function returning only a list cannot satisfy that: collapsing
     * `[qA] exclude [qA]` to `[]` would delete the two-empties discriminator before any
     * handler could read it, and the handler's refusal arm becomes dead code that only a
     * WIRE drive can detect. PHP carries the discriminator as the `null` rather than as a
     * second return value — the same property, spelled the way this substrate spells
     * "absent".
     *
     * "Every seam that narrows is exempted alike, inbound-wire and in-process
     * sub-dispatch, or one request receives two different answers according to which door
     * it arrived through." This peer has exactly ONE narrowing seam — this method, called
     * by the tree handler — and §6.5's dispatch chain does not project: Peer::dispatch
     * passes `$exec` through untouched and {@see checkPermission} reads `resource` for
     * itself. So there is no second door to keep in step, and adding a projection at
     * dispatch would create one.
     *
     * A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
     * Reporting it absent would serve the WIDER absent-case answer to a request that
     * named a resource, which is N11's own defect one field over.
     *
     * The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
     * separately from the grant arm) and that is INHERITED here rather than restated:
     * {@see canonicalize} answers the sentinel, {@see matchesPattern} then answers false,
     * and the target simply survives.
     *
     * @return list<string>|null
     */
    public static function effectiveTargets(string $localPeer, Entity $exec): ?array
    {
        $r = $exec->mapField('resource');
        if ($r === null || !$r->hasTextKey('targets')) {
            return null;
        }
        $targets = Ecf::textList($r, 'targets') ?? [];
        $callerExcl = Ecf::textList($r, 'exclude') ?? [];
        $out = [];
        foreach ($targets as $t) {
            $ct = self::canonicalize($localPeer, $t);
            $dropped = false;
            foreach ($callerExcl as $x) {
                if (self::matchesPattern($ct, self::canonicalize($localPeer, $x))) {
                    $dropped = true;
                    break;
                }
            }
            if (!$dropped) {
                $out[] = $t;
            }
        }
        return $out;
    }

    /**
     * §6.3's handler-level path check: may the caller access `$path` AS A TREE PATH,
     * under `$handlerPattern`, with `$token`?
     *
     * IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
     * subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
     * by caller-controlled input: a caller who excludes the one target its capability
     * does not cover removes that target from {@see checkPermission}'s view entirely, and
     * a handler that then acts on it has authorized nothing.
     *
     * THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
     * construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
     * step 3, before any handler runs), and §6.3's signature names only handlers,
     * operations and resources.
     *
     * THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
     * rather than a choice: §6.3's block reads
     * `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` —
     * there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the
     * subject is a pattern compared against a parent's pattern; this call site compares a
     * CONCRETE local path the handler is about to touch.
     *
     * Scope types: `handlers` -> path-scope, `operations` -> id-scope, `resources` ->
     * path-scope. An empty `resources.include` is a legal grant shape (§5.2: handlers
     * that touch no tree paths) and DENIES every path here, which is what that note says
     * it should. A malformed path canonicalizes to NEVER_MATCH, which matches no grant,
     * so it falls through to DENY rather than being matched against anything.
     */
    public static function checkPathPermission(
        string $localPeer,
        string $operation,
        string $path,
        Entity $token,
        string $handlerPattern,
    ): bool {
        foreach (self::grantsOfToken($token) as $g) {
            if (self::matchesScope($localPeer, $handlerPattern, $g['handlers'], 'path')
                && self::matchesScope($localPeer, $operation, $g['operations'], 'id')
                && self::matchesScope($localPeer, $path, $g['resources'], 'path')) {
                return true;
            }
        }
        return false;
    }

    // ── §5.5 chain verification + attenuation ────────────────────────────────────────

    /** @param list<array{hash:string,entity:Entity}> $included */
    public static function findSignature(string $target, array $included): ?Entity
    {
        foreach ($included as $pair) {
            $e = $pair['entity'];
            if ($e->type === 'system/signature' && Ecf::octetsEqual($e->bytes('target'), $target)) {
                return $e;
            }
        }
        return null;
    }

    /**
     * @param list<array{hash:string,entity:Entity}> $included
     * @return list<Entity>
     */
    private static function signaturesTargeting(string $target, array $included): array
    {
        $out = [];
        foreach ($included as $pair) {
            $e = $pair['entity'];
            if ($e->type === 'system/signature' && Ecf::octetsEqual($e->bytes('target'), $target)) {
                $out[] = $e;
            }
        }
        return $out;
    }

    /** @param callable(string):?Entity $resolve */
    /**
     * §6.2 CAP-6a: true when every temporal field on a RECEIVED token is either
     * absent (legal) or representable as a uint64.
     *
     * This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
     * PHP's fail-open is the ARITHMETIC one, not the null-collapse one, and the
     * distinction matters because the grep that catches the other misses this:
     * Ecf::uint returns gmp_init() of ANY int and any \GMP verbatim, negative
     * included. The expiry check therefore did NOT skip -- it RAN and returned the
     * wrong answer. For a negative not_before, gmp_cmp($now, $nb) < 0 is simply
     * false and the capability passed. No null, no skip, nothing an Option-shaped
     * audit would find.
     *
     * GMP is arbitrary-precision, so the >2^64 half is likewise a DELIBERATE range
     * check rather than an overflow trap.
     *
     * §6.2 CAP-6a: such a token "is malformed. A verifier MUST refuse it and MUST
     * NOT treat the unrepresentable field as absent." An absent expires_at stays
     * legal and is NOT rejected here. Refusal must be the §5.2 capability_denied
     * disposition, never a decode-layer drop or a transport close.
     */
    public static function temporalFieldsRepresentable(Entity $tok): bool
    {
        $ceiling = \gmp_pow(2, 64);
        foreach (['expires_at', 'not_before', 'created_at'] as $key) {
            $v = $tok->field($key);
            if ($v === null) {
                continue; // absent is legal
            }
            $n = $tok->uint($key);
            if ($n === null || \gmp_cmp($n, 0) < 0 || \gmp_cmp($n, $ceiling) >= 0) {
                return false; // present but not a uint64 => malformed
            }
        }
        return true;
    }

    /**
     * §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp
     * relative to $createdAt. Rule 3: a conversion that is not representable is
     * treated as ABSENT (null) exactly as a null term is -- it MUST NOT wrap and
     * MUST NOT saturate to a representable maximum, since saturation manufactures
     * expires_at == 2^64-1, a finite bound no reader can distinguish from a
     * deliberate one. GMP does not wrap, so this is a deliberate range check.
     *
     * ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED
     * value yielding $createdAt (expire immediately). The absent field is the only
     * "no bound" spelling, and falling out of the arithmetic is what keeps the two
     * from ever collapsing into each other.
     */
    public static function addTtl(\GMP $createdAt, \GMP $ttl): ?\GMP
    {
        if (\gmp_cmp($ttl, 0) < 0) {
            return null;
        }
        $sum = \gmp_add($createdAt, $ttl);
        return \gmp_cmp($sum, \gmp_pow(2, 64)) >= 0 ? null : $sum;
    }

    public static function capResolve(array $included, Store $store, string $h): ?Entity
    {
        foreach ($included as $pair) {
            if (\hash_equals($pair['hash'], $h)) {
                return $pair['entity'];
            }
        }
        return $store->getByHash($h);
    }

    // ── §3.6 M3 multi-signature granter ─────────────────────────────────────────
    // The capability `granter` field is a union (§3.6): a single system/hash
    // (ByteString, single-sig) OR a {signers:[system/hash], threshold:uint} map
    // (multi-sig, ROOT-ONLY). A multi-sig root is verified by verifyMultiSigRoot —
    // §3.6 M3 structure first, then §5.5 M6 root-at-local + M4 k-of-n quorum.

    public static function isMultiSig(Entity $cap): bool
    {
        return $cap->field('granter') instanceof EcfMap;
    }

    /**
     * Parse the `granter` union as a multi-sig descriptor, or null if it is a
     * single system/hash (ByteString) or absent.
     *
     * @return array{signers:list<string>,threshold:\GMP}|null
     */
    public static function multiGranterOf(Entity $cap): ?array
    {
        $m = $cap->field('granter');
        if (!($m instanceof EcfMap)) {
            return null;
        }
        $signers = [];
        $arr = $m->get('signers');
        if (\is_array($arr)) {
            foreach ($arr as $s) {
                if ($s instanceof ByteString) {
                    $signers[] = $s->bytes;
                }
            }
        }
        $threshold = Ecf::uint($m, 'threshold') ?? \gmp_init(0);
        return ['signers' => $signers, 'threshold' => $threshold];
    }

    /** @param list<string> $signers */
    private static function hasDuplicateSigners(array $signers): bool
    {
        $n = \count($signers);
        for ($i = 0; $i < $n; $i++) {
            for ($j = $i + 1; $j < $n; $j++) {
                if (\hash_equals($signers[$i], $signers[$j])) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @param callable(string):?Entity $resolve */
    private static function peerIdOfSigner(callable $resolve, string $signerHash): ?string
    {
        $p = $resolve($signerHash);
        $pk = $p?->bytes('public_key');
        return $pk === null ? null : Identity::peerIdOfPublicKey($pk);
    }

    /**
     * Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4·M6).
     * Returns true (ALLOW) only if the quorum is well-formed AND a threshold of
     * DISTINCT signers signed the cap's content hash. Structural validation (M3)
     * precedes signature counting (§3.6 precedence 25): a malformed quorum is
     * denied on its structure, not on missing/invalid sigs. Every failure path
     * returns false → the dispatcher maps it to 403 (never a throw, never a hang).
     *
     * @param callable(string):?Entity $resolve
     * @param array{signers:list<string>,threshold:\GMP} $mg
     * @param list<array{hash:string,entity:Entity}> $included
     */
    private static function verifyMultiSigRoot(
        string $localPeer,
        callable $resolve,
        Entity $cap,
        array $mg,
        array $included,
    ): bool {
        $n = \count($mg['signers']);
        // §3.6 M3 structure — root-only (parent null); a real quorum (n ≥ 2); a
        // usable threshold (2 ≤ threshold ≤ n); distinct signers. BEFORE any
        // signature work (precedence 25).
        if ($cap->bytes('parent') !== null) {
            return false;
        }
        if ($n < 2) {
            return false;
        }
        if (\gmp_cmp($mg['threshold'], 2) < 0 || \gmp_cmp($mg['threshold'], $n) > 0) {
            return false;
        }
        if (self::hasDuplicateSigners($mg['signers'])) {
            return false;
        }

        // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
        $localInSigners = false;
        foreach ($mg['signers'] as $s) {
            if (self::peerIdOfSigner($resolve, $s) === $localPeer) {
                $localInSigners = true;
                break;
            }
        }
        if (!$localInSigners) {
            return false;
        }

        // Temporal validity + grantee resolution (as for any root).
        $now = self::nowMs();
        $nb = $cap->uint('not_before');
        if ($nb !== null && \gmp_cmp($now, $nb) < 0) {
            return false;
        }
        $ex = $cap->uint('expires_at');
        if ($ex !== null && \gmp_cmp($ex, $now) < 0) {
            return false;
        }
        $grantee = $cap->bytes('grantee');
        if ($grantee === null || $resolve($grantee) === null) {
            return false;
        }

        // §5.5 M4 k-of-n: at least `threshold` DISTINCT quorum members produced a
        // valid signature over the cap's content hash. A duplicate signature from
        // one signer does NOT inflate the count (count distinct signer hashes).
        $sigs = self::signaturesTargeting($cap->hash(), $included);
        $validSigners = [];
        foreach ($mg['signers'] as $signerHash) {
            $already = false;
            foreach ($validSigners as $vs) {
                if (\hash_equals($vs, $signerHash)) {
                    $already = true;
                    break;
                }
            }
            if ($already) {
                continue;
            }
            $signerPeer = $resolve($signerHash);
            if ($signerPeer === null) {
                continue;
            }
            foreach ($sigs as $sgn) {
                if (Ecf::octetsEqual($sgn->bytes('signer'), $signerHash)
                    && Identity::verifySignature($sgn, $signerPeer)) {
                    $validSigners[] = $signerHash;
                    break;
                }
            }
        }
        return \gmp_cmp(\gmp_init(\count($validSigners)), $mg['threshold']) >= 0;
    }

    /**
     * §PR-8 / §5.5a per-link canonicalization frame for a cap's resource patterns
     * = its granter's peer_id. Multi-sig root (no granter hash) → localPeer.
     * Single-sig: derive from the resolved granter's public_key; unresolvable →
     * null (caller denies).
     *
     * @param callable(string):?Entity $resolve
     */
    private static function linkGranterPeer(callable $resolve, string $localPeer, Entity $cap): ?string
    {
        $gh = $cap->bytes('granter');
        if ($gh === null) {
            return $localPeer;
        }
        $g = $resolve($gh);
        $pk = $g?->bytes('public_key');
        return $pk === null ? null : Identity::peerIdOfPublicKey($pk);
    }

    /**
     * §5.5a/§5.6 subset check: every child include must be covered by some parent
     * include, and every parent exclude must be inherited by some child exclude.
     *
     * TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
     * §3.6's id-scope grammar binds the scope TYPE, not one function — "An
     * implementation on the canonicalizing reading is non-conformant and MUST adopt the
     * literal matcher" — so the rule F40 landed on {@see matchesScope} reaches here too,
     * with delegation-chain WIDENING named as the reason: on the canonicalizing reading a
     * bare id include reads as covered by a path-form parent pattern it does not
     * literally match, and a child grant comes out wider than its parent. `lean`'s
     * differential put it at 2 of 64 include pairs and 2 of 64 exclude pairs,
     * fail-closed, with a 16-pair control alphabet reporting 0 — which is why every
     * hand-tried example missed it.
     *
     * `$kind` has NO DEFAULT and is named at every call site, because a default is how
     * the next dimension inherits the wrong matcher silently — the original F40 defect.
     * The per-link granter frames are meaningless on the id arm (an id pattern is never
     * canonicalized) and are simply unread there.
     *
     * @param array{incl:list<string>,excl:list<string>} $child
     * @param array{incl:list<string>,excl:list<string>} $parent
     * @param 'id'|'path' $kind
     */
    private static function scopeSubset(string $childPeer, string $parentPeer, array $child, array $parent, string $kind): bool
    {
        $frame = static fn (string $pattern, string $peer): string
            => $kind === 'path' ? self::canonicalize($peer, $pattern) : $pattern;
        $covers = static fn (string $pattern, string $value): bool
            => $kind === 'path' ? self::matchesPattern($value, $pattern) : self::matchesIdPattern($value, $pattern);

        foreach ($child['incl'] as $cp) {
            $cc = $frame($cp, $childPeer);
            $covered = false;
            foreach ($parent['incl'] as $pp) {
                if ($covers($frame($pp, $parentPeer), $cc)) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }
        foreach ($parent['excl'] as $pe) {
            $cpe = $frame($pe, $parentPeer);
            $covered = false;
            foreach ($child['excl'] as $ce) {
                if ($covers($frame($ce, $childPeer), $cpe)) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array{handlers:array,resources:array,operations:array,peers:?array} $child
     * @param array{handlers:array,resources:array,operations:array,peers:?array} $parent
     */
    public static function grantSubset(string $localPeer, string $childPeer, string $parentPeer, array $child, array $parent): bool
    {
        // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
        // dimensions stay on the local frame. The scope KIND is a property of the
        // DIMENSION and is named at every call site, never defaulted (F50 / 0.8.2.16).
        if (!self::scopeSubset($localPeer, $localPeer, $child['handlers'], $parent['handlers'], 'path')) {
            return false;
        }
        if (!self::scopeSubset($localPeer, $localPeer, $child['operations'], $parent['operations'], 'id')) {
            return false;
        }
        if (!self::scopeSubset($childPeer, $parentPeer, $child['resources'], $parent['resources'], 'path')) {
            return false;
        }
        $cp = $child['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
        $pp = $parent['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
        return self::scopeSubset($localPeer, $localPeer, $cp, $pp, 'id');
    }

    private static function isAttenuated(string $localPeer, string $childPeer, string $parentPeer, Entity $child, Entity $parent): bool
    {
        $cg = self::grantsOfToken($child);
        $pg = self::grantsOfToken($parent);
        foreach ($cg as $c) {
            $ok = false;
            foreach ($pg as $p) {
                if (self::grantSubset($localPeer, $childPeer, $parentPeer, $c, $p)) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return false;
            }
        }
        $pe = $parent->uint('expires_at');
        $ce = $child->uint('expires_at');
        if ($pe !== null && $ce === null) {
            return false; // child infinite, parent finite
        }
        if ($pe !== null) {
            return \gmp_cmp($ce, $pe) <= 0;
        }
        return true;
    }

    private static function checkDelegationCaveats(Entity $parent, Entity $child, int $depth): bool
    {
        $caveats = $parent->mapField('delegation_caveats');
        if ($caveats === null) {
            return true;
        }
        if (Ecf::isTrue($caveats->get('no_delegation'))) {
            return false;
        }
        $depthOk = true;
        $m = Ecf::uint($caveats, 'max_delegation_depth');
        if ($m !== null) {
            $depthOk = \gmp_cmp(\gmp_init($depth), $m) < 0;
        }
        $ttlOk = true;
        $maxTtl = Ecf::uint($caveats, 'max_delegation_ttl');
        if ($maxTtl !== null) {
            $ex = $child->uint('expires_at');
            $cr = $child->uint('created_at');
            if ($ex !== null && $cr !== null) {
                $ttlOk = \gmp_cmp(\gmp_sub($ex, $cr), $maxTtl) <= 0;
            } elseif ($ex !== null) {
                $ttlOk = true; // created_at absent — can't bound, admit
            } else {
                $ttlOk = false; // infinite child lifetime exceeds any limit
            }
        }
        return $depthOk && $ttlOk;
    }

    /**
     * Collect the parent chain rooted at $cap.
     *
     * @param callable(string):?Entity $resolve
     * @return array{chain:?list<Entity>,ok:bool}
     */
    private static function collectChain(Entity $cap, callable $resolve): array
    {
        $acc = [];
        $current = $cap;
        $depth = 0;
        while (true) {
            if ($depth > self::MAX_CHAIN_DEPTH) {
                return ['chain' => null, 'ok' => false];
            }
            $acc[] = $current;
            $ph = $current->bytes('parent');
            if ($ph === null) {
                return ['chain' => $acc, 'ok' => true];
            }
            $parent = $resolve($ph);
            if ($parent === null) {
                return ['chain' => null, 'ok' => false];
            }
            $current = $parent;
            $depth++;
        }
    }

    /**
     * §4.10(b) structural-bound pre-check: true if the authority chain rooted at
     * $capability exceeds the max depth (64). Walks parent pointers WITHOUT
     * verifying signatures — depth is a purely structural property, gated BEFORE
     * the per-link authz walk so an over-deep chain is reported as 400
     * chain_depth_exceeded (structural excess), distinct from a 403 authz failure
     * (arch ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem
     * — it returns false here and is left for the authz walk to deny (403).
     *
     * @param list<array{hash:string,entity:Entity}> $included
     */
    public static function chainExceedsDepth(Store $store, Entity $capability, array $included): bool
    {
        $resolve = static fn (string $h): ?Entity => self::capResolve($included, $store, $h);
        $current = $capability;
        $depth = 0;
        while (true) {
            if ($depth > self::MAX_CHAIN_DEPTH) {
                return true;
            }
            $ph = $current->bytes('parent');
            if ($ph === null) {
                return false; // root reached within bound
            }
            $parent = $resolve($ph);
            if ($parent === null) {
                return false; // unreachable — not a depth problem
            }
            $current = $parent;
            $depth++;
        }
    }

    /**
     * @param list<array{hash:string,entity:Entity}> $included
     */
    public static function verifyCapabilityChain(string $localPeer, Store $store, Entity $capability, array $included): Verdict
    {
        return self::verifyCapabilityChainRootedAt($localPeer, $localPeer, $store, $capability, $included);
    }

    /**
     * {@see verifyCapabilityChain} with the expected ROOT granter named separately from
     * the verifying peer.
     *
     * §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
     * minted by the TARGET peer, so root-trust is relaxed away from the local peer — and
     * every other clause (per-link signatures, grantee resolution, temporal validity,
     * attenuation, caveats) is unchanged. Parameterized rather than forked because a
     * second copy of a chain walk is a second copy that drifts.
     *
     * A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
     * `$rootPeer` differs from `$localPeer` the quorum arm is REFUSED outright rather
     * than verified: *minted by the target* means the target SOLELY minted it, and a
     * K-of-N root is a GROUP's authority — its co-signers authorized it too. Accepting it
     * would let any one signer's target confer the whole group's grant, which is
     * E3/F66's over-acceptance. §5.5's M6 also requires the LOCAL peer in the signer set,
     * so the quorum arm has no meaning in a foreign frame even on its own terms.
     */
    public static function verifyCapabilityChainRootedAt(string $localPeer, string $rootPeer, Store $store, Entity $capability, array $included): Verdict
    {
        $resolve = static fn (string $h): ?Entity => self::capResolve($included, $store, $h);
        $c = self::collectChain($capability, $resolve);
        if (!$c['ok']) {
            return Verdict::Deny;
        }
        $chain = $c['chain'];
        $root = $chain[\count($chain) - 1];
        // Root authority: a single-sig root must root at $rootPeer; a §3.6 M3 multi-sig
        // root (root-only) must pass k-of-n quorum validation, LOCAL frame only.
        $rootMg = self::multiGranterOf($root);
        if ($rootMg !== null) {
            $rootOk = $rootPeer === $localPeer
                && self::verifyMultiSigRoot($localPeer, $resolve, $root, $rootMg, $included);
        } else {
            $rgh = $root->bytes('granter');
            $g = $rgh !== null ? $resolve($rgh) : null;
            $pk = $g?->bytes('public_key');
            $rootOk = $pk !== null && Identity::peerIdOfPublicKey($pk) === $rootPeer;
        }
        if (!$rootOk) {
            return Verdict::Deny;
        }

        $good = true;
        $n = \count($chain);
        $i = 0;
        while ($i < $n && $good) {
            $current = $chain[$i];
            // A §3.6 M3 multi-sig token is root-only and fully verified above. A
            // multi-sig token anywhere but the chain root is rejected; otherwise
            // it is skipped here.
            if (self::isMultiSig($current)) {
                if ($i !== $n - 1) {
                    $good = false;
                }
                $i++;
                continue;
            }
            // signature: signer == granter, verify against granter identity
            $gh = $current->bytes('granter');
            if ($gh !== null) {
                $sgn = self::findSignature($current->hash(), $included);
                $granter = $resolve($gh);
                if ($sgn !== null && $granter !== null) {
                    $signer = $sgn->bytes('signer');
                    if (!($signer !== null && \hash_equals($signer, $gh) && Identity::verifySignature($sgn, $granter))) {
                        $good = false;
                    }
                } else {
                    $good = false;
                }
            } else {
                $good = false;
            }
            // grantee resolution → 401 carve-out
            $geh = $current->bytes('grantee');
            if ($geh !== null) {
                if ($resolve($geh) === null) {
                    throw new UnresolvableGranteeException();
                }
            } else {
                throw new UnresolvableGranteeException();
            }
            // temporal validity.
            //
            // CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
            // created_at is MALFORMED and must be refused outright. This has to run
            // BEFORE the two range checks below, because those are what the ambiguity
            // defeats -- see temporalFieldsRepresentable for the mechanism, which in
            // PHP is the ARITHMETIC form rather than the null-collapse one.
            if (!self::temporalFieldsRepresentable($current)) {
                $good = false;
            }
            $now = self::nowMs();
            $nb = $current->uint('not_before');
            if ($nb !== null && \gmp_cmp($now, $nb) < 0) {
                $good = false;
            }
            $ex = $current->uint('expires_at');
            if ($ex !== null && \gmp_cmp($ex, $now) < 0) {
                $good = false;
            }
            // delegation link
            if ($i < $n - 1) {
                $parent = $chain[$i + 1];
                $childPeer = self::linkGranterPeer($resolve, $localPeer, $current);
                $parentPeer = self::linkGranterPeer($resolve, $localPeer, $parent);
                if ($childPeer === null || $parentPeer === null) {
                    $good = false;
                } else {
                    $pg = $parent->bytes('grantee');
                    $cg = $current->bytes('granter');
                    if (!($pg !== null && $cg !== null && \hash_equals($pg, $cg)
                        && self::isAttenuated($localPeer, $childPeer, $parentPeer, $current, $parent)
                        && self::checkDelegationCaveats($parent, $current, $i))) {
                        $good = false;
                    }
                }
            }
            $i++;
        }
        return $good ? Verdict::Allow : Verdict::Deny;
    }

    /** @param list<array{hash:string,entity:Entity}> $included */
    public static function isRevoked(string $localPeer, Store $store, Entity $capability, array $included): bool
    {
        $resolve = static fn (string $h): ?Entity => self::capResolve($included, $store, $h);
        $c = self::collectChain($capability, $resolve);
        $rootHash = $c['ok'] ? $c['chain'][\count($c['chain']) - 1]->hash() : $capability->hash();
        return self::revokeMarker($localPeer, $store, $capability->hash()) !== null
            || self::revokeMarker($localPeer, $store, $rootHash) !== null;
    }

    private static function revokeMarker(string $localPeer, Store $store, string $h): ?Entity
    {
        return $store->getAt("/{$localPeer}/system/capability/revocations/" . \bin2hex($h));
    }

    // ── §5.2 verify-request (3-way verdict) ─────────────────────────────────────────

    public static function verifyRequest(string $localPeer, Store $store, Envelope $env): RequestVerdict
    {
        $exec = $env->root;
        $included = $env->included;
        $sgn = self::findSignature($exec->hash(), $included);
        if ($sgn === null) {
            return RequestVerdict::AuthnFail;
        }
        $authorH = $exec->bytes('author');
        $signer = $sgn->bytes('signer');
        if (!($signer !== null && $authorH !== null && \hash_equals($signer, $authorH))) {
            return RequestVerdict::AuthnFail;
        }
        $author = $env->includedGet($authorH);
        if ($author === null) {
            return RequestVerdict::AuthnFail;
        }
        if (!Identity::verifySignature($sgn, $author)) {
            return RequestVerdict::AuthnFail;
        }
        $ch = $exec->bytes('capability');
        $cap = $ch !== null ? $env->includedGet($ch) : null;
        if ($cap === null) {
            return RequestVerdict::AuthzDeny;
        }
        // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
        // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk.
        if (self::chainExceedsDepth($store, $cap, $included)) {
            return RequestVerdict::ChainTooDeep;
        }
        if (self::verifyCapabilityChain($localPeer, $store, $cap, $included) === Verdict::Deny) {
            return RequestVerdict::AuthzDeny;
        }
        $grantee = $cap->bytes('grantee');
        if (!($grantee !== null && \hash_equals($grantee, $authorH))) {
            return RequestVerdict::AuthzDeny;
        }
        if (self::isRevoked($localPeer, $store, $cap, $included)) {
            return RequestVerdict::AuthzDeny;
        }
        return RequestVerdict::Allow;
    }

    // ── §1.4 PD-2: outbound sub-dispatch authorization ──────────────────────

    /**
     * Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
     *
     * §1.4 admits three spellings of one address — `system/tree`,
     * `/{peer}/system/tree` and `entity://{peer}/system/tree` — and §1.4's PD-2 block
     * requires Dimension 1's handler pattern to be the target uri's peer-relative path,
     * because a grant names HANDLERS and a handler pattern never carries a peer segment.
     * Matching a grant against the absolute or schemed form matches nothing, silently,
     * which reads at the wire as an authority refusal.
     *
     * The first segment is dropped ONLY when it is a peer_id. A peer-relative
     * `system/protocol/connect` must not lose `system` — the standing defect on
     * `smalltalk` and `forth`, where an unconditional strip made every self-minted grant
     * unusable while the handshake stayed green.
     */
    public static function peerRelativeOf(string $uri): string
    {
        $p = self::normalizeUri($uri);
        if ($p === '' || $p[0] !== '/') {
            return $p;
        }
        $body = \substr($p, 1);
        $slash = \strpos($body, '/');
        $first = $slash === false ? $body : \substr($body, 0, $slash);
        if (!self::isPeerId($first)) {
            return $body;
        }
        return $slash === false ? '' : \substr($body, $slash + 1);
    }

    /**
     * Store key of a handler's OWN grant (§6.8:
     * `system/capability/grants/{pattern}`), tolerant of the pattern arriving absolute or
     * peer-relative.
     *
     * §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
     * the grant path is built from the PEER-RELATIVE one. The two are one segment apart
     * and concatenating the wrong one yields a doubled peer segment whose lookup misses —
     * which fails closed as "no handler grant" and is indistinguishable, at the wire,
     * from a genuine authority refusal.
     */
    public static function grantPathFor(string $localPeer, string $pattern): string
    {
        $prefix = "/{$localPeer}/";
        $rel = \str_starts_with($pattern, $prefix) ? \substr($pattern, \strlen($prefix)) : $pattern;
        return "/{$localPeer}/system/capability/grants/{$rel}";
    }

    /**
     * Verify a presented reentry credential against §1.4's clauses. Answers
     * `[verified, scope]`: `verified` is "did every clause hold", `scope` is the `peers`
     * scope Dimension 4 relaxes to, and `null` there means "the target itself".
     *
     * THE PAIR IS THE POINT. A null scope is a legitimate RESULT, so a lone scope return
     * would collapse "relaxes to the target" into "relaxes nothing" — the
     * absent-vs-present conflation §6.2's CAP-6a records for temporal accessors, one
     * layer up and in the direction that REFUSES a valid reentry.
     *
     * @param  list<array{hash: string, entity: Entity}>  $included
     * @return array{0: bool, 1: ?array}
     */
    public static function targetMintedPeersRelaxation(string $localPeer, string $targetPeer, Store $store, Entity $cred, array $included): array
    {
        // Nothing to relax — the default already covers this peer.
        if ($targetPeer === $localPeer) {
            return [false, null];
        }
        if (self::verifyCapabilityChainRootedAt($localPeer, $targetPeer, $store, $cred, $included) !== Verdict::Allow) {
            return [false, null];
        }
        if (self::isRevoked($localPeer, $store, $cred, $included)) {
            return [false, null];
        }
        $gh = $cred->bytes('grantee');
        if ($gh === null) {
            return [false, null];
        }
        $ge = self::capResolve($included, $store, $gh);
        $pk = $ge?->bytes('public_key');
        if ($pk === null || Identity::peerIdOfPublicKey($pk) !== $localPeer) {
            return [false, null];
        }
        $gs = self::grantsOfToken($cred);
        if ($gs === []) {
            return [false, null];
        }
        return [true, $gs[0]['peers'] ?? null];
    }

    /**
     * §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
     * LEAVES the peer, with all four dimensions applied.
     *
     * ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
     * decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension
     * 1's pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY
     * THE TARGET PEER naming this peer as `grantee` relaxes Dimension 4 (`peers`) AND
     * ONLY DIMENSION 4.
     *
     * *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT
     * a grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
     * sub-dispatch is refused however good the credential is. That is the COMPOSE, and
     * the BYPASS it is distinguished from is a peer that treats the credential as a
     * standalone authorizer and steers past its own grant — §6.8's confused-deputy
     * substitution. Both obvious vectors agree under either reading, so the only input
     * that separates them is a VALID credential presented to a handler whose own grant
     * does NOT cover the request.
     *
     * `$haveRelax === false` is the ambient arm (and equally a credential that failed a
     * clause): Dimension 4 is decided by the handler's grant alone.
     */
    public static function checkOutboundSubDispatch(string $localPeer, string $targetPeer, string $handlerPattern, string $operation, Entity $handlerGrant, EcfMap $resource, bool $haveRelax, ?array $relaxScope): bool
    {
        foreach (self::grantsOfToken($handlerGrant) as $g) {
            if (!self::matchesScope($localPeer, $handlerPattern, $g['handlers'], 'path')) {
                continue;
            }
            if (!self::matchesScope($localPeer, $operation, $g['operations'], 'id')) {
                continue;
            }
            if (!self::checkResourceScope($localPeer, $localPeer, $resource, $g['resources'])) {
                continue;
            }
            // Dimension 4. §5.2's default for an absent `peers` scope is
            // {include: [local_peer_id]}, so a foreign target fails unless this grant
            // names it or a target-minted credential relaxes it.
            $peers = $g['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
            if (self::matchesScope($localPeer, $targetPeer, $peers, 'id')) {
                return true;
            }
            if ($haveRelax) {
                if ($relaxScope === null) {
                    return true;   // absent `peers` on the credential relaxes to the granter
                }
                if (self::matchesScope($localPeer, $targetPeer, $relaxScope, 'id')) {
                    return true;
                }
            }
        }
        return false;
    }

}
