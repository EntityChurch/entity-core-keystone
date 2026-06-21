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

    /** Resolve peer-relative paths to absolute /{local}/... form. */
    public static function canonicalize(string $localPeer, string $path): string
    {
        if (\str_starts_with($path, './') || \str_starts_with($path, '../')) {
            throw new ProtocolException('canonicalize: reserved directory-relative path');
        }
        if (\str_starts_with($path, '*/')) {
            throw new ProtocolException('canonicalize: ambiguous bare peer wildcard');
        }
        if (\str_starts_with($path, '/')) {
            return $path;
        }
        return "/{$localPeer}/{$path}";
    }

    public static function matchesPattern(string $path, string $pattern): bool
    {
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

    /** @param array{incl:list<string>,excl:list<string>} $s */
    public static function matchesScope(string $localPeer, string $value, array $s): bool
    {
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
            $ok = self::matchesScope($localPeer, $operation, $g['operations'])
                && self::matchesScope($localPeer, $handlerPattern, $g['handlers']);
            if ($ok) {
                $peers = $g['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
                $ok = self::matchesScope($localPeer, $targetPeer, $peers);
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
     * @param array{incl:list<string>,excl:list<string>} $child
     * @param array{incl:list<string>,excl:list<string>} $parent
     */
    private static function scopeSubset(string $childPeer, string $parentPeer, array $child, array $parent): bool
    {
        foreach ($child['incl'] as $cp) {
            $cc = self::canonicalize($childPeer, $cp);
            $covered = false;
            foreach ($parent['incl'] as $pp) {
                if (self::matchesPattern($cc, self::canonicalize($parentPeer, $pp))) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }
        foreach ($parent['excl'] as $pe) {
            $cpe = self::canonicalize($parentPeer, $pe);
            $covered = false;
            foreach ($child['excl'] as $ce) {
                if (self::matchesPattern($cpe, self::canonicalize($childPeer, $ce))) {
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
        if (!self::scopeSubset($localPeer, $localPeer, $child['handlers'], $parent['handlers'])) {
            return false;
        }
        if (!self::scopeSubset($localPeer, $localPeer, $child['operations'], $parent['operations'])) {
            return false;
        }
        if (!self::scopeSubset($childPeer, $parentPeer, $child['resources'], $parent['resources'])) {
            return false;
        }
        $cp = $child['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
        $pp = $parent['peers'] ?? ['incl' => [$localPeer], 'excl' => []];
        return self::scopeSubset($localPeer, $localPeer, $cp, $pp);
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
        $resolve = static fn (string $h): ?Entity => self::capResolve($included, $store, $h);
        $c = self::collectChain($capability, $resolve);
        if (!$c['ok']) {
            return Verdict::Deny;
        }
        $chain = $c['chain'];
        $root = $chain[\count($chain) - 1];
        // Root authority: a single-sig root must root at the local peer; a §3.6
        // M3 multi-sig root (root-only) must pass k-of-n quorum validation.
        $rootMg = self::multiGranterOf($root);
        if ($rootMg !== null) {
            $rootOk = self::verifyMultiSigRoot($localPeer, $resolve, $root, $rootMg, $included);
        } else {
            $rgh = $root->bytes('granter');
            $g = $rgh !== null ? $resolve($rgh) : null;
            $pk = $g?->bytes('public_key');
            $rootOk = $pk !== null && Identity::peerIdOfPublicKey($pk) === $localPeer;
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
            // temporal validity
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
}
