<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\ByteString;
use EntityCore\Capability;
use EntityCore\Ecf;
use EntityCore\Entity;
use EntityCore\Envelope;
use EntityCore\Identity;
use EntityCore\Peer;
use EntityCore\Store;
use EntityCore\UnresolvableGranteeException;
use EntityCore\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * §3.6 M3 multi-signature K-of-N — ACCEPT path.
 *
 * The validate-peer `multisig` category is 100% rejection tests (malformed-quorum
 * → 403), which a fail-closed peer passes vacuously. This unit test covers the
 * direction the oracle omits: a real 2-of-3 multi-sig root (one signer = the local
 * peer, two valid signatures over the cap content_hash) → ALLOW, plus the deny
 * flips (below-threshold M4, duplicate-sig-no-inflate M4, local-not-in-signers M6,
 * degenerate-threshold M3, duplicate-signers M3, off-root M3) and the single-sig
 * superset (a single-sig root still verifies, unregressed).
 *
 * Direct against {@see Capability::verifyCapabilityChain} — the Layer-1 verdict
 * core (§5.10 determinism) — with the chain materialized in the envelope's
 * `included` list, exactly as a dispatch request carries it (§5.5).
 */
final class MultiSigCapabilityTest extends TestCase
{
    private function seed(int $b): string
    {
        return \str_repeat(\chr($b), 32);
    }

    /** @param list<string> $signers */
    private function multiSigCap(array $signers, int $threshold, string $grantee): Entity
    {
        $granter = Ecf::map(
            'signers', \array_map(static fn (string $s) => new ByteString($s), $signers),
            'threshold', $threshold,
        );
        return Entity::make('system/capability/token', Ecf::map(
            'granter', $granter,
            'grantee', new ByteString($grantee),
            'grants', [Peer::grant(['system/tree'], ['system/type/*'], ['get'], null)],
        ));
    }

    /** @return list<array{hash:string,entity:Entity}> */
    private function included(Entity ...$entities): array
    {
        return \array_map(static fn (Entity $e) => Envelope::inc($e), $entities);
    }

    /** @param list<array{hash:string,entity:Entity}> $inc */
    private function allows(string $local, Entity $cap, array $inc): bool
    {
        try {
            return Capability::verifyCapabilityChain($local, new Store(), $cap, $inc) === Verdict::Allow;
        } catch (UnresolvableGranteeException) {
            return false;
        }
    }

    public function testMultiSigKofN(): void
    {
        // Three signer identities; id1 is the LOCAL peer (M6).
        $id1 = Identity::ofSeed($this->seed(0x11));
        $id2 = Identity::ofSeed($this->seed(0x22));
        $id3 = Identity::ofSeed($this->seed(0x33));
        $local = $id1->peerId;

        // The grantee is the local peer too (so the §5.5 root grantee resolves).
        $grantee = $id1->identityHash();
        $signers = [$id1->identityHash(), $id2->identityHash(), $id3->identityHash()];

        $p1 = $id1->peerEntity;
        $p2 = $id2->peerEntity;
        $p3 = $id3->peerEntity;

        // ── ACCEPT: valid 2-of-3, local in quorum, 2 valid sigs over the cap hash ──
        $cap = $this->multiSigCap($signers, 2, $grantee);
        $s1 = $id1->sign($cap);
        $s2 = $id2->sign($cap);
        self::assertTrue($this->allows($local, $cap, $this->included($p1, $p2, $p3, $s1, $s2)),
            '2-of-3 valid quorum (local in signers) -> ALLOW (M3/M4/M6)');

        // M4: only 1 valid sig (< threshold) -> DENY.
        self::assertFalse($this->allows($local, $cap, $this->included($p1, $p2, $p3, $s1)),
            '1-of-3 below threshold -> DENY (M4 k-of-n)');

        // M4: a DUPLICATE signature from one signer does NOT inflate the count.
        $s1dup = $id1->sign($cap);
        self::assertFalse($this->allows($local, $cap, $this->included($p1, $p2, $p3, $s1, $s1dup)),
            'duplicate signature from one signer does not reach threshold -> DENY (M4)');

        // M6: the local peer is NOT among the signers -> DENY (even w/ a valid quorum).
        $capNoLocal = $this->multiSigCap([$id2->identityHash(), $id3->identityHash()], 2, $grantee);
        $s2b = $id2->sign($capNoLocal);
        $s3b = $id3->sign($capNoLocal);
        self::assertFalse($this->allows($local, $capNoLocal, $this->included($p2, $p3, $s2b, $s3b)),
            'local peer not in signers -> DENY (M6)');

        // M3: threshold = 1 (degenerate single disguised as quorum) -> DENY by structure.
        $capT1 = $this->multiSigCap($signers, 1, $grantee);
        $s1t = $id1->sign($capT1);
        $s2t = $id2->sign($capT1);
        self::assertFalse($this->allows($local, $capT1, $this->included($p1, $p2, $p3, $s1t, $s2t)),
            'threshold=1 -> DENY (M3 structure precedence)');

        // M3: duplicate signers in the descriptor -> DENY by structure.
        $capDup = $this->multiSigCap([$id1->identityHash(), $id1->identityHash()], 2, $grantee);
        $s1d = $id1->sign($capDup);
        self::assertFalse($this->allows($local, $capDup, $this->included($p1, $s1d)),
            'duplicate signers in descriptor -> DENY (M3 distinct)');

        // M3 root-only: a multi-sig token WITH a parent (off-root) -> DENY.
        $multiWithParent = Entity::make('system/capability/token', Ecf::map(
            'granter', Ecf::map(
                'signers', [new ByteString($id1->identityHash()), new ByteString($id2->identityHash())],
                'threshold', 2),
            'grantee', new ByteString($grantee),
            'parent', new ByteString($p1->hash())));
        self::assertFalse($this->allows($local, $multiWithParent, $this->included($p1, $p2)),
            'multi-sig token with a parent (off-root) -> DENY (M3 root-only)');

        // ── single-sig superset: a normal single-sig root still verifies (unregressed).
        $singleRoot = Entity::make('system/capability/token', Ecf::map(
            'granter', new ByteString($id1->identityHash()),
            'grantee', new ByteString($id1->identityHash()),
            'grants', [Peer::grant(['system/tree'], ['system/type/*'], ['get'], null)]));
        $singleSig = $id1->sign($singleRoot);
        self::assertTrue($this->allows($local, $singleRoot, $this->included($p1, $singleSig)),
            'single-sig root rooted at local still verifies (strict superset)');
    }
}
