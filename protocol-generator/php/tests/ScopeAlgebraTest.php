<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\Capability;
use EntityCore\Ecf;
use EntityCore\EcfMap;
use EntityCore\Entity;
use EntityCore\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The 0.8.2.20 -> 0.8.2.25 scope-algebra units: §3.3's effective-target projection,
 * §6.3's handler-level path check, §5.2's PATH-SCOPED sentinel guard, and §5.5a's
 * scope-kind-typed subset check.
 *
 * These are the pure predicates. The §3.3 LADDER (which arm answers which code) and the
 * operation-before-resource ordering are driven over a real socket in
 * {@see TreeLadderTest}, because both are properties of the handler's control flow rather
 * than of any one predicate.
 */
final class ScopeAlgebraTest extends TestCase
{
    private const LOCAL = '2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg';
    private const PATTERN = '/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/tree';
    private const COVERED = '/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/system/type/qA';
    private const OUTSIDE = '/2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg/secrets/qB';

    /**
     * A `resource` map: `{targets: [...]}` plus `{exclude: [...]}` when non-empty.
     *
     * @param list<string> $targets
     * @param list<string> $excl
     */
    private static function resource(array $targets, array $excl = []): EcfMap
    {
        return $excl === []
            ? Ecf::map('targets', $targets)
            : Ecf::map('targets', $targets, 'exclude', $excl);
    }

    private static function execWith(string $operation, ?EcfMap $resource): Entity
    {
        $fields = ['operation', $operation, 'uri', self::PATTERN];
        if ($resource !== null) {
            $fields[] = 'resource';
            $fields[] = $resource;
        }
        return Entity::make('system/protocol/execute', Ecf::map(...$fields));
    }

    /**
     * A scope map. `include`/`exclude` are BOTH emitted so an empty include is
     * distinguishable from an absent one — §5.2 makes an empty include a legal grant
     * shape that denies everything, and a fixture that dropped the key would test the
     * wrong thing.
     *
     * @param list<string> $incl
     * @param list<string> $excl
     */
    private static function scope(array $incl, array $excl = []): EcfMap
    {
        return Ecf::map('include', $incl, 'exclude', $excl);
    }

    /**
     * @param array{0:list<string>,1:list<string>} $handlers
     * @param array{0:list<string>,1:list<string>} $operations
     * @param array{0:list<string>,1:list<string>} $resources
     */
    private static function grant(array $handlers, array $operations, array $resources): EcfMap
    {
        return Ecf::map(
            'handlers', self::scope($handlers[0], $handlers[1]),
            'operations', self::scope($operations[0], $operations[1]),
            'resources', self::scope($resources[0], $resources[1]),
        );
    }

    private static function token(EcfMap ...$grants): Entity
    {
        return Entity::make('system/capability/token', Ecf::map('grants', \array_values($grants)));
    }

    // ── §3.3 effective targets (0.8.2.20/.21, N11) ────────────────────────────────

    public function testEffectiveTargetsIsANonLossyProjection(): void
    {
        // ABSENT resource — the two empties must be TELLABLE APART (N11). A projection
        // that answered `[]` here would delete the discriminator before any handler could
        // read it, and `get`'s absent arm (a root listing) and its self-excluded arm
        // (400 path_required) would collapse into one.
        self::assertNull(
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', null)),
            'an absent resource must be reported as absent, not as an empty list',
        );

        // PRESENT, every target carved out by the caller's own exclude: NOT null, and an
        // empty survivor list. This is the other half of the discriminator.
        self::assertSame(
            [],
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', self::resource(['a/b'], ['a/*']))),
            'a present resource whose every target is excluded is [] and not null',
        );

        // SURVIVORS COME BACK IN THE CALLER'S OWN SPELLING, not canonicalized (0.8.2.21).
        // The value flows on to the store lookup, which canonicalizes for itself; handing
        // back a canonical form here would double-canonicalize a relative target.
        self::assertSame(
            ['x/one'],
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', self::resource(['x/one', 'x/two'], ['x/two']))),
            'the survivor keeps the caller own spelling',
        );

        // THE SELECTION MUST (F84): the survivor is the one the exclude LEFT, never
        // targets[0]. That is the whole point — a handler that counts the effective list
        // and then indexes the raw targets has the arithmetic right and reads a path no
        // authorization covered.
        self::assertSame(
            ['x/two'],
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', self::resource(['x/one', 'x/two'], ['x/one']))),
            'the survivor is x/two, not targets[0]',
        );

        // THE CALLER-EXCLUDE ARM IS FAIL-OPEN ON AN UNMATCHABLE PATTERN. §5.4 rules it
        // separately from the grant arm: canonicalize answers the sentinel,
        // matchesPattern then answers false, and the target simply SURVIVES. Inherited,
        // not restated — this assertion exists so the inheritance is measured rather than
        // assumed.
        self::assertSame(
            ['x/one'],
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', self::resource(['x/one'], ['../nope']))),
            'an unmatchable CALLER exclude carves out nothing',
        );

        // A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
        // Reporting it absent would serve the WIDER absent-case answer to a request that
        // named a resource — N11's own defect one field over.
        self::assertSame(
            [],
            Capability::effectiveTargets(self::LOCAL, self::execWith('get', Ecf::map('targets', 7))),
            'an ill-typed targets is still a PRESENT resource',
        );
    }

    // ── §6.3 check_path_permission (0.8.2.20/.22/.23) ─────────────────────────────

    public function testCheckPathPermissionConsultsThreeDimensions(): void
    {
        // The ACCEPT case first, and it is the one that validates the FIXTURE: a suite
        // built only from deny cases is indistinguishable from one asserting
        // False === False, which a mis-built grant fixture guarantees for free.
        $tok = self::token(self::grant([['system/tree'], []], [['get'], []], [['system/type/*'], []]));
        self::assertTrue(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $tok, self::PATTERN),
            'a grant covering handler+operation+resource must ALLOW',
        );
        // One deny per DIMENSION — a single deny cannot distinguish "the predicate checks
        // the dimension I care about" from "the predicate denies".
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', self::OUTSIDE, $tok, self::PATTERN),
            'RESOURCES: a path outside resources.include must DENY',
        );
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'put', self::COVERED, $tok, self::PATTERN),
            'OPERATIONS: an operation outside operations.include must DENY',
        );
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $tok, '/x/system/other'),
            'HANDLERS: a handler pattern outside handlers.include must DENY',
        );

        // AN EMPTY `resources.include` IS A LEGAL GRANT SHAPE and denies EVERY path
        // (§5.2: handlers that touch no tree paths). `covered` over an empty include list
        // is false, which is what that note says it should be.
        $empty = self::token(self::grant([['system/tree'], []], [['get'], []], [[], []]));
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $empty, self::PATTERN),
            'an empty resources.include denies every path',
        );

        // A GRANT EXCLUDE COVERING THE SUBJECT DENIES, even though the include covers it.
        $excl = self::token(self::grant([['system/tree'], []], [['get'], []], [['system/type/*'], ['system/type/qA']]));
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $excl, self::PATTERN),
            'a grant exclude covering the subject denies',
        );

        // A MALFORMED PATH canonicalizes to the §5.4 sentinel, which matches no grant, so
        // it falls through to DENY rather than being matched against anything — including
        // against a grant whose include is a bare star.
        $star = self::token(self::grant([['system/tree'], []], [['get'], []], [['*'], []]));
        self::assertTrue(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $star, self::PATTERN),
            'control: the bare-star grant does allow an ordinary path',
        );
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', '../nope', $star, self::PATTERN),
            'a path that canonicalizes to NEVER_MATCH denies',
        );

        // THE OPERATIONS DIMENSION IS ID-SCOPE, NOT PATH-SCOPE (F40). A path-form pattern
        // in `operations` is matched as a LITERAL string: a non-match, never a fault, and
        // never a canonicalizing match against an unrelated operation name.
        $idScoped = self::token(self::grant([['system/tree'], []], [['/*/get'], []], [['*'], []]));
        self::assertFalse(
            Capability::checkPathPermission(self::LOCAL, 'get', self::COVERED, $idScoped, self::PATTERN),
            'operations is id-scope: a path-form pattern is a literal and does not match get',
        );
    }

    // ── §5.2 the sentinel is scoped to PATH-SCOPE (0.8.2.24, N2/N3) ───────────────

    public function testSentinelGuardIsPathScopeOnly(): void
    {
        // AN ID-SCOPE EXCLUDE THAT PATH-CANONICALIZES TO THE SENTINEL MUST NOT DENY THE
        // WHOLE DIMENSION. `*/apply` is an ordinary namespaced operation name and a
        // literal under the id-scope grammar; putting it through the §5.4 transforms
        // purely to classify it produced the sentinel and denied EVERY operation.
        // Over-denial, and invisible on any well-formed grant — which is why this needs a
        // test rather than a reading.
        $tok = self::token(self::grant([['*'], []], [['*'], ['*/apply']], [['*'], []]));
        self::assertSame(
            Verdict::Allow,
            Capability::checkPermission(self::LOCAL, self::LOCAL, self::execWith('get', null), $tok, self::PATTERN),
            'an id-scope exclude that path-canonicalizes to the sentinel must not deny the dimension',
        );

        // THE PATH-SCOPE ARM STILL DENIES — the control that says the guard was SCOPED
        // rather than DELETED. An unmatchable exclude on `resources` excludes everything
        // (0.8.2.21), because there the sentinel means the author wrote a carve-out that
        // carves nothing and the grant is silently wider than written.
        $res = self::token(self::grant([['*'], []], [['*'], []], [['*'], ['../nope']]));
        self::assertSame(
            Verdict::Deny,
            Capability::checkPermission(
                self::LOCAL,
                self::LOCAL,
                self::execWith('get', self::resource(['system/type/qA'])),
                $res,
                self::PATTERN,
            ),
            'an unmatchable PATH-SCOPE exclude still denies (0.8.2.21)',
        );

        // And the same guard on the HANDLERS dimension, the other path-scope one.
        $hand = self::token(self::grant([['*'], ['../nope']], [['*'], []], [['*'], []]));
        self::assertSame(
            Verdict::Deny,
            Capability::checkPermission(self::LOCAL, self::LOCAL, self::execWith('get', null), $hand, self::PATTERN),
            'an unmatchable handlers exclude still denies (handlers is path-scope)',
        );
    }

    // ── §5.5a scope_subset is typed by scope kind (F50 / 0.8.2.16, K-7) ───────────

    /**
     * @param array{0:list<string>,1:list<string>} $childOps
     * @param array{0:list<string>,1:list<string>} $parentOps
     * @param array{0:list<string>,1:list<string>} $childRes
     * @param array{0:list<string>,1:list<string>} $parentRes
     */
    private static function subset(array $childOps, array $parentOps, array $childRes = [['*'], []], array $parentRes = [['*'], []]): bool
    {
        $parse = static function (EcfMap $g): array {
            $tok = self::token($g);
            return Capability::grantsOfToken($tok)[0];
        };
        return Capability::grantSubset(
            self::LOCAL,
            self::LOCAL,
            self::LOCAL,
            $parse(self::grant([['*'], []], $childOps, $childRes)),
            $parse(self::grant([['*'], []], $parentOps, $parentRes)),
        );
    }

    public function testScopeSubsetIsTypedByScopeKind(): void
    {
        // THE DIFFERENTIAL. `entity-core-formalization` measured 2 of 64 include pairs
        // disagreeing between the two readings, FAIL-CLOSED, with a 16-pair control
        // alphabet reporting 0 — which is why every hand-tried example missed it. Both
        // witnesses (`*/apply`, `/tree/get`) are OPERATIONS patterns, which §3.6 types as
        // id-scope: under the literal matcher a bare-star parent covers any child
        // pattern, and under the canonicalizing matcher the child canonicalizes to the
        // sentinel (or to an absolute path the parent's peer-framed star cannot cover)
        // and the subset is wrongly REFUSED.
        self::assertTrue(
            self::subset([['*/apply'], []], [['*'], []]),
            'id-scope: a namespaced operation child is covered by a bare-star parent',
        );
        self::assertTrue(
            self::subset([['/tree/get'], []], [['*'], []]),
            'id-scope: a path-form operation child is covered by a bare-star parent',
        );

        // THE CONTROL ALPHABET — the pairs that agree under both readings. Without these
        // the two assertions above are equally explained by a subset check that has
        // stopped checking anything.
        self::assertTrue(self::subset([['get'], []], [['*'], []]), 'control: get is covered by a bare-star parent');
        self::assertFalse(self::subset([['put'], []], [['get'], []]), 'control: put is NOT covered by a get-only parent');

        // A WIDENING ON THE PATH-SCOPE DIMENSION IS STILL REFUSED — the kind parameter
        // selected the matcher, it did not disable the check.
        self::assertFalse(
            self::subset([['get'], []], [['get'], []], [['*'], []], [['system/type/*'], []]),
            'path-scope: a bare-star child is NOT covered by a narrower parent',
        );

        // A PARENT EXCLUDE MUST BE INHERITED BY THE CHILD, on the id arm too.
        self::assertFalse(
            self::subset([['get'], []], [['*'], ['put']]),
            'id-scope: a child that does not inherit the parent exclude is refused',
        );
    }
}
