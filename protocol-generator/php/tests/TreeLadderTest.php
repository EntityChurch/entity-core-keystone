<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\Ecf;
use EntityCore\EcfMap;
use EntityCore\Entity;
use EntityCore\Envelope;
use EntityCore\Peer;
use EntityCore\Session;
use EntityCore\Transport;
use EntityCore\Wire;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * §3.3's effective-target ladder and the operation-before-resource ordering, over real
 * loopback TCP.
 *
 * THE RESPONDER RUNS WITH OPEN GRANTS, AND THAT IS THE MEASUREMENT SETUP RATHER THAN A
 * CONVENIENCE. Under the §6.9a discovery floor the caller's grant names operations `get`
 * only, so an unknown-operation request is refused 403 at the DISPATCH authorization
 * boundary and never reaches the tree handler at all — which is exactly the ordering
 * question this is trying to ask, answered by the wrong gate. Opening the grants removes
 * that gate and nothing else; it is also how `run-s4.sh` launches the peer the census
 * measures.
 *
 * The narrow-capability half of §6.3 — `check_path_permission` denying a path the
 * caller's OWN exclude removed from the dispatch check — is deliberately NOT here: it
 * needs a minted capability narrower than the floor, which is `tools/arc-probe`'s family
 * G, and the predicate itself is unit-tested in {@see ScopeAlgebraTest}. What only a
 * socket can say is WHICH ARM OF THE LADDER ANSWERS, and that is what this drives.
 */
#[Group('loopback')]
final class TreeLadderTest extends TestCase
{
    private function seed(int $b): string
    {
        return \str_repeat(\chr($b), 32);
    }

    /**
     * @param list<string> $targets
     * @param list<string> $excl
     */
    private static function resource(array $targets, array $excl = []): EcfMap
    {
        return $excl === []
            ? Ecf::map('targets', $targets)
            : Ecf::map('targets', $targets, 'exclude', $excl);
    }

    /** @return array{0:int,1:string} status and the result `code` ('' on a 200). */
    private static function ask(Session $s, string $uri, string $operation, ?EcfMap $resource): array
    {
        $r = $s->execute($uri, $operation, Wire::emptyParams(), $resource);
        if (!$r instanceof Envelope) {
            return [0, 'no response'];
        }
        return [Wire::responseStatus($r), Wire::responseResult($r)?->text('code') ?? ''];
    }

    public function testEffectiveTargetLadderOverTheWire(): void
    {
        $transport = Transport::withLoop();
        $responder = Peer::create($this->seed(0x55), openGrants: true);
        [$listener, $port] = $transport->startListener($responder, 0);
        try {
            $initiator = Peer::create($this->seed(0x66));
            $s = $transport->dial($initiator, '127.0.0.1', $port);
            try {
                $tree = "/{$s->remotePeerId}/system/tree";

                // RESOLVE THE OPERATION FIRST, THE DIFFERENTIAL. An unknown operation is
                // an OPERATION fault (501) and a resource fault is 400; a handler that
                // validates the resource FIRST answers the wrong one for every unknown
                // operation. Measured across the cohort as the same call answering
                // `ambiguous_resource` WITHOUT a resource and 501 WITH one — i.e. the
                // fault the caller is told about depended on a field with nothing to do
                // with it. BOTH arms are driven, and so is a KNOWN operation, because
                // "501 to everything" satisfies the first two vacuously.
                self::assertSame(
                    [501, 'unsupported_operation'],
                    self::ask($s, $tree, 'bogusop', null),
                    'unknown op, NO resource -> 501 (not a resource fault)',
                );
                self::assertSame(
                    [501, 'unsupported_operation'],
                    self::ask($s, $tree, 'bogusop', self::resource(['system/type/system/peer'])),
                    'unknown op, WITH a resource -> the same 501',
                );
                self::assertSame(
                    200,
                    self::ask($s, $tree, 'get', self::resource(['system/type/system/peer']))[0],
                    'control: a known op with a resource still routes -> 200',
                );

                // §3.3 arithmetic on the EFFECTIVE list.
                //
                // SELF-EXCLUDED: `resource` PRESENT, every target carved out by the
                // caller's own exclude. EXTENSION-TREE §2.2a (v4.11) declares `get`
                // resource-OPTIONAL and BROAD-RESULT, so this is 400 path_required and
                // NOT the absent case's root listing — serving the listing would answer a
                // request for one excluded path with a listing of the whole tree.
                self::assertSame(
                    [400, 'path_required'],
                    self::ask($s, $tree, 'get', self::resource(['system/type/system/peer'], ['system/type/*'])),
                    'get, every target self-excluded -> 400 path_required',
                );
                // ABSENT resource is the OTHER empty and answers the root listing (§2.2a's
                // absent-case answer). The two arms together are the non-lossy projection
                // N11 requires: a peer that collapsed them could not answer both.
                self::assertSame(
                    200,
                    self::ask($s, $tree, 'get', null)[0],
                    'get, NO resource -> 200 root listing (the absent case, not path_required)',
                );
                self::assertSame(
                    [400, 'ambiguous_resource'],
                    self::ask($s, $tree, 'get', self::resource(['system/type/system/peer', 'system/type/system/hash'])),
                    'get, two effective targets -> 400 ambiguous_resource',
                );
                // THE SELECTION MUST (F84). Two targets, the FIRST excluded: the survivor
                // is targets[1] and it resolves. A handler that counted the effective list
                // and then indexed targets[0] would read `no/such/thing` — 404 — with the
                // arithmetic entirely correct. The 200 is what says the selection came
                // from the effective set.
                self::assertSame(
                    200,
                    self::ask($s, $tree, 'get', self::resource(['no/such/thing', 'system/type/system/peer'], ['no/such/*']))[0],
                    'get, targets[0] excluded -> the SURVIVOR is read (200), not targets[0] (404)',
                );
                // A §5.4 PATTERN is not a concrete path (0.8.2.20). A trailing `/` is a
                // LISTING request and stays one — only a star makes a target a pattern.
                self::assertSame(
                    [400, 'malformed_resource'],
                    self::ask($s, $tree, 'get', self::resource(['system/type/*'])),
                    'get, a pattern target -> 400 malformed_resource',
                );

                // `put` is resource-REQUIRED (§2.2a), so §3.3's "an empty effective list
                // IS the absent case" applies unscoped and BOTH empties answer
                // path_required. This branch answered `ambiguous_resource` until 0.8.2.20
                // named that as the exact inversion it forbids: *supply a resource* is not
                // *disambiguate your request*, and the code selects the remedy.
                self::assertSame(
                    [400, 'path_required'],
                    self::ask($s, $tree, 'put', null),
                    'put, NO resource -> 400 path_required (not ambiguous_resource)',
                );
                self::assertSame(
                    [400, 'path_required'],
                    self::ask($s, $tree, 'put', self::resource(['a/b'], ['a/*'])),
                    'put, every target self-excluded -> 400 path_required',
                );
            } finally {
                $s->close();
            }
        } finally {
            $listener->close();
        }
    }

    /**
     * §6.3's listing filter (0.8.2.21/.22) and its `count`.
     *
     * Driven IN-PROCESS rather than over the wire because it needs a caller capability
     * NARROWER than anything the handshake mints, and the peer's own tree handler is the
     * subject either way. The wire half of this is `tools/arc-probe` family G, which mints
     * exactly such a capability and drives it end to end.
     */
    public function testListingFilterOmitsDeniedEntriesAndCountFollows(): void
    {
        $responder = Peer::create($this->seed(0x77), openGrants: true);
        $local = $responder->localPeer;
        $responder->store->bind("/{$local}/box/qA", Entity::make('primitive/any', Ecf::map('n', 1)));
        $responder->store->bind("/{$local}/box/qB", Entity::make('primitive/any', Ecf::map('n', 2)));

        $listingFor = static function (?Entity $cap) use ($responder, $local): array {
            $ctx = new \EntityCore\HandlerContext(
                Entity::make('system/protocol/execute', Ecf::map(
                    'operation', 'get',
                    'uri', "/{$local}/system/tree",
                    'resource', Ecf::map('targets', ['box/']),
                )),
                new \EntityCore\Conn(),
                [],
                $cap,
                new Envelope(Entity::make('primitive/any', Ecf::emptyMap())),
                "/{$local}/system/tree",
            );
            $out = (new \EntityCore\TreeHandler($responder))->handle('get', $ctx);
            $data = $out->result->data();
            $entries = $data instanceof EcfMap ? $data->get('entries') : null;
            $names = [];
            if ($entries instanceof EcfMap) {
                foreach ($entries->entries() as [$k, $_]) {
                    $names[] = (string) $k;
                }
            }
            $count = $data instanceof EcfMap ? $data->get('count') : null;
            return [$names, $count === null ? -1 : \gmp_intval($count)];
        };

        // AN UNAUTHENTICATED CONTEXT IS NOT FILTERED — the filter's subject is "the
        // caller's verified capability", and where there is none there is no caller to
        // narrow. This is the bootstrap path, and it is also the control: without it a
        // filter that omitted everything would look like a filter that works.
        [$names, $count] = $listingFor(null);
        \sort($names);
        self::assertSame(['qA', 'qB'], $names, 'control: an unauthenticated listing is not filtered');
        self::assertSame(2, $count, 'control: count follows the unfiltered entries');

        // A CAPABILITY THAT EXCLUDES qB MUST OMIT IT, and `count` MUST follow the
        // FILTERED total. A count still reporting the source total is the disclosure the
        // rule exists to prevent — it names how many bindings live under the prefix to a
        // caller whose capability covers none of them.
        $cap = Entity::make('system/capability/token', Ecf::map('grants', [Ecf::map(
            'handlers', Ecf::map('include', ['*'], 'exclude', []),
            'operations', Ecf::map('include', ['*'], 'exclude', []),
            'resources', Ecf::map('include', ['*'], 'exclude', ['box/qB']),
        )]));
        [$names, $count] = $listingFor($cap);
        self::assertSame(['qA'], $names, 'the excluded entry is omitted from the listing');
        self::assertSame(1, $count, 'count reflects the FILTERED entry total, not the source tree total');
    }
}
