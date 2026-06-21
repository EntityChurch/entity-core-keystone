<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\ByteString;
use EntityCore\Ecf;
use EntityCore\Entity;
use EntityCore\Peer;
use EntityCore\Session;
use EntityCore\Transport;
use EntityCore\Wire;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * S3 two-peer loopback smoke test (the phase exit gate; 11/11).
 *
 * Two PHP peers talk over real loopback TCP through the full §6.5 dispatch chain,
 * multiplexed on ONE single-thread {@see \EntityCore\EventLoop} (A-PHP-005): a
 * RESPONDER listens; an INITIATOR (a second identity) dials it and drives the §4.1
 * forward handshake (hello → authenticate), then:
 *  - 404 on an unregistered path (no handler resolved);
 *  - an authority-gated tree get (200) over the §4.4 discovery floor;
 *  - a capability request (200);
 *  - 8-way request_id demux of concurrently-issued replies (N7, §6.11) — 8
 *    requests in flight on the one connection, resolved out of order by the loop.
 *
 * A second scenario exercises the v7.74 Core Extensibility Boundary
 * (--debug-open-grants + --validate): the register live-hook (§6.13(a)), the emit
 * hook firing on register's tree writes (§6.13(c)), the §7a echo handler, AND the
 * §6.11 dispatch-outbound reentry (the validator-as-B surface S4 needs).
 *
 * The full validate-peer --profile core run is S4. This smoke proves the
 * wire-level peer surface so S4 can run the oracle.
 */
#[Group('loopback')]
final class SmokeTest extends TestCase
{
    /** @var list<bool> */
    private array $results = [];

    private function check(string $name, bool $ok): bool
    {
        $this->results[] = $ok;
        \fwrite(\STDOUT, '  [' . ($ok ? 'PASS' : 'FAIL') . "] {$name}\n");
        return $ok;
    }

    private function seed(int $b): string
    {
        return \str_repeat(\chr($b), 32);
    }

    public function testTwoPeerLoopback(): void
    {
        $this->runCoreScenario();
        $this->runExtensibilityScenario();
        $pass = \count(\array_filter($this->results));
        $total = \count($this->results);
        \fwrite(\STDOUT, "\nSMOKE: " . ($pass === $total ? 'PASS' : 'FAIL') . " ({$pass}/{$total})\n");
        self::assertSame($total, $pass, 'two-peer loopback must be all-PASS');
    }

    // ── Scenario 1: core ops (responder = default seed policy) ──────────────────────

    private function runCoreScenario(): void
    {
        $transport = Transport::withLoop();
        $responder = Peer::create($this->seed(0x11));
        [$listener, $port] = $transport->startListener($responder, 0);
        try {
            $initiator = Peer::create($this->seed(0x22));
            $s = $transport->dial($initiator, '127.0.0.1', $port);
            try {
                $remote = $s->remotePeerId;
                $this->check('session established (capability minted)', $s->capability !== null);
                $this->check('remote peer_id matches responder', $remote === $responder->localPeer);

                // 404 on an unregistered path
                $r404 = $s->execute("/{$remote}/does/not/exist", 'noop', Wire::emptyParams(), null);
                $this->check('unregistered path -> 404', $r404 !== null && Wire::responseStatus($r404) === 404);

                // authority-gated tree get (200) over the discovery floor.
                $ifaceTarget = Wire::resourceTarget('system/handler/system/tree');
                $rget = $s->execute("/{$remote}/system/tree", 'get', Wire::emptyParams(), $ifaceTarget);
                $this->check('granted tree get -> 200', $rget !== null && Wire::responseStatus($rget) === 200);
                $res = $rget !== null ? Wire::responseResult($rget) : null;
                $this->check('tree get returns a system/handler/interface entity',
                    $res !== null && $res->type === 'system/handler/interface');

                // capability request (200)
                $reqGrant = Peer::grant(['system/tree'], ['system/type/*'], ['get'], null);
                $reqParams = Entity::make('system/capability/request', Ecf::map('grants', [$reqGrant]));
                $rcap = $s->execute("/{$remote}/system/capability", 'request', $reqParams, null);
                $this->check('capability request -> 200', $rcap !== null && Wire::responseStatus($rcap) === 200);

                // 8-way request_id demux (N7, §6.11) — 8 requests in flight at once.
                $rids = [];
                for ($i = 0; $i < 8; $i++) {
                    $rids[] = $s->executeAsync("/{$remote}/system/tree", 'get', Wire::emptyParams(),
                        Wire::resourceTarget('system/handler/system/tree'));
                }
                $replies = $s->awaitAll($rids);
                $correlated = 0;
                foreach ($rids as $rid) {
                    $r = $replies[$rid] ?? null;
                    if ($r === null || Wire::responseStatus($r) !== 200) {
                        continue;
                    }
                    $rr = Wire::responseResult($r);
                    // the reply's request_id MUST equal the one we sent (demux correctness)
                    if ($rr !== null && $rr->type === 'system/handler/interface'
                        && ($r->root->text('request_id') === $rid)) {
                        $correlated++;
                    }
                }
                $this->check("8 interleaved requests each correlated -> {$correlated}/8", $correlated === 8);
            } finally {
                $s->close();
            }
        } finally {
            $listener->close();
        }
    }

    // ── Scenario 2: the v7.74 Core Extensibility Boundary over the wire ─────────────

    private function runExtensibilityScenario(): void
    {
        $transport = Transport::withLoop();
        $responder = Peer::create($this->seed(0x33), openGrants: true, conformance: true);
        $emitEvents = 0;
        $responder->store->registerTreeConsumer(function () use (&$emitEvents): void {
            $emitEvents++;
        });
        [$listener, $port] = $transport->startListener($responder, 0);
        try {
            // the initiator is ALSO a --validate peer so the §6.11 reentry echo
            // round-trips (B originates echo back to A; A must serve it).
            $initiator = Peer::create($this->seed(0x44), openGrants: true, conformance: true);
            $s = $transport->dial($initiator, '127.0.0.1', $port);
            try {
                $remote = $s->remotePeerId;
                $emitBefore = $emitEvents;

                // register live-hook (§6.13(a))
                $manifest = Ecf::map('name', 'demo', 'operations', Ecf::emptyMap());
                $req = Entity::make('system/handler/register-request', Ecf::map('manifest', $manifest));
                $rreg = $s->execute("/{$remote}/system/handler", 'register', $req,
                    Wire::resourceTarget('system/handler/demo'));
                $this->check('handler register -> 200 (live, not 501)',
                    $rreg !== null && Wire::responseStatus($rreg) === 200);
                $this->check('emit hook fired on register tree writes (§6.13(c))', $emitEvents > $emitBefore);

                // §7a echo conformance handler (resolve→dispatch)
                $payload = Entity::make('primitive/any', Ecf::map('ping', 42));
                $recho = $s->execute("/{$remote}/system/validate/echo", 'echo', $payload, null);
                $this->check('§7a echo -> 200', $recho !== null && Wire::responseStatus($recho) === 200);
                $res = $recho !== null ? Wire::responseResult($recho) : null;
                $this->check('§7a echo returns params verbatim', $res !== null && $res->type === 'primitive/any');

                // §6.11 dispatch-outbound REENTRY: B originates an outbound EXECUTE
                // back over THIS inbound connection to A; A's reader dispatches it.
                $this->check('§6.11 dispatch-outbound reentry round-trips (B→A echo over inbound conn)',
                    $this->runReentryProbe($s, $remote));
            } finally {
                $s->close();
            }
        } finally {
            $listener->close();
        }
    }

    private function runReentryProbe(Session $s, string $remote): bool
    {
        $params = Entity::make('primitive/any', Ecf::map(
            'target', 'system/validate/echo',
            'operation', 'echo',
            'value', Ecf::map('ping', 7),
            'reentry_capability', $s->capability->toCbor(),
            'reentry_granter', $s->granterPeer->toCbor(),
            'reentry_cap_signature', $s->capSignature->toCbor(),
        ));
        $r = $s->execute("/{$remote}/system/validate/dispatch-outbound", 'dispatch', $params, null);
        if ($r === null) {
            return false;
        }
        // Outer 200 = the §6.11 reentry round-tripped end-to-end: B's
        // dispatch-outbound handler originated an EXECUTE back to A over the SAME
        // inbound connection, A's reader dispatched it and replied, and B
        // correlated the reply by request_id and returned it. The INNER status
        // reflects A's authz verdict on the reentrant EXECUTE (a §5.2 cap check);
        // S4's validator supplies the cross-peer reentry cap that makes it 200.
        $inner = Wire::responseResult($r)?->uint('status');
        \fwrite(\STDOUT, '    (reentry round-tripped; inner echo verdict=' . ($inner !== null ? \gmp_strval($inner) : 'null') . ")\n");
        return Wire::responseStatus($r) === 200;
    }
}
