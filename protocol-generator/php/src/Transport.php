<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Transport (L4): TCP listener + dialer over a single {@see EventLoop}, the §6.11
 * request_id demux, the §4.8 inbound-concurrent-with-outbound dispatch (here:
 * cooperative interleaving on one thread), and the §6.13(b) reentry seam. Plus the
 * initiator dialer/handshake that drives the two-peer loopback.
 *
 * == Concurrency model (A-PHP-005): single-thread stream_select event loop
 *
 * One {@see EventLoop} multiplexes the listen socket + every connection. An
 * inbound EXECUTE is dispatched inline ({@see Peer::dispatch}); a handler that
 * originates an outbound EXECUTE (§6.13(b)) calls `$conn->outbound`, which PUMPS
 * the same loop until the reply correlates (§6.11 reentry) — no thread, no
 * condvar. The §4.8 store-safety MUST is satisfied by construction (one handler
 * runs at a time).
 */
final class Transport
{
    public function __construct(private readonly EventLoop $loop)
    {
    }

    public static function withLoop(): self
    {
        return new self(new EventLoop());
    }

    public function loop(): EventLoop
    {
        return $this->loop;
    }

    // ── server: listener + accept loop ──────────────────────────────────────────────

    /**
     * Bind 127.0.0.1:port (0 = auto) and register the accept source on the loop.
     * Returns [Listener, boundPort].
     *
     * @return array{0:Listener,1:int}
     */
    public function startListener(Peer $peer, int $port): array
    {
        $errno = 0;
        $errstr = '';
        $server = @\stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        if ($server === false) {
            throw new TransportException("listen failed: {$errstr} ({$errno})");
        }
        \stream_set_blocking($server, false);
        $name = \stream_socket_get_name($server, false);
        $bound = (int) \substr($name, \strrpos($name, ':') + 1);

        $id = $this->loop->add($server, function () use ($server, $peer): bool {
            // accept ALL pending connections (§4.9: don't starve the backlog).
            while (true) {
                $client = @\stream_socket_accept($server, 0);
                if ($client === false) {
                    break;
                }
                $this->serveConnection($peer, $client);
            }
            return true; // keep the accept source registered
        });
        return [new Listener($this->loop, $server, $id), $bound];
    }

    /** @param resource $client */
    private function serveConnection(Peer $peer, $client): void
    {
        $io = new Io($client);
        $conn = new Conn();
        // wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
        $conn->outbound = fn (Envelope $env): ?Envelope => $io->outbound($this->loop, $env);
        $io->onInbound = function (Envelope $env) use ($peer, $conn, $io): void {
            try {
                $resp = $peer->dispatch($conn, $env);
            } catch (\Throwable) {
                $rid = $env->root->text('request_id') ?? '';
                $resp = new Envelope(Wire::makeResponse($rid, 500, Wire::errorResult('internal_error', null)));
            }
            if ($resp !== null) {
                try {
                    $io->writeFramed($resp);
                } catch (TransportException) {
                    // write failure ends this exchange; loop keeps serving others
                }
            }
        };
        $this->loop->add($io->stream(), fn (): bool => $io->onReadable());
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // Client side — the dialer + initiator handshake (drives the loopback)
    // ════════════════════════════════════════════════════════════════════════════════

    /** Open a client connection to host:port, register its reader, drive the handshake. */
    public function dial(Peer $initiator, string $host, int $port): Session
    {
        $errno = 0;
        $errstr = '';
        $sock = @\stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 5.0);
        if ($sock === false) {
            throw new TransportException("dial failed: {$errstr} ({$errno})");
        }
        $io = new Io($sock);
        $conn = new Conn();
        // the client reader: a core responder sends only EXECUTE_RESPONSEs; an
        // inbound EXECUTE (§6.11 reentry) is dispatched on the SAME loop so the
        // initiator can serve a B→A reentrant echo (the S4 validator-as-B shape).
        $conn->outbound = fn (Envelope $env): ?Envelope => $io->outbound($this->loop, $env);
        $io->onInbound = function (Envelope $env) use ($initiator, $conn, $io): void {
            try {
                $resp = $initiator->dispatch($conn, $env);
            } catch (\Throwable) {
                $rid = $env->root->text('request_id') ?? '';
                $resp = new Envelope(Wire::makeResponse($rid, 500, Wire::errorResult('internal_error', null)));
            }
            if ($resp !== null) {
                try {
                    $io->writeFramed($resp);
                } catch (TransportException) {
                    // best-effort
                }
            }
        };
        $this->loop->add($io->stream(), fn (): bool => $io->onReadable());
        $session = new Session($this->loop, $io, $initiator->identity);
        $session->handshake();
        return $session;
    }
}
