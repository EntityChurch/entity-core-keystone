<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Per-connection framed IO over a non-blocking stream socket, driven by the
 * {@see EventLoop}. Owns the inbound read buffer + frame parser, the §6.11
 * request_id demux table (pending outbound waiters), and a loop-driven outbound
 * primitive.
 *
 * A reader callback ({@see onReadable}) drains the socket into the buffer and
 * dispatches every COMPLETE frame: an EXECUTE_RESPONSE resolves its pending
 * outbound waiter (§6.11); any other frame goes to the inbound {@see $onInbound}
 * sink (the peer dispatch). Writes are length-prefixed (§1.6) and drained inline
 * (loopback small-frame path; a partial write briefly selects-on-write).
 *
 * §4.10(a): the 4-byte length prefix is checked against {@see Wire::MAX_FRAME}
 * BEFORE the body is buffered — an over-limit prefix closes the connection (the
 * body boundary is unknowable).
 */
final class Io
{
    /** @var resource */
    private $socket;
    private string $rbuf = '';
    private bool $closed = false;

    /** @var array<string,array{env:?Envelope,done:bool}> request_id → waiter */
    private array $pending = [];

    /** @var (callable(Envelope):void)|null inbound non-response frame sink */
    public $onInbound = null;

    /** @param resource $socket a non-blocking stream socket */
    public function __construct($socket)
    {
        $this->socket = $socket;
        \stream_set_blocking($socket, false);
        // §7b: TCP_NODELAY — Nagle/delayed-ACK is the small-frame req/resp killer.
        if (\function_exists('socket_import_stream')) {
            $sock = @\socket_import_stream($socket);
            if ($sock !== false && $sock !== null) {
                @\socket_set_option($sock, \SOL_TCP, \TCP_NODELAY, 1);
            }
        }
    }

    /** @return resource */
    public function stream()
    {
        return $this->socket;
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }

    /**
     * Loop readable callback: drain available bytes, dispatch complete frames.
     * Returns false (deregister) on EOF / fault.
     */
    public function onReadable(): bool
    {
        if ($this->closed) {
            return false;
        }
        $chunk = @\fread($this->socket, 65536);
        if ($chunk === false || ($chunk === '' && \feof($this->socket))) {
            $this->close();
            return false;
        }
        $this->rbuf .= $chunk;
        try {
            $this->drainFrames();
        } catch (PayloadTooLargeException) {
            // §4.10(a): over-limit prefix — body boundary unknown, end the conn.
            $this->close();
            return false;
        } catch (TransportException) {
            $this->close();
            return false;
        }
        return !$this->closed;
    }

    private function drainFrames(): void
    {
        while (\strlen($this->rbuf) >= 4) {
            $len = \unpack('N', \substr($this->rbuf, 0, 4))[1];
            if ($len < 0 || $len > Wire::MAX_FRAME) {
                throw new PayloadTooLargeException("frame length out of bounds: {$len}");
            }
            if (\strlen($this->rbuf) < 4 + $len) {
                return; // wait for the rest of the body
            }
            $payload = \substr($this->rbuf, 4, $len);
            $this->rbuf = \substr($this->rbuf, 4 + $len);
            $this->dispatchFrame($payload);
        }
    }

    private function dispatchFrame(string $payload): void
    {
        try {
            $env = Wire::envelopeOfFrame($payload);
        } catch (\Throwable) {
            return; // skip a malformed frame (§4.9: don't crash, keep serving)
        }
        if ($env->root->type === 'system/protocol/execute/response') {
            $rid = $env->root->text('request_id') ?? '';
            if (isset($this->pending[$rid])) {
                $this->pending[$rid] = ['env' => $env, 'done' => true];
            }
            return;
        }
        $sink = $this->onInbound;
        if ($sink !== null) {
            $sink($env);
        }
    }

    /** Write an envelope as a length-prefixed frame (§1.6), draining fully. */
    public function writeFramed(Envelope $env): void
    {
        if ($this->closed) {
            throw new TransportException('write on closed connection');
        }
        $payload = Wire::frameOfEnvelope($env);
        $this->writeAll(Wire::frame($payload));
    }

    private function writeAll(string $data): void
    {
        $off = 0;
        $len = \strlen($data);
        while ($off < $len) {
            $w = @\fwrite($this->socket, \substr($data, $off));
            if ($w === false) {
                throw new TransportException('frame write failed');
            }
            if ($w === 0) {
                // socket buffer full — wait briefly for writability, then retry.
                $r = null;
                $wr = [$this->socket];
                $ex = null;
                $n = @\stream_select($r, $wr, $ex, 5);
                if ($n === false || $n === 0) {
                    throw new TransportException('write stalled');
                }
                continue;
            }
            $off += $w;
        }
    }

    /**
     * §6.13(b) outbound primitive (§6.11 reentry): send a request envelope, then
     * pump the loop until the correlated EXECUTE_RESPONSE arrives (or timeout /
     * close). Returns the response envelope, or null. The "await" is cooperative
     * loop re-entry — there is no thread to block.
     */
    public function outbound(EventLoop $loop, Envelope $request): ?Envelope
    {
        $rid = $request->root->text('request_id') ?? '';
        $this->pending[$rid] = ['env' => null, 'done' => false];
        try {
            $this->writeFramed($request);
        } catch (TransportException) {
            unset($this->pending[$rid]);
            return null;
        }
        $loop->runUntil(fn (): bool => $this->closed || ($this->pending[$rid]['done'] ?? false), 30000);
        $waiter = $this->pending[$rid] ?? null;
        unset($this->pending[$rid]);
        return $waiter['env'] ?? null;
    }

    /**
     * Send a request WITHOUT awaiting it (register a waiter, write the frame).
     * Lets multiple requests be in-flight on the one connection so the §6.11
     * request_id demux is genuinely exercised (the 8-way concurrent check):
     * fire-and-register N, then {@see runUntil} all N resolve out of order.
     */
    public function sendAsync(Envelope $request): void
    {
        $rid = $request->root->text('request_id') ?? '';
        $this->pending[$rid] = ['env' => null, 'done' => false];
        $this->writeFramed($request);
    }

    public function isResolved(string $rid): bool
    {
        return $this->closed || ($this->pending[$rid]['done'] ?? false);
    }

    /** Take a resolved response by request_id (and forget the waiter). */
    public function take(string $rid): ?Envelope
    {
        $w = $this->pending[$rid] ?? null;
        unset($this->pending[$rid]);
        return $w['env'] ?? null;
    }

    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        // wake any parked outbound waiters so a reentrant outbound returns null.
        foreach ($this->pending as $rid => $_) {
            $this->pending[$rid]['done'] = true;
        }
        @\fclose($this->socket);
    }
}
