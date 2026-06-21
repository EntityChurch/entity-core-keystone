<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * The single-thread non-blocking event loop (A-PHP-005) — the PHP-native
 * concurrency primitive for a multi-connection socket server. PHP-CLI has NO
 * userland threads (ext-pthreads is dead; ext-parallel is a ZTS-only non-core
 * dep), so every socket is non-blocking and multiplexed by `stream_select()`.
 *
 * == Why this satisfies the v7.75 substrate floor
 *
 *   - §4.8 store-safety: TRIVIAL — one handler runs to completion before the next
 *     is dispatched, so the {@see Store} maps are never accessed concurrently
 *     (no lock; no race by construction — the cleanest story in the cohort).
 *   - §6.11 reentrant demux (N6/N7): an outbound EXECUTE registers a waiter on its
 *     {@see Io}; {@see runUntil} pumps the loop until the correlated
 *     EXECUTE_RESPONSE arrives, so a handler can originate an outbound EXECUTE over
 *     the SAME inbound connection (reentry) and "await" it WITHOUT a thread —
 *     {@see Io::outbound} re-enters this loop cooperatively.
 *   - §4.9 resilience / §4.10(c): a slow/closed peer never blocks the others
 *     because every read/write/accept is non-blocking + multiplexed; a malformed
 *     frame closes only its own connection (keep serving).
 *   - §7b: TCP_NODELAY is set on every socket ({@see Io}).
 *
 * Each registered source is a callable invoked when its stream is readable; the
 * source returns false to deregister (the connection ended).
 */
final class EventLoop
{
    /** @var array<int,resource> id → stream */
    private array $streams = [];
    /** @var array<int,callable():bool> id → on-readable (false ⇒ deregister) */
    private array $onReadable = [];
    private int $nextId = 0;

    /**
     * Register a readable stream source.
     *
     * @param resource $stream
     * @param callable():bool $onReadable
     */
    public function add($stream, callable $onReadable): int
    {
        $id = $this->nextId++;
        $this->streams[$id] = $stream;
        $this->onReadable[$id] = $onReadable;
        return $id;
    }

    public function remove(int $id): void
    {
        unset($this->streams[$id], $this->onReadable[$id]);
    }

    public function isEmpty(): bool
    {
        return $this->streams === [];
    }

    /**
     * Run ONE select cycle: block (up to $timeoutMs, or indefinitely if null)
     * until a registered stream is readable, then service every ready stream.
     * Returns the count of ready streams serviced (0 = timeout / no streams).
     */
    public function pump(?int $timeoutMs = null): int
    {
        if ($this->streams === []) {
            return 0;
        }
        $read = \array_values($this->streams);
        $write = null;
        $except = null;
        $sec = $timeoutMs === null ? null : \intdiv($timeoutMs, 1000);
        $usec = $timeoutMs === null ? 0 : ($timeoutMs % 1000) * 1000;
        $n = @\stream_select($read, $write, $except, $sec, $usec);
        if ($n === false || $n === 0) {
            return 0;
        }
        $serviced = 0;
        foreach ($read as $stream) {
            $id = \array_search($stream, $this->streams, true);
            if ($id === false) {
                continue;
            }
            $serviced++;
            $cb = $this->onReadable[$id];
            $keep = $cb();
            if (!$keep) {
                $this->remove((int) $id);
            }
        }
        return $serviced;
    }

    /**
     * Pump until $cond returns true (the §6.11 reentry rendezvous + the initiator
     * handshake driver) or $timeoutMs elapses. Returns whether $cond became true.
     */
    public function runUntil(callable $cond, int $timeoutMs = 30000): bool
    {
        $deadline = \microtime(true) + ($timeoutMs / 1000);
        while (!$cond()) {
            $remaining = (int) (($deadline - \microtime(true)) * 1000);
            if ($remaining <= 0) {
                return $cond();
            }
            $this->pump(\min($remaining, 1000));
        }
        return true;
    }

    /** Pump forever (the standalone host's serve loop). */
    public function runForever(): void
    {
        while (!$this->isEmpty()) {
            $this->pump(1000);
        }
    }
}
