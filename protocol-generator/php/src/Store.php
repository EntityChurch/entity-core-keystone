<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Storage (foundation, §1.7): the two layers.
 *
 *   Content Store: hash → entity   (immutable, content-addressed, dedup)
 *   Entity Tree:   path → hash     (mutable location index)
 *
 * In-memory minimal impl. Paths are the canonical absolute form `/{peer_id}/rest`
 * (§1.4); the peer canonicalizes before calling in. Path keys are strings; the
 * content store is keyed by the lowercase-hex content_hash.
 *
 * == §4.8 store data-race safety — STRUCTURAL under the PHP idiom
 *
 * The transport is a SINGLE-THREAD `stream_select` event loop (A-PHP-005): one
 * handler runs to completion before the next is dispatched, so there is NO
 * concurrent access to these maps — the §4.8 store-safety MUST is satisfied BY
 * CONSTRUCTION, not by a lock. §3.9 CAS is a sequential read-then-write that
 * cannot interleave. This is the cleanest store-safety story in the cohort
 * (compare Zig's RwLock / Common-Lisp's :synchronized) — there is literally no
 * concurrency to race.
 *
 * == EMIT PATHWAY (§6.10 / §6.13(c)) — the Core Extensibility Boundary
 *
 * Tree/content writes produce events delivered to registered consumers. The hook
 * is LIVE even with ZERO consumers (events are produced and discarded) so a
 * future extension can register a consumer WITHOUT rebuilding the peer (the
 * §6.13(c) MUST). A core-only peer registers zero consumers, but the seam fires
 * on every bind.
 */
final class Store
{
    /** @var array<string,Entity> hash-hex → entity */
    private array $content = [];
    /** @var array<string,string> path → hash-hex */
    private array $tree = [];
    /** @var list<callable(array{hash:string,entity:Entity}):void> */
    private array $contentConsumers = [];
    /** @var list<callable(array{event_type:string,path:string,new_hash:?string,previous_hash:?string}):void> */
    private array $treeConsumers = [];

    // ── emit consumer registration (§6.10) ─────────────────────────────────────

    public function registerContentConsumer(callable $fn): void
    {
        $this->contentConsumers[] = $fn;
    }

    public function registerTreeConsumer(callable $fn): void
    {
        $this->treeConsumers[] = $fn;
    }

    // ── content store (§6.10 Store step: event only when the entity is new) ─────

    public function putEntity(Entity $e): void
    {
        $k = \bin2hex($e->hash());
        if (!isset($this->content[$k])) {
            $this->content[$k] = $e;
            $ev = ['hash' => $e->hash(), 'entity' => $e];
            foreach ($this->contentConsumers as $fn) {
                $fn($ev);
            }
        }
    }

    public function getByHash(string $h): ?Entity
    {
        return $this->content[\bin2hex($h)] ?? null;
    }

    // ── entity tree (§6.10 Bind step: event when the binding at the path changes) ─

    public function bind(string $path, Entity $e): void
    {
        $this->putEntity($e);
        $next = \bin2hex($e->hash());
        $prev = $this->tree[$path] ?? null;
        $this->tree[$path] = $next;
        if ($next !== $prev) {
            $ev = [
                'event_type' => $this->deriveEventType($prev, $next),
                'path' => $path,
                'new_hash' => $next,
                'previous_hash' => $prev,
            ];
            foreach ($this->treeConsumers as $fn) {
                $fn($ev);
            }
        }
    }

    public function unbind(string $path): void
    {
        $prev = $this->tree[$path] ?? null;
        if ($prev !== null) {
            unset($this->tree[$path]);
            $ev = ['event_type' => 'deleted', 'path' => $path, 'new_hash' => null, 'previous_hash' => $prev];
            foreach ($this->treeConsumers as $fn) {
                $fn($ev);
            }
        }
    }

    private function deriveEventType(?string $prev, ?string $next): string
    {
        if ($prev === null) {
            return 'created';
        }
        if ($next === null) {
            return 'deleted';
        }
        return 'modified';
    }

    /** The hex content_hash bound at $path, or null. */
    public function hashAt(string $path): ?string
    {
        return $this->tree[$path] ?? null;
    }

    public function getAt(string $path): ?Entity
    {
        $h = $this->tree[$path] ?? null;
        return $h === null ? null : ($this->content[$h] ?? null);
    }

    /**
     * One-level listing under $prefix (a trailing slash is added if absent),
     * sorted by segment (§3.9).
     *
     * @return list<array{segment:string,hash_hex:?string,has_children:bool}>
     */
    public function listing(string $prefix): array
    {
        $p = \str_ends_with($prefix, '/') ? $prefix : "{$prefix}/";
        $plen = \strlen($p);
        /** @var array<string,array{0:?string,1:bool}> $acc */
        $acc = [];
        foreach ($this->tree as $path => $hash) {
            if (\strlen($path) > $plen && \str_starts_with($path, $p)) {
                $rest = \substr($path, $plen);
                $slash = \strpos($rest, '/');
                if ($slash !== false) {
                    $seg = \substr($rest, 0, $slash);
                    $cur = $acc[$seg] ?? [null, false];
                    $acc[$seg] = [$cur[0], true];
                } else {
                    $cur = $acc[$rest] ?? [null, false];
                    $acc[$rest] = [$hash, $cur[1]];
                }
            }
        }
        \ksort($acc);
        $out = [];
        foreach ($acc as $seg => $cell) {
            $out[] = ['segment' => (string) $seg, 'hash_hex' => $cell[0], 'has_children' => $cell[1]];
        }
        return $out;
    }
}
