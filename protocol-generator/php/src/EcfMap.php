<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A CBOR map (major type 5) with arbitrary key types.
 *
 * A native PHP associative array cannot represent a CBOR map whose keys are byte
 * strings (or where text "1" must stay distinct from int 1 — PHP coerces numeric
 * string keys to int). The corpus DOES carry byte-string-keyed maps (e.g.
 * map_keys.5, the envelope `included` maps keyed by content-hash bytes), so the
 * decoder returns an EcfMap to round-trip them faithfully (the cpp explicit-Map
 * model). The encoder accepts BOTH an EcfMap and a native associative array (the
 * idiomatic public API for text-keyed maps).
 *
 * Keys are PHP values (string for text, ByteString for byte, int|\GMP for
 * integer keys); entries preserve insertion order, and the encoder applies the
 * canonical length-first key sort.
 */
final class EcfMap implements \Countable
{
    /** @var list<array{0:mixed,1:mixed}> ordered [key, value] entries */
    private array $entries = [];

    /** @param iterable<array{0:mixed,1:mixed}> $entries */
    public function __construct(iterable $entries = [])
    {
        foreach ($entries as [$k, $v]) {
            $this->entries[] = [$k, $v];
        }
    }

    public function put(mixed $key, mixed $value): void
    {
        $this->entries[] = [$key, $value];
    }

    /** @return list<array{0:mixed,1:mixed}> */
    public function entries(): array
    {
        return $this->entries;
    }

    public function count(): int
    {
        return \count($this->entries);
    }

    /** Look up a value by a TEXT-string key; returns null if absent. */
    public function get(string $textKey): mixed
    {
        foreach ($this->entries as [$k, $v]) {
            if (\is_string($k) && $k === $textKey) {
                return $v;
            }
        }
        return null;
    }

    public function hasTextKey(string $textKey): bool
    {
        foreach ($this->entries as [$k]) {
            if (\is_string($k) && $k === $textKey) {
                return true;
            }
        }
        return false;
    }
}
