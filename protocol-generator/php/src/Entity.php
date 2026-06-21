<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A materialized entity `{type, data, content_hash}` (§1.1, §3.4) on top of the
 * S2 codec value model.
 *
 * The content_hash covers ONLY `{type, data}` (§1.1 / ENTITY-CBOR §4.2); the wire
 * form ({@see toCbor}) carries content_hash as a third field so entities are
 * self-describing across serialization (§3.1). The two forms stay distinct — the
 * hash is never computed over a map that already contains the content_hash field.
 *
 * `data` is an ARBITRARY ECF value (§1.1 / A-JAVA-010): an {@see EcfMap} for
 * every core protocol entity, or a scalar for e.g. primitive/string. {@see data}
 * gives a null-safe map VIEW (the empty map for scalar data) so field reads never
 * throw; {@see rawData} is the underlying value when a handler needs it verbatim.
 *
 * The 33-byte content_hash (format byte 0x00 + 32-byte SHA-256 digest) is a
 * binary PHP `string`. Equality is content_hash-based.
 */
final class Entity
{
    private function __construct(
        public readonly string $type,
        private readonly mixed $rawData,
        private readonly string $hashOctets,
    ) {
    }

    /**
     * Construct a materialized entity, computing the content_hash under the §9.1
     * floor (format_code 0x00 = ecfv1-sha256) over `{type, data}`. `data` is any
     * ECF value (an {@see EcfMap} for protocol entities, a scalar otherwise).
     */
    public static function make(string $type, mixed $data): self
    {
        $hash = Hash::contentHash(['type' => $type, 'data' => $data], 0);
        return new self($type, $data, $hash);
    }

    /**
     * Parse a wire entity map (`{type, data, content_hash}`), recompute the hash
     * from `{type, data}`, and validate it against the carried content_hash (§1.8
     * fidelity — we trust our recomputed hash, not the wire bytes; §5.2
     * validate-before-trust).
     */
    public static function ofCbor(EcfMap $m): self
    {
        $type = $m->get('type');
        if (!\is_string($type)) {
            throw new ProtocolException('entity: missing/invalid type');
        }
        if (!$m->hasTextKey('data')) {
            throw new ProtocolException('entity: missing data');
        }
        $data = $m->get('data');
        $e = self::make($type, $data);
        $carried = $m->get('content_hash');
        if ($carried instanceof ByteString && !\hash_equals($e->hashOctets, $carried->bytes)) {
            throw new ProtocolException('content_hash mismatch (§1.8 fidelity)');
        }
        return $e;
    }

    /** The 33-byte content_hash octets. */
    public function hash(): string
    {
        return $this->hashOctets;
    }

    /**
     * The `data` as a map view: the {@see EcfMap} itself when data IS a map (every
     * core protocol entity), or the empty map when data is a scalar (so field
     * reads on a scalar-data entity return null rather than throw).
     */
    public function data(): EcfMap
    {
        return $this->rawData instanceof EcfMap ? $this->rawData : new EcfMap();
    }

    /** The raw `data` value (§1.1) — may be any ECF node, not just a map. */
    public function rawData(): mixed
    {
        return $this->rawData;
    }

    // ── field reads off data ─────────────────────────────────────────────────

    public function text(string $key): ?string
    {
        return Ecf::text($this->data(), $key);
    }

    public function bytes(string $key): ?string
    {
        return Ecf::bytes_($this->data(), $key);
    }

    public function uint(string $key): ?\GMP
    {
        return Ecf::uint($this->data(), $key);
    }

    public function field(string $key): mixed
    {
        return $this->data()->get($key);
    }

    public function mapField(string $key): ?EcfMap
    {
        return Ecf::asMap($this->data()->get($key));
    }

    /** Decode a nested entity carried at $key (a wire entity map). */
    public function entityField(string $key): ?self
    {
        $m = $this->mapField($key);
        return $m === null ? null : self::ofCbor($m);
    }

    // ── wire form ────────────────────────────────────────────────────────────

    /** The wire entity map `{type, data, content_hash}`. */
    public function toCbor(): EcfMap
    {
        return Ecf::map(
            'type', $this->type,
            'data', $this->rawData,
            'content_hash', new ByteString($this->hashOctets),
        );
    }

    public function equalsHash(self $other): bool
    {
        return \hash_equals($this->hashOctets, $other->hashOctets);
    }
}
