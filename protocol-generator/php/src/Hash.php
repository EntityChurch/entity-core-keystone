<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Content-hash construction (ENTITY-CBOR-ENCODING.md §4.2):
 *
 *   content_hash = varint(format_code) || hash_alg(ECF({type, data}))
 *
 * The default format code 0x00 is ecfv1-sha256; 0x01 is ecfv1-sha384 (agility).
 * The format_code is NOT part of the hashed entity — only {type, data} is hashed.
 * The varint prefix is multicodec-style LEB128, so a code >= 0x80 extends to
 * multiple bytes (invariant N1). SHA-256/384 come from the stdlib hash() (bundled,
 * no dep).
 */
final class Hash
{
    /** Allocated content-hash format codes (V7 §1.2 / §4.3 active set). */
    private const ALLOCATED = [0 => 'sha256', 1 => 'sha384'];

    /**
     * Compute the wire content hash (varint format-code prefix + digest) over an
     * entity carrying at least "type" and "data". `data` is an arbitrary ECF
     * value (A-JAVA-010) — never assume it is a map.
     *
     * @param array<string,mixed> $entity
     */
    public static function contentHash(array $entity, int $formatCode = 0): string
    {
        if (!\array_key_exists('type', $entity) || !\array_key_exists('data', $entity)) {
            throw new UnsupportedValueException('entity must carry "type" and "data"');
        }
        $hashed = ['type' => $entity['type'], 'data' => $entity['data']];
        $digest = \hash(self::digestName($formatCode), Cbor::encode($hashed), true);
        return Varint::encode($formatCode) . $digest;
    }

    /** Resolve an integer format code to its hash() algo name, or null. */
    public static function resolveFormat(int $code): ?string
    {
        return self::ALLOCATED[$code] ?? null;
    }

    /**
     * Decode a multicodec-style LEB128 format-code prefix and resolve it
     * (invariant N1 — the multi-byte varint decoder fires before the registry
     * check, so a code >= 0x80 decodes, not short-circuits). Returns the hash()
     * algo name or null.
     */
    public static function resolveWireFormat(string $prefix): ?string
    {
        [$code] = Varint::decode($prefix);
        return self::resolveFormat($code);
    }

    /**
     * Construct-side digest name. Code 0x01 = SHA-384 (agility); everything else
     * = SHA-256 (the required floor + the synthetic-high-code corpus case
     * content_hash.4, which hashes with SHA-256 under a high varint prefix).
     */
    private static function digestName(int $formatCode): string
    {
        return $formatCode === 1 ? 'sha384' : 'sha256';
    }
}
