<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * ECF conformance runner. Pure (no file IO): it takes the corpus bytes, decodes
 * them with THIS peer's own decoder (a decoder bug here is itself a conformance
 * failure, ENTITY-CBOR-ENCODING.md §E.3), and runs every encode_equal /
 * decode_reject vector.
 *
 * Vectors dispatch by category (the id prefix before the dot):
 *   * content_hash — varint(format_code) || SHA-2(ECF({type, data}))
 *   * peer_id      — Cbor.encode(Base58(varint(kt)||varint(ht)||digest)) as text
 *   * signature    — Ed25519_sign(seed, ECF(entity))
 *   * everything else (float/int/map_keys/length/primitive/nested/envelope)
 *     — plain Cbor.encode(input)
 *   * decode_reject — the decoder MUST reject the canonical wire bytes
 */
final class Conformance
{
    private const KINDS = ['encode_equal', 'decode_reject'];

    /**
     * Run every encode_equal / decode_reject vector in the decoded corpus.
     *
     * @return list<ConformanceResult>
     */
    public static function run(string $corpusBytes): array
    {
        $vectors = Cbor::decode($corpusBytes);
        if (!\is_array($vectors)) {
            throw new CodecException('corpus did not decode to an array of vectors');
        }
        $results = [];
        foreach ($vectors as $v) {
            if (!$v instanceof EcfMap) {
                continue; // meta rows that are not maps
            }
            $kind = $v->get('kind');
            if (!\is_string($kind) || !\in_array($kind, self::KINDS, true)) {
                continue; // meta / non-conformance rows
            }
            $results[] = self::runVector($v);
        }
        return $results;
    }

    private static function runVector(EcfMap $vector): ConformanceResult
    {
        $id = (string) $vector->get('id');
        $kind = (string) $vector->get('kind');
        return match ($kind) {
            'decode_reject' => self::runReject($id, $vector->get('canonical')),
            'encode_equal' => self::runEncode($id, $vector->get('input'), $vector->get('canonical')),
            default => new ConformanceResult($id, false, "unknown kind: {$kind}"),
        };
    }

    private static function runReject(string $id, mixed $wire): ConformanceResult
    {
        $bytes = self::asBytes($wire);
        try {
            Cbor::decode($bytes);
            return new ConformanceResult($id, false, 'expected reject but decoded successfully');
        } catch (CodecException) {
            return new ConformanceResult($id, true, null);
        }
    }

    private static function runEncode(string $id, mixed $input, mixed $want): ConformanceResult
    {
        $wantBytes = self::asBytes($want);
        try {
            $got = self::produce($id, $input);
        } catch (\Throwable $e) {
            return new ConformanceResult($id, false, 'raised ' . $e::class . ': ' . $e->getMessage());
        }
        if ($got === $wantBytes) {
            return new ConformanceResult($id, true, null);
        }
        return new ConformanceResult(
            $id,
            false,
            'got ' . \bin2hex($got) . ' want ' . \bin2hex($wantBytes)
        );
    }

    private static function produce(string $id, mixed $input): string
    {
        $category = \explode('.', $id)[0];
        return match ($category) {
            'content_hash' => self::produceContentHash($input),
            'peer_id' => self::producePeerId($input),
            'signature' => self::produceSignature($input),
            default => Cbor::encode($input),
        };
    }

    private static function produceContentHash(mixed $input): string
    {
        if (!$input instanceof EcfMap) {
            throw new UnsupportedValueException('content_hash input must be a map');
        }
        $entity = ['type' => $input->get('type'), 'data' => $input->get('data')];
        $formatCode = 0;
        if ($input->hasTextKey('format_code')) {
            $fc = $input->get('format_code');
            $formatCode = \is_int($fc) ? $fc : (int) \gmp_strval($fc);
        }
        return Hash::contentHash($entity, $formatCode);
    }

    private static function producePeerId(mixed $input): string
    {
        if (!$input instanceof EcfMap) {
            throw new UnsupportedValueException('peer_id input must be a map');
        }
        $keyType = self::asInt($input->get('key_type'));
        $hashType = self::asInt($input->get('hash_type'));
        $digest = self::asBytes($input->get('digest'));
        $peer = PeerId::format($keyType, $hashType, $digest);
        // The corpus pins the Base58 peer-id string ECF-encoded as CBOR text.
        return Cbor::encode($peer);
    }

    private static function produceSignature(mixed $input): string
    {
        if (!$input instanceof EcfMap) {
            throw new UnsupportedValueException('signature input must be a map');
        }
        $seed = self::asBytes($input->get('seed'));
        $entity = $input->get('entity');
        return Signature::signRaw($seed, Cbor::encode($entity));
    }

    /** Coerce a decoded value to raw bytes (ByteString or already a string). */
    private static function asBytes(mixed $v): string
    {
        if ($v instanceof ByteString) {
            return $v->bytes;
        }
        if (\is_string($v)) {
            return $v;
        }
        throw new UnsupportedValueException('expected bytes, got ' . \get_debug_type($v));
    }

    private static function asInt(mixed $v): int
    {
        if (\is_int($v)) {
            return $v;
        }
        if ($v instanceof \GMP) {
            return (int) \gmp_strval($v);
        }
        throw new UnsupportedValueException('expected int, got ' . \get_debug_type($v));
    }
}
