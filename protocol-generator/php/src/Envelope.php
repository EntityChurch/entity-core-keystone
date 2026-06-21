<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * The protocol envelope (§3.1): a {@see Entity} `root` plus an `included` list of
 * protocol entities keyed by content_hash. `included` is the §5.8 authority
 * carrier (capabilities, peer identities, signatures travel here).
 *
 * Held as an insertion-ordered list of {hash, entity} pairs so a wire round-trip
 * is deterministic; lookup is by content_hash octets.
 */
final class Envelope
{
    /**
     * @param list<array{hash:string,entity:Entity}> $included
     */
    public function __construct(
        public readonly Entity $root,
        public readonly array $included = [],
    ) {
    }

    /** A typed included entry. */
    public static function inc(Entity $e): array
    {
        return ['hash' => $e->hash(), 'entity' => $e];
    }

    /** Find an included entity by its content_hash, or null. */
    public function includedGet(string $h): ?Entity
    {
        foreach ($this->included as $pair) {
            if (\hash_equals($pair['hash'], $h)) {
                return $pair['entity'];
            }
        }
        return null;
    }

    // ── wire form ──────────────────────────────────────────────────────────────

    /**
     * §3.1: `included` is a content_hash → entity MAP, so duplicate hashes
     * collapse to one entry. The peer/transport builders may list the same entity
     * twice (e.g. a cap whose granter IS the local identity — granterPeer ==
     * peerEntity in the §6.11 reentry path), which would otherwise emit a
     * duplicate map key that the canonical codec rejects on decode. Dedup by
     * content_hash, preserving first-seen order, before encoding. Keys are
     * {@see ByteString} so they encode as CBOR byte strings (the content-hash
     * major-2 seam — NOT text keys).
     */
    public function toCbor(): EcfMap
    {
        $incl = new EcfMap();
        $seen = [];
        foreach ($this->included as $pair) {
            $hex = \bin2hex($pair['hash']);
            if (isset($seen[$hex])) {
                continue;
            }
            $seen[$hex] = true;
            $incl->put(new ByteString($pair['hash']), $pair['entity']->toCbor());
        }
        return Ecf::map(
            'root', $this->root->toCbor(),
            'included', $incl,
        );
    }

    public static function ofCbor(EcfMap $m): self
    {
        $rootV = $m->get('root');
        if (!($rootV instanceof EcfMap)) {
            throw new ProtocolException('envelope: missing root');
        }
        $root = Entity::ofCbor($rootV);
        $included = [];
        $incM = $m->get('included');
        if ($incM instanceof EcfMap) {
            $seen = [];
            foreach ($incM->entries() as [$k, $v]) {
                if (!($k instanceof ByteString)) {
                    throw new ProtocolException('envelope: included key not bytes');
                }
                if (!($v instanceof EcfMap)) {
                    throw new ProtocolException('envelope: included value not a map');
                }
                $ent = Entity::ofCbor($v);
                // §3.1: the included content_hash MUST equal the map key.
                if (!\hash_equals($k->bytes, $ent->hash())) {
                    throw new ProtocolException('included key != content_hash');
                }
                $hex = \bin2hex($k->bytes);
                if (isset($seen[$hex])) {
                    continue;
                }
                $seen[$hex] = true;
                $included[] = ['hash' => $k->bytes, 'entity' => $ent];
            }
        }
        return new self($root, $included);
    }
}
