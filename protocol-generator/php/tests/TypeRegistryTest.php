<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\CoreTypes;
use EntityCore\Entity;
use EntityCore\Peer;
use PHPUnit\Framework\TestCase;

/**
 * §9.5 core type-registry smoke (the 53/53 type-registry gate).
 *
 * A bootstrapped peer publishes the full §9.5 53-type core floor at
 * `/{peer}/system/type/{name}` (render-from-model — the content_hash of each is
 * computed by THIS peer's S2-green codec over `{type, data}`). For every one of
 * the 53 floor types this verifies:
 *  - it is rendered + bound in the store (reachable at its tree path);
 *  - its content_hash is a 33-byte ecfv1-sha256 hash (format byte 0x00 + digest);
 *  - the render is DETERMINISTIC (a re-render yields the byte-identical hash) — the
 *    convergence the S4 type_system byte-diff against the canonical vectors needs.
 *
 * The byte-for-byte diff against the canonical type-registry vectors is the S4
 * `type_system` category; this S3 smoke proves the 53/53 floor renders + binds +
 * is stable, so the registry surface the oracle fetches exists.
 */
final class TypeRegistryTest extends TestCase
{
    public function testCoreTypeFloorPublishes(): void
    {
        $peer = Peer::create(\str_repeat("\x11", 32));
        $local = $peer->localPeer;
        $models = CoreTypes::models();
        self::assertCount(53, $models, 'the §9.5 core floor is exactly 53 types');

        $checked = 0;
        foreach ($models as $name => $_) {
            $e = $peer->store->getAt("/{$local}/system/type/{$name}");
            self::assertNotNull($e, "core type published at tree path: {$name}");
            self::assertSame('system/type', $e->type, "{$name} is a system/type entity");
            $h = $e->hash();
            self::assertSame(33, \strlen($h), "{$name} content_hash is 33 bytes");
            self::assertSame(0, \ord($h[0]), "{$name} content_hash format byte is 0x00 (ecfv1-sha256)");
            // determinism: a fresh render of the same model yields the same hash.
            $rerendered = Entity::make('system/type', $models[$name]);
            self::assertTrue(\hash_equals($h, $rerendered->hash()), "{$name} render is deterministic");
            $checked++;
        }
        self::assertSame(53, $checked);
    }
}
