<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Multikey key-type codes (V7 §1.5 / §7.3). A PHP 8.1 backed enum — the
 * closed-vocabulary / exhaustive-set seam.
 *
 * Ed448 (0x02) is ALLOCATED here but the SIGNATURE primitive is DEFERRED for v0.1
 * (A-PHP-002 — ext-sodium has no Ed448; hybrid-FFI when agility lands). The
 * peer-id formatting for Ed448 still works (it is pure varint + base58); only the
 * Ed448 sign/verify is the deferred FFI piece.
 */
enum KeyType: int
{
    case Ed25519 = 1;
    case Ed448 = 2;
}
