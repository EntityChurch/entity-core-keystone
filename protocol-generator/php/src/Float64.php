<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * An explicit CBOR float node (majors 7/25-27).
 *
 * PHP — like JS (the TS A-005 lesson) — erases the int-vs-float distinction for
 * integral magnitudes: a PHP `float` 1.0 is encode-indistinguishable from int 1
 * unless the type is preserved. `is_float()` DOES separate them at the top level
 * (1.0 is a float, 1 is an int), so the encoder treats a native PHP `float` as a
 * CBOR float directly. This wrapper exists for the cases where an integral-valued
 * float must be carried unambiguously through a structure (and as the decode
 * surface for floats), so 1.0 never silently collapses to int 1.
 *
 * The decoder returns finite floats as native PHP `float`; NAN / INF / -INF are
 * native PHP float specials. This class is the explicit-construction helper; the
 * encoder accepts both a native `float` and a Float64.
 */
final class Float64
{
    public function __construct(public readonly float $value)
    {
    }

    public static function of(float $value): self
    {
        return new self($value);
    }
}
