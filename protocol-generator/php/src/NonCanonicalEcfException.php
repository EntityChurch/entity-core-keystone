<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A wire input the canonical decoder MUST reject: a CBOR tag (major type 6,
 * invariant N2), an indefinite length, a non-minimal argument, a reserved
 * additional-info value, duplicate map keys, trailing bytes, or over-depth.
 *
 * The peer maps this to 400 non_canonical_ecf at the dispatch boundary.
 */
class NonCanonicalEcfException extends CodecException
{
}
