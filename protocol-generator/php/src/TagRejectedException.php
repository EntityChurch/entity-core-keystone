<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A CBOR tag (major type 6) was found in the input. ECF §6.3 / invariant N2:
 * tags MUST be rejected at ANY nesting depth → 400 non_canonical_ecf.
 *
 * A subclass of NonCanonicalEcfException (a tag is one species of non-canonical
 * input) so a `catch (NonCanonicalEcfException)` catches it too.
 */
class TagRejectedException extends NonCanonicalEcfException
{
}
