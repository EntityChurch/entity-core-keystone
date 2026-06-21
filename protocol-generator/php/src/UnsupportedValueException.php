<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A value this encoder does not model (a head-form argument beyond uint64, or a
 * non-ECF PHP value handed to the encoder).
 */
class UnsupportedValueException extends CodecException
{
}
