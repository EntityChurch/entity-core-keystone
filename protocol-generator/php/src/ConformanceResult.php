<?php

declare(strict_types=1);

namespace EntityCore;

/** A single conformance-vector result. */
final class ConformanceResult
{
    public function __construct(
        public readonly string $id,
        public readonly bool $pass,
        public readonly ?string $detail,
    ) {
    }
}
