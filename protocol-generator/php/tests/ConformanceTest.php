<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\Conformance;
use PHPUnit\Framework\TestCase;

/**
 * The S2 wire-conformance gate: decode the vendored v7.71 ECF corpus with THIS
 * peer's own decoder and assert byte-identity (encode) / mandatory-reject
 * (decode) for every vector.
 */
final class ConformanceTest extends TestCase
{
    public function testEcfConformanceCorpusByteIdentical(): void
    {
        $bytes = \file_get_contents(CorpusPaths::conformanceCorpus());
        self::assertNotFalse($bytes, 'could not read the conformance corpus');

        $results = Conformance::run($bytes);
        $failures = \array_filter($results, static fn ($r) => !$r->pass);
        $passes = \count($results) - \count($failures);

        if ($failures !== []) {
            $lines = [];
            foreach ($failures as $r) {
                $lines[] = "  {$r->id}: {$r->detail}";
            }
            \fwrite(STDERR, "\n=== ECF conformance failures (" . \count($failures) . '/' . \count($results) . ") ===\n");
            \fwrite(STDERR, \implode("\n", $lines) . "\n");
        }

        \fwrite(STDERR, "\nECF corpus: {$passes}/" . \count($results) . " PASS\n");
        self::assertSame([], \array_values($failures), \count($failures) . ' vector(s) failed');
        self::assertGreaterThanOrEqual(69, \count($results), 'expected at least 69 conformance vectors');
    }
}
