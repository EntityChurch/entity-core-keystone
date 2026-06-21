<?php

declare(strict_types=1);

namespace EntityCore\Tests;

/** Vendored test-vector corpus locations (relative to protocol-generator/php/). */
final class CorpusPaths
{
    public static function vectorsDir(): string
    {
        return \dirname(__DIR__, 2) . '/shared/test-vectors';
    }

    public static function corpusVersion(): string
    {
        return \getenv('CORPUS_VERSION') ?: 'v0.8.0';
    }

    public static function conformanceCorpus(): string
    {
        $env = \getenv('CORPUS');
        if ($env !== false && $env !== '') {
            return $env;
        }
        return self::vectorsDir() . '/' . self::corpusVersion() . '/conformance-vectors-v1.cbor';
    }
}
