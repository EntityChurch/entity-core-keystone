<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Root of the EntityCore exception hierarchy (profile [error_model]).
 *
 * Extends \Exception (which implements \Throwable) so a bare `catch (\Exception)`
 * / `catch (\Throwable)` at the dispatch boundary catches protocol faults. NOT
 * \Error — that is reserved for engine/programmer faults (\TypeError, etc.).
 * Mirrors the C#/TS/Ruby exception trees in SHAPE while reading as idiomatic PHP.
 */
class EntityCoreException extends \Exception
{
}
