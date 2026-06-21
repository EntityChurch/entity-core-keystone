<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A byte cursor over a binary PHP string (binary-safe; length in BYTES). The ECF
 * decoder needs to peek/backtrack/slice, so a small explicit cursor is clearer
 * than a stream. Wire bytes are handled via strlen/substr/ord — NEVER mb_*.
 *
 * @internal
 */
final class Cursor
{
    private int $pos = 0;
    private readonly int $len;

    public function __construct(private readonly string $bytes)
    {
        $this->len = \strlen($bytes);
    }

    public function eof(): bool
    {
        return $this->pos >= $this->len;
    }

    public function remaining(): int
    {
        return $this->len - $this->pos;
    }

    public function pos(): int
    {
        return $this->pos;
    }

    public function readByte(): int
    {
        if ($this->pos >= $this->len) {
            throw new TruncatedInputException('unexpected end of input');
        }
        $b = \ord($this->bytes[$this->pos]);
        $this->pos++;
        return $b;
    }

    public function read(int $n): string
    {
        if ($n < 0) {
            throw new NonCanonicalEcfException('negative read length');
        }
        if ($n > $this->remaining()) {
            throw new TruncatedInputException("need {$n} bytes, have " . $this->remaining());
        }
        $slice = \substr($this->bytes, $this->pos, $n);
        $this->pos += $n;
        return $slice;
    }

    /** A raw slice that does NOT advance the cursor (for canonical-order checks). */
    public function slice(int $start, int $length): string
    {
        return \substr($this->bytes, $start, $length);
    }
}
