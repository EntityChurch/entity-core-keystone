<?php

declare(strict_types=1);

namespace EntityCore;

/** §5.10 Layer-1 verdict (a PHP 8.1 enum — the closed verdict vocabulary). */
enum Verdict
{
    case Allow;
    case Deny;
}
