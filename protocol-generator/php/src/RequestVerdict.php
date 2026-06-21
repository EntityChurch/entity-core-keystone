<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §5.2 three-way request verdict, plus the §4.10(b) structural chain-depth case.
 * Matched EXHAUSTIVELY at the dispatch site (the §5.2 verdict trichotomy →
 * 401/403, the §4.10(b) excess → 400).
 */
enum RequestVerdict
{
    case Allow;
    case AuthnFail;   // → 401 authentication_failed
    case AuthzDeny;   // → 403 capability_denied
    case ChainTooDeep; // → 400 chain_depth_exceeded
}
