<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §5.5 carve-out: a capability whose grantee cannot be resolved is an
 * UNAUTHENTICATED condition (→ 401), not an authorization denial (403). The chain
 * verifier throws this; the dispatcher maps it to 401 unresolvable_grantee.
 */
class UnresolvableGranteeException extends ProtocolException
{
}
