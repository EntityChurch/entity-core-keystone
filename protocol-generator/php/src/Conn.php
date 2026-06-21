<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Per-connection state carried through the §6.5 dispatch chain.
 *
 *   - handshake state (§4.1/§4.6): the issued nonce + the hello-declared peer_id;
 *   - `established` (post-authenticate gate);
 *   - the §6.13(b)/§6.11 reentry OUTBOUND seam: a callable that originates an
 *     EXECUTE back over THIS connection and returns the correlated response
 *     envelope (or null). In the single-thread event loop the callable pumps the
 *     loop until the reply correlates by request_id — there is no thread to block.
 *   - an outbound request_id counter (distinct from inbound request ids).
 */
final class Conn
{
    public bool $established = false;
    public ?string $issuedNonce = null;
    public ?string $helloPeerId = null;

    /** @var (callable(Envelope):?Envelope)|null */
    public $outbound = null;

    private int $outCounter = 0;

    public function nextOutCounter(): int
    {
        return ++$this->outCounter;
    }
}
