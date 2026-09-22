<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A frame that never completed: a prefix declaring `n` bytes followed by fewer, or a
 * partial length prefix. §4.11's framing arm names this input outright — "un-parseable,
 * truncated or non-canonical CBOR, or a length prefix that never completes" ->
 * `400 invalid_request`.
 *
 * A SEPARATE TYPE FROM A CLEAN EOF, because the two are different events and the read
 * collapses them: a clean EOF at a FRAME BOUNDARY is an ordinary close and is owed
 * nothing, while a stream that ends MID-FRAME is a REFUSAL and is owed a coded frame.
 * Getting it wrong in the other direction would answer 400 to every peer that simply
 * hangs up. On this substrate the discriminator is whether the read buffer still holds
 * bytes at EOF — the frame boundary is the only place that distinction exists.
 */
class TruncatedFrameException extends TransportException
{
}
