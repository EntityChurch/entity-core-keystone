<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried `content_hash` is
 * not `content_hash({type, data})`, or an `included` entry whose MAP KEY does not bind to
 * the entity filed under it.
 *
 * §5.2a pins this arm: "A peer that refuses at the decode boundary MUST answer
 * `400 hash_mismatch` [MUST]" (mood corrected 0.8.2.24), and in the same breath
 * "`400 non_canonical_ecf` is NOT conformant here [MUST]". That code is
 * `ENTITY-CBOR-ENCODING` §6.3's, for a CBOR tag-policy violation, and a mis-keyed
 * `included` entry carries NO TAG: its encoding is canonical, what is false is the claim
 * the KEY makes, and the remedy `non_canonical_ecf` selects (*re-encode*) sends an honest
 * caller to the wrong layer. This peer answered `non_canonical_ecf` for every
 * decode-boundary refusal until 0.8.2.24 — measured on the wire, `arc-probe` B1/B2.
 *
 * A SUBCLASS of {@see ProtocolException} rather than a sibling, so every existing
 * `catch (ProtocolException)` site keeps its behaviour; the classifier that maps a
 * refusal to a code tests this type FIRST, which is the whole point of the split.
 */
class HashMismatchException extends ProtocolException
{
}
