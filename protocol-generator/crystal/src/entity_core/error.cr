module EntityCore
  # Root of the EntityCore exception hierarchy (profile [error_model]). Rooted at
  # `Exception` per the Crystal profile; a bare `rescue` at the dispatch boundary
  # catches protocol faults. Mirrors the Ruby peer tree in SHAPE while reading as
  # idiomatic, statically-typed, COMPILED Crystal.
  class Error < Exception
  end

  # CBOR / canonicalization / decode faults (ECF §6.x). The codec raises
  # `CodecError` subclasses; the peer layer (S3) rescue-maps them to §5.2a / §6.12
  # status codes at the dispatch boundary.
  class CodecError < Error
  end

  # A wire input the canonical decoder MUST reject: a CBOR tag (major type 6,
  # invariant N2), an indefinite length, a non-minimal argument, a reserved
  # additional-info value, duplicate map keys, trailing bytes, or over-depth.
  class NonCanonicalError < CodecError
  end

  # A CBOR major-type-6 tag in a position ECF forbids (ENTITY-CBOR-ENCODING
  # section 6.3).
  #
  # A SUBCLASS RATHER THAN A MESSAGE, because section 4.11 makes this the one
  # decode-boundary cause that KEEPS `400 non_canonical_ecf` while every other one
  # moves to a different code — and a classifier that recognises the cause by
  # matching on the exception's message text is one string edit away from silently
  # re-collapsing them. Crystal's `rescue TagRejectedError` is a compiler-checked
  # type test; a message match is not.
  #
  # section 6.3 disjoins the two cases by CAUSE rather than putting two MUSTs in
  # conflict: a tag in a DATA-FIELD position is the policy violation with its own
  # code, while "the envelope and entity-wrapper CBOR shapes are fixed maps and
  # contain no positions where a tag could legally be placed" — i.e. section
  # 4.11's framing arm.
  class TagRejectedError < NonCanonicalError
  end

  # The input ended before a complete value could be read.
  class TruncatedError < CodecError
  end

  # A value this encoder does not model (e.g. an int beyond uint64/nint64 range,
  # or a non-ECF value).
  class UnsupportedValueError < CodecError
  end

  # A protocol-shaped fault above the codec (malformed envelope / entity,
  # handshake violation). The peer rescue-maps these at the dispatch boundary to
  # §5.2a / §6.12 status codes.
  class ProtocolError < Error
  end

  # A section 1.8 / section 3.1 RESOLUTION-INTEGRITY failure: an entity whose
  # carried `content_hash` is not `content_hash({type, data})`, or an `included`
  # entry whose MAP KEY does not bind to the entity filed under it.
  #
  # section 5.2a pins this arm: "A peer that refuses at the decode boundary MUST
  # answer `400 hash_mismatch` [MUST]" (mood corrected 0.8.2.24), and in the same
  # breath "`400 non_canonical_ecf` is NOT conformant here [MUST]". That code is
  # ENTITY-CBOR-ENCODING section 6.3's, for a CBOR tag-policy violation, and a
  # mis-keyed `included` entry carries NO TAG: its encoding is canonical, what is
  # false is the claim the KEY makes, and the remedy `non_canonical_ecf` selects
  # (re-encode) sends an honest caller to the wrong layer. This peer answered
  # `non_canonical_ecf` for every decode-boundary refusal until 0.8.2.24 —
  # measured on the wire, arc-probe B1/B2.
  #
  # A SUBCLASS of ProtocolError rather than a sibling, so every existing
  # `rescue ProtocolError` site keeps its behaviour; the classifier that maps a
  # refusal to a code tests this type FIRST, which is the whole point of the split.
  class HashMismatchError < ProtocolError
  end

  class HelloFailedError < ProtocolError
  end

  class AuthenticationError < ProtocolError
  end

  # §5.5 carve-out: a grantee that cannot be resolved → 401, not 403. Raised
  # inside the chain walk, caught at the dispatch boundary.
  class UnresolvableGranteeError < ProtocolError
  end

  # Transport faults (§6.12): framing errors, broken connections, timeouts.
  class TransportError < Error
  end

  class RecvTimeoutError < TransportError
  end

  class ConnectionBrokenError < TransportError
  end

  # A frame that never completed: a prefix declaring `n` bytes followed by fewer,
  # or a partial length prefix. Section 4.11's framing arm names this input
  # outright — "un-parseable, truncated or non-canonical CBOR, or a length prefix
  # that never completes" -> `400 invalid_request`.
  #
  # A SEPARATE TYPE FROM A CLEAN EOF, because the two are different events and the
  # read collapses them: a clean EOF at a FRAME BOUNDARY is an ordinary close and
  # is owed nothing, while a stream that ends MID-FRAME is a REFUSAL and is owed a
  # coded frame. Getting it wrong in the other direction would answer 400 to every
  # peer that simply hangs up. Distinct from ConnectionBrokenError, which this peer
  # also raises for a WRITE failure — there is nobody left to answer one of those.
  class TruncatedFrameError < TransportError
  end

  # The §6.12 protocol_error name (avoids the ProtocolErrorError stutter, A-003
  # precedent).
  class WireProtocolError < TransportError
  end

  # §4.10(a): an inbound frame whose length prefix exceeds MAX_FRAME → the peer
  # answers 413 payload_too_large (mapped at the read site / dispatch boundary).
  class PayloadTooLargeError < TransportError
  end
end
