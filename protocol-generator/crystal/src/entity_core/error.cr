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

  # The §6.12 protocol_error name (avoids the ProtocolErrorError stutter, A-003
  # precedent).
  class WireProtocolError < TransportError
  end

  # §4.10(a): an inbound frame whose length prefix exceeds MAX_FRAME → the peer
  # answers 413 payload_too_large (mapped at the read site / dispatch boundary).
  class PayloadTooLargeError < TransportError
  end
end
