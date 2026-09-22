require "./cbor"
require "./entity"
require "./envelope"
require "./error"

module EntityCore
  # Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
  # EXECUTE_RESPONSE). A frame is `[4-byte BE length][CBOR payload]`; the payload
  # is a CBOR-encoded protocol envelope (§3.1).
  #
  # Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
  # authenticate are OPERATIONS on system/protocol/connect, not message types —
  # any other root type yields no response on the server side.
  module Wire
    # §4.10(a) / §1.6 finite max inbound payload — 16 MiB. A length prefix over
    # this is rejected with 413 payload_too_large BEFORE the body is buffered.
    MAX_FRAME = 16_u32 * 1024 * 1024

    extend self

    # ── frame read/write ─────────────────────────────────────────────────────────

    # Read one length-prefixed frame from an IO; return its CBOR payload bytes.
    # Returns nil on a clean EOF at a frame boundary (the connection closed). The
    # length prefix is checked against MAX_FRAME (§4.10(a)) BEFORE reading the body
    # — an over-limit prefix raises PayloadTooLargeError so the dispatcher can
    # answer 413 without buffering the (possibly huge) body.
    def read_frame(io : IO) : Bytes?
      hdr = Bytes.new(4)
      n = read_full(io, hdr)
      return nil if n == 0
      # A stream that ends MID-FRAME is a §4.11 framing REFUSAL owed a coded frame,
      # not an ordinary close. Both surface here as a short read, so the
      # distinction can only be made where the frame boundary is known — and
      # getting it wrong in the other direction would answer 400 to every peer that
      # simply hangs up. `n == 0` above is the ordinary-close arm and stays FIRST.
      raise TruncatedFrameError.new("truncated frame length") if n < 4

      len = (hdr[0].to_u32 << 24) | (hdr[1].to_u32 << 16) | (hdr[2].to_u32 << 8) | hdr[3].to_u32
      raise PayloadTooLargeError.new("frame length #{len} exceeds #{MAX_FRAME}") if len > MAX_FRAME

      # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and
      # is refused there as bytes that never become an Envelope.
      return Bytes.new(0) if len == 0
      body = Bytes.new(len)
      m = read_full(io, body)
      raise TruncatedFrameError.new("truncated frame body") if m < len
      body
    rescue IO::Error
      # socket closed while parked in a blocking read — a clean end, not a fault.
      nil
    end

    # Read exactly `buf.size` bytes; returns the count read (< size on EOF).
    private def read_full(io : IO, buf : Bytes) : Int32
      off = 0
      while off < buf.size
        r = io.read(buf[off, buf.size - off])
        break if r == 0
        off += r
      end
      off
    end

    # Write `payload` as a length-prefixed frame and flush. The caller serializes
    # concurrent writers on the same stream (per-connection write mutex).
    def write_frame(io : IO, payload : Bytes) : Nil
      len = payload.size.to_u32
      hdr = Bytes[
        ((len >> 24) & 0xFF).to_u8,
        ((len >> 16) & 0xFF).to_u8,
        ((len >> 8) & 0xFF).to_u8,
        (len & 0xFF).to_u8,
      ]
      io.write(hdr)
      io.write(payload)
      io.flush
    rescue e : IO::Error
      raise ConnectionBrokenError.new("frame write failed: #{e.message}")
    end

    # ── envelope <-> frame ───────────────────────────────────────────────────────

    def envelope_of_frame(payload : Bytes) : Envelope
      v = Cbor.decode(payload)
      raise WireProtocolError.new("frame: not a map") unless v.is_a?(::Hash(Cbor::EcValue, Cbor::EcValue))
      Envelope.from_cbor(v)
    end

    # §6.3 rejection reporting: recover ONLY the request_id from a frame the strict
    # decoder rejected, so the rejection can be delivered as a correlated
    # `400 non_canonical_ecf` response instead of silence. The frame stays rejected
    # — nothing else is read out of it. Returns nil when even the request_id is
    # unrecoverable (an unattributable frame, where silence is the only option
    # left). See `Cbor.decode_salvage`.
    #
    # The envelope and entity-wrapper shapes are fixed maps with no legal tag
    # position (§6.3), so a frame whose ONLY defect is a tag inside some entity's
    # `data` still has a structurally sound root — which is exactly the case this
    # recovers.
    def salvage_request_id(payload : Bytes) : String?
      v = Cbor.decode_salvage(payload)
      root = v.as?(::Hash(Cbor::EcValue, Cbor::EcValue)).try &.[]?("root")
      data = root.as?(::Hash(Cbor::EcValue, Cbor::EcValue)).try &.[]?("data")
      rid = data.as?(::Hash(Cbor::EcValue, Cbor::EcValue)).try &.[]?("request_id")
      rid.as?(String)
    rescue
      nil
    end

    def frame_of_envelope(envelope : Envelope) : Bytes
      Cbor.encode(envelope.to_cbor)
    end

    # ── §4.11 pre-admission refusal classification (0.8.2.25) ────────────────────

    # The `{status, code, message}` §4.11 assigns a pre-admission failure's CAUSE.
    #
    # "The frame obligation belongs to the class; the CODE belongs to the cause
    # [MUST]" — a single code for the class would answer an honest caller under the
    # wrong reason and send them to the wrong layer.
    #
    #   connect-auth proof-of-possession      401 authentication_failed  (§4.6/§4.7 —
    #                                            the connect handler's, not here)
    #   envelope over the configured maximum  413 payload_too_large      (§4.10(a), N14)
    #   resolution integrity (mis-keyed inc.) 400 hash_mismatch          (§5.2a, §1.8)
    #   framing / never becomes an Envelope   400 invalid_request        (§4.7, §4.11)
    #   root is neither EXECUTE nor E_R       400 invalid_request        (§3.3, §4.11 —
    #                                            in Peer#dispatch, not here)
    #
    # THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that
    # code non-conformant "on the framing arm" and gives its reason in the same
    # sentence: ENTITY-CBOR-ENCODING defines it for CBOR tag-policy violations
    # specifically, which that document still MUSTs at decode time (§6.3). The two
    # rows are disjoint by CAUSE rather than in conflict. Everything else this
    # decoder calls non-canonical (a non-minimal head, an indefinite length,
    # mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an
    # Envelope" and takes invalid_request.
    #
    # ORDER IS LOAD-BEARING: TagRejectedError < NonCanonicalError < CodecError and
    # HashMismatchError < ProtocolError, so each specific arm must be tested before
    # its superclass or it can never be reached. Crystal's `case ... when Type`
    # tests in source order, so this is a property of the listing.
    #
    # The messages are a FIXED TABLE, never the internal exception text: an
    # exception message is a developer diagnostic and can name internal state.
    def pre_admission_refusal(e : Exception) : {Int32, String, String}
      case e
      when PayloadTooLargeError
        {413, "payload_too_large", "frame exceeds the configured maximum"}
      when HashMismatchError
        {400, "hash_mismatch", "included entry does not bind to its key"}
      when TagRejectedError
        {400, "non_canonical_ecf", "CBOR tag in a data-field position"}
      else
        {400, "invalid_request", "frame does not decode to an envelope"}
      end
    end

    # ── EXECUTE builder (§3.2) ────────────────────────────────────────────────────

    # Build an EXECUTE entity. `author` / `capability` are 33-byte hashes;
    # `resource` is a cbor-map (`{"targets" => [...]}`) or nil.
    def make_execute(request_id : String, uri : String, operation : String, params : Entity,
                     author : Bytes? = nil, capability : Bytes? = nil,
                     resource : ::Hash(Cbor::EcValue, Cbor::EcValue)? = nil) : Entity
      data = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      data["request_id"] = request_id
      data["uri"] = uri
      data["operation"] = operation
      data["params"] = params.to_cbor
      data["author"] = author if author
      data["capability"] = capability if capability
      data["resource"] = resource if resource
      Entity.make("system/protocol/execute", data)
    end

    # ── EXECUTE_RESPONSE builder (§3.3) ────────────────────────────────────────────

    def make_response(request_id : String, status : Int32, result : Entity) : Entity
      data = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      data["request_id"] = request_id
      data["status"] = Cbor::EcInt.from(status)
      data["result"] = result.to_cbor
      Entity.make("system/protocol/execute/response", data)
    end

    # ── error result + empty params + resource target ──────────────────────────────

    def error_result(code : String, message : String? = nil) : Entity
      data = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      data["code"] = code
      data["message"] = message if message
      Entity.make("system/protocol/error", data)
    end

    # Empty-params (§3.2): a primitive/any whose data is the canonical empty map.
    def empty_params : Entity
      Entity.make("primitive/any", ::Hash(Cbor::EcValue, Cbor::EcValue).new)
    end

    # Build a resource cbor-map `{"targets" => [...]}`.
    def resource_target(*targets : String) : ::Hash(Cbor::EcValue, Cbor::EcValue)
      m = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      arr = targets.map { |t| t.as(Cbor::EcValue) }.to_a
      m["targets"] = arr
      m
    end

    # ── response decode helpers (initiator side) ────────────────────────────────────

    def response_status(envelope : Envelope) : UInt64
      envelope.root.uint("status") || 0_u64
    end

    def response_result(envelope : Envelope) : Entity?
      rc = envelope.root.map_field("result")
      rc ? Entity.from_cbor(rc) : nil
    end
  end
end
