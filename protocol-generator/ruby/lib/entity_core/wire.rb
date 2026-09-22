# frozen_string_literal: true

require_relative "cbor"
require_relative "entity"
require_relative "envelope"
require_relative "error"

module EntityCore
  # Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
  # EXECUTE_RESPONSE). A frame is +[4-byte BE length][CBOR payload]+; the payload
  # is a CBOR-encoded protocol envelope (§3.1).
  #
  # Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
  # authenticate are OPERATIONS on system/protocol/connect, not message types —
  # any other root type yields no response on the server side.
  module Wire
    # §4.10(a) / §1.6 finite max inbound payload — 16 MiB. A length prefix over
    # this is rejected with 413 payload_too_large BEFORE the body is buffered.
    MAX_FRAME = 16 * 1024 * 1024

    module_function

    # ── frame read/write ───────────────────────────────────────────────────────

    # Read one length-prefixed frame from an IO; return its CBOR payload bytes.
    # Returns nil on a clean EOF at a frame boundary (the connection closed). The
    # length prefix is checked against MAX_FRAME (§4.10(a)) BEFORE reading the
    # body — an over-limit prefix raises PayloadTooLargeError so the dispatcher
    # can answer 413 without buffering the (possibly huge) body.
    def read_frame(io)
      hdr = io.read(4)
      return nil if hdr.nil? || hdr.empty?
      # A stream that ends MID-FRAME is a §4.11 framing REFUSAL owed a coded frame,
      # not an ordinary close. Both surface here as a short/absent read, so the
      # distinction can only be made where the frame boundary is known — and getting
      # it wrong in the other direction would answer 400 to every peer that simply
      # hangs up. `hdr.empty?` above is the ordinary-close arm and stays first.
      raise TruncatedFrameError, "truncated frame length" if hdr.bytesize < 4

      len = hdr.unpack1("N")
      raise PayloadTooLargeError, "frame length #{len} exceeds #{MAX_FRAME}" if len > MAX_FRAME

      # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
      # refused there as bytes that never become an Envelope.
      payload = len.zero? ? "".b : io.read(len)
      raise TruncatedFrameError, "truncated frame body" if payload.nil? || payload.bytesize < len

      payload
    rescue EOFError
      nil
    rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::ENOTCONN
      # the peer (or our own teardown) closed the socket while we were parked in
      # a blocking read — a clean connection end, not a protocol fault.
      nil
    end

    # Write +payload+ as a length-prefixed frame and flush. The caller serializes
    # concurrent writers on the same stream (per-connection write Mutex).
    def write_frame(io, payload)
      io.write([payload.bytesize].pack("N"))
      io.write(payload)
      io.flush
    rescue Errno::EPIPE, Errno::ECONNRESET, IOError => e
      raise ConnectionBrokenError, "frame write failed: #{e.message}"
    end

    # ── envelope <-> frame ─────────────────────────────────────────────────────

    def envelope_of_frame(payload)
      v = Cbor.decode(payload)
      raise WireProtocolError, "frame: not a map" unless v.is_a?(::Hash)

      Envelope.from_cbor(v)
    end

    def frame_of_envelope(envelope)
      Cbor.encode(envelope.to_cbor)
    end

    # §6.3 rejection reporting: recover ONLY the request_id from a frame the strict
    # decoder rejected, so the rejection can be delivered as a correlated
    # `400 non_canonical_ecf` response instead of silence. The frame stays
    # rejected — nothing else is read out of it. Returns nil when even the
    # request_id is unrecoverable (an unattributable frame, where silence is the
    # only option left). See Cbor.decode_salvage.
    #
    # The envelope and entity-wrapper shapes are fixed maps with no legal tag
    # position (§6.3), so a frame whose ONLY defect is a tag inside some entity's
    # +data+ still has a structurally sound root — which is exactly the case this
    # recovers.
    def salvage_request_id(payload)
      v = Cbor.decode_salvage(payload)
      rid = v.dig("root", "data", "request_id") if v.is_a?(::Hash)
      rid if rid.is_a?(::String)
    rescue StandardError
      nil
    end

    # ── §4.11 pre-admission refusal classification (0.8.2.25) ───────────────────

    # The +[status, code, message]+ §4.11 assigns a pre-admission failure's CAUSE.
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
    # THE TAG ARM KEEPS +non_canonical_ecf+ AND THAT IS DELIBERATE. §4.11 rules that
    # code non-conformant "on the framing arm" and gives its reason in the same
    # sentence: +ENTITY-CBOR-ENCODING+ defines it for CBOR tag-policy violations
    # specifically, which that document still MUSTs at decode time (§6.3). The two
    # rows are disjoint by CAUSE rather than in conflict. Everything else this decoder
    # calls non-canonical (a non-minimal head, an indefinite length, mis-ordered keys)
    # is genuinely "non-canonical CBOR that never becomes an Envelope".
    #
    # ORDER IS LOAD-BEARING: TagRejectedError < NonCanonicalError and
    # HashMismatchError < ProtocolError, so each specific arm must be tested before
    # its superclass or it can never be reached.
    #
    # The messages are a FIXED TABLE, never the internal exception text: a
    # wire-visible string stays ASCII (two peers in this cohort have been killed at
    # runtime by a non-ASCII byte in an encoded string, on two unrelated compilers),
    # the internal texts carry section signs, and nothing here echoes attacker-supplied
    # bytes back.
    def pre_admission_refusal(e)
      case e
      when PayloadTooLargeError
        [413, "payload_too_large", "inbound frame exceeds the configured maximum size"]
      when HashMismatchError
        [400, "hash_mismatch", "an entity was addressed by a hash that does not bind to it"]
      when TagRejectedError
        [400, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field"]
      else
        [400, "invalid_request", "frame did not decode into an envelope"]
      end
    end

    # Whether a +read_frame+ failure is a §4.11 REFUSAL owed a coded frame rather
    # than an ordinary end of connection. A closed or reset socket is not a refusal
    # of anything and there is nobody left to answer.
    def framing_refusal?(e)
      e.is_a?(PayloadTooLargeError) || e.is_a?(TruncatedFrameError)
    end

    # ── EXECUTE builder (§3.2) ──────────────────────────────────────────────────

    # Build an EXECUTE entity. +author+ / +capability+ are 33-byte hashes;
    # +resource+ is a cbor-map (+{"targets" => [...]}+) or nil.
    def make_execute(request_id, uri, operation, params, author: nil, capability: nil, resource: nil)
      data = {
        "request_id" => request_id,
        "uri" => uri,
        "operation" => operation,
        "params" => params.to_cbor
      }
      data["author"] = author if author
      data["capability"] = capability if capability
      data["resource"] = resource if resource
      Entity.make("system/protocol/execute", data)
    end

    # ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────

    def make_response(request_id, status, result)
      Entity.make("system/protocol/execute/response",
                  { "request_id" => request_id, "status" => status, "result" => result.to_cbor })
    end

    # ── error result + empty params + resource target ───────────────────────────

    def error_result(code, message = nil)
      data = message ? { "code" => code, "message" => message } : { "code" => code }
      Entity.make("system/protocol/error", data)
    end

    # Empty-params (§3.2): a primitive/any whose data is the canonical empty map.
    def empty_params
      Entity.make("primitive/any", {})
    end

    # Build a resource cbor-map +{"targets" => [...]}+.
    def resource_target(*targets)
      { "targets" => targets }
    end

    # ── response decode helpers (initiator side) ────────────────────────────────

    def response_status(envelope)
      s = envelope.root.uint("status")
      s || 0
    end

    def response_result(envelope)
      rc = envelope.root.map_field("result")
      rc && Entity.from_cbor(rc)
    end
  end

  # §4.10(a): an inbound frame whose length prefix exceeds MAX_FRAME → the peer
  # answers 413 payload_too_large (mapped at the read site / dispatch boundary).
  class PayloadTooLargeError < TransportError; end
end
