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
      raise ConnectionBrokenError, "truncated frame length" if hdr.bytesize < 4

      len = hdr.unpack1("N")
      raise PayloadTooLargeError, "frame length #{len} exceeds #{MAX_FRAME}" if len > MAX_FRAME

      payload = len.zero? ? "".b : io.read(len)
      raise ConnectionBrokenError, "truncated frame body" if payload.nil? || payload.bytesize < len

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
