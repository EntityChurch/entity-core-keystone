# frozen_string_literal: true

require "socket"
require "timeout"

require_relative "test_helper"

# §4.11 pre-admission refusals (0.8.2.25) — classification AND emission.
#
# §4.11's rule has two halves and they fail differently.
#
#   * "The frame obligation belongs to the class" is WIRE-VISIBLE, and the two
#     non-conformant behaviours it names are distinct: DROPPING the frame (no
#     response, no close — "the weaker of the two precisely because nothing surfaces
#     it") and CLOSING WITH NO CODED FRAME (indistinguishable from a network fault,
#     and on a multiplexed connection it destroys unrelated ADMITTED requests). This
#     peer had BOTH before 0.8.2.25: the un-salvageable decode arm and the non-EXECUTE
#     root dropped, the oversize and truncated arms closed bare.
#   * "The CODE belongs to the cause [MUST]" is a MAPPING, and a mapping is exactly
#     the thing that regresses silently when a new failure joins an existing branch.
#
# So both halves are covered here: the mapping at the unit level, and the emission
# over a real socket, because a green mapping over a transport that never calls it is
# the `check_path_permission` shape all over again.
#
# THE PINNED CHECK SET (778) HAS NO VECTOR ON THIS SURFACE, which is why the coverage
# is authored here rather than inherited.
#
# EVERY SOCKET CASE CARRIES A POSITIVE CONTROL in the same connection or the same
# run. A probe fails in the direction of the answer it is looking for: a malformed
# frame that is malformed in a SECOND way answers the code under measurement for the
# wrong reason, and without the control that publishes as a peer finding.
class PreAdmissionTest < Minitest::Test
  include EntityCore

  LOCAL_SEED = ("\x7b".chr * 32).b

  # ── 1. The mapping: §4.11's table, one row at a time ────────────────────────

  def test_pre_admission_code_is_the_causes
    rows = [
      # §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14).
      [PayloadTooLargeError.new("x"), 413, "payload_too_large"],
      # §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
      # non_canonical_ecf NON-CONFORMANT here.
      [HashMismatchError.new("x"), 400, "hash_mismatch"],
      # ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
      [TagRejectedError.new("x"), 400, "non_canonical_ecf"],
      # §4.7 / §4.11 framing arm: bytes that never become an Envelope.
      [TruncatedFrameError.new("x"), 400, "invalid_request"],
      [TruncatedError.new("x"), 400, "invalid_request"],
      [ProtocolError.new("x"), 400, "invalid_request"],
      # The one that makes the subclass ORDERING load-bearing: a non-minimal head is
      # "non-canonical CBOR" by name and is NOT the tag-policy arm.
      [NonCanonicalError.new("x"), 400, "invalid_request"]
    ]
    assert_equal 7, rows.length, "examined-N, not merely `no failures`"
    rows.each do |exc, status, code|
      got_status, got_code, message = Wire.pre_admission_refusal(exc)
      assert_equal [status, code], [got_status, got_code], exc.class.name
      assert message && message.ascii_only?, "a wire-visible message stays ASCII"
    end
  end

  def test_framing_refusal_separates_owed_from_ended
    # Which read failures are owed a frame at all. A closed or reset socket is not a
    # refusal of anything and there is nobody left to answer.
    assert Wire.framing_refusal?(PayloadTooLargeError.new("x"))
    assert Wire.framing_refusal?(TruncatedFrameError.new("x"))
    refute Wire.framing_refusal?(ConnectionBrokenError.new("closed"))
    refute Wire.framing_refusal?(TransportError.new("reset"))
  end

  # ── 2. read_frame: a close at a frame boundary is not a refusal ──────────────

  # A socket-shaped reader over a fixed byte string, so read_frame can be driven
  # without a listener. `read` answering nil is the close.
  class Chunks
    def initialize(data) = @data = data

    def read(n)
      return nil if @data.empty?

      chunk = @data[0, n]
      @data = @data[chunk.bytesize..] || "".b
      chunk
    end
  end

  def test_read_frame_distinguishes_close_from_truncation
    # A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a
    # stream that ends MID-FRAME is a §4.11 framing refusal and is owed a coded frame.
    # Both surface as a short read, so the distinction can only be made where the
    # frame boundary is known — and getting it wrong in the other direction would
    # answer 400 to every peer that simply hangs up.
    assert_nil Wire.read_frame(Chunks.new("".b))
    assert_raises(TruncatedFrameError) { Wire.read_frame(Chunks.new("\x00\x00".b)) }
    assert_raises(TruncatedFrameError) { Wire.read_frame(Chunks.new("\x00\x00\x10\x00\xa1".b)) }
    assert_raises(PayloadTooLargeError) { Wire.read_frame(Chunks.new("\x02\x00\x00\x00".b)) }
    # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
    # refused there as bytes that never become an Envelope.
    assert_equal "".b, Wire.read_frame(Chunks.new("\x00\x00\x00\x00".b))
  end

  # ── 3. The decode boundary: the two causes arrive as DIFFERENT exceptions ────

  def good_entity = Entity.make("primitive/any", { "x" => 1 })

  def root_execute
    Wire.make_execute("t1", "system/tree", "get", Wire.empty_params)
  end

  def test_decode_boundary_cause_split
    # Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of
    # these, which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed
    # `included` entry carries NO TAG, its encoding is canonical, and *re-encode* is
    # not the caller's remedy.
    good = good_entity

    # (a) MIS-KEYED included entry -> resolution integrity.
    mis_keyed = { "root" => root_execute.to_cbor,
                  "included" => { ("\x11".b * 33) => good.to_cbor } }
    assert_raises(HashMismatchError) { Envelope.from_cbor(mis_keyed) }

    # (b) A CORRECTLY keyed entry whose entity carries a wrong content_hash is the
    # same class (§1.8 item 1) and takes the same code.
    assert_raises(HashMismatchError) do
      Entity.from_cbor({ "type" => good.type, "data" => good.data,
                         "content_hash" => ("\x22".b * 33) })
    end

    # (c) STRUCTURAL faults stay a bare ProtocolError -> invalid_request. THIS IS THE
    # DISCRIMINATOR: HashMismatchError subclasses ProtocolError, so if both causes
    # collapsed into one type the split above would pass vacuously — the test has to
    # assert the NEGATIVE direction too.
    [{ "data" => 1 }, { "type" => 7, "data" => 1 }, { "type" => "primitive/any" }].each do |bad|
      e = assert_raises(ProtocolError) { Entity.from_cbor(bad) }
      refute_kind_of HashMismatchError, e, bad.inspect
    end
    e = assert_raises(ProtocolError) { Envelope.from_cbor({ "nope" => 1 }) }
    refute_kind_of HashMismatchError, e

    # (d) And the WELL-FORMED envelope must still decode, or every case above is
    # satisfied by a decoder that refuses everything.
    env = Envelope.from_cbor({ "root" => root_execute.to_cbor,
                               "included" => { good.content_hash => good.to_cbor } })
    refute_nil env.included_get(good.content_hash)
  end

  def test_tag_is_the_only_non_canonical_ecf
    # ENTITY-CBOR-ENCODING §6.3 is the sole definition of that code in the corpus and
    # assigns it to a major-type-6 item in a data-field position. Everything else this
    # decoder calls non-canonical is §4.11's framing arm.
    assert_raises(TagRejectedError) { Cbor.decode("\xc1\x00".b) } # tag 1 over a uint
    non_tag = assert_raises(NonCanonicalError) { Cbor.decode("\x18\x01".b) } # non-minimal head
    refute_kind_of TagRejectedError, non_tag
    assert_equal "invalid_request", Wire.pre_admission_refusal(non_tag)[1]
  end

  # ── 4. Over the wire: the frame obligation, with a positive control per run ──

  def framed(payload) = [payload.bytesize].pack("N") + payload

  # A well-formed EXECUTE the peer MUST answer 200 — the positive control.
  def hello_frame
    ident = Identity.of_seed(("\x2a".chr * 32).b)
    hello = Entity.make("system/protocol/connect/hello", {
                          "peer_id" => ident.peer_id,
                          "nonce" => ("\x01".b * 32),
                          "protocols" => ["entity-core/1.0"],
                          "timestamp" => 1,
                          "hash_formats" => ["ecfv1-sha256"],
                          "key_types" => ["ed25519"]
                        })
    env = Envelope.new(Wire.make_execute("ctl-1", "system/protocol/connect", "hello", hello))
    framed(Wire.frame_of_envelope(env))
  end

  # A frame whose ONLY defect is a CBOR tag inside an entity's `data` map.
  #
  # Hand-spliced, because this peer's encoder cannot emit a tag by construction — AND
  # THE SPLICE IS ASSERTED. A mutation that is not verified to have landed is not a
  # mutation: an unverified splice leaves the frame perfectly well-formed, the peer
  # answers something correct to a question this test is not asking, and that reads as
  # a peer that does not implement the branch.
  def tagged_execute_payload
    root = Entity.make("system/protocol/execute", {
                         "request_id" => "tag-1", "uri" => "system/tree", "operation" => "get",
                         "params" => Wire.empty_params.to_cbor, "extra" => 0
                       })
    payload = Cbor.encode({ "root" => root.to_cbor })
    marker = "\x65extra\x00".b # text(5) "extra", then uint 0
    assert_equal 1, payload.scan(marker).length,
                 "the splice target moved; the mutation is not a mutation"
    tagged = payload.sub(marker, "\x65extra\xc1\x00".b) # 0xc1 = tag 1
    refute_equal payload, tagged
    assert_raises(TagRejectedError) { Cbor.decode(tagged) }
    tagged
  end

  # Send `frames` on one connection and read `expect` responses.
  #
  # A missing response is the §4.11 silent drop and shows up as a socket timeout,
  # which is the failure this whole file exists to catch — so it is raised, never
  # swallowed.
  # THE DEADLINE IS THE ASSERTION, not a convenience. §4.11's silent drop produces NO
  # response, and `IO#read` on a TCPSocket retries through EAGAIN rather than honouring
  # SO_RCVTIMEO — so without `Timeout.timeout` a dropped frame HANGS the suite instead
  # of failing it, and a hung test is strictly worse than a red one: it reports nothing
  # and blocks everything behind it. Measured the hard way while planting.
  READ_DEADLINE_S = 5

  def drive(frames, expect, port)
    s = TCPSocket.new("127.0.0.1", port)
    begin
      frames.each { |f| s.write(f) }
      s.flush
      Timeout.timeout(READ_DEADLINE_S, Timeout::Error, "no response: the frame was DROPPED (section 4.11)") do
        Array.new(expect) do
          env = Wire.envelope_of_frame(Wire.read_frame(s))
          res = Wire.response_result(env)
          [Wire.response_status(env), res ? (res.text("code") || "") : "",
           env.root.text("request_id") || ""]
        end
      end
    ensure
      s.close
    end
  end

  # One framed response off a raw socket, under the same deadline.
  def read_one(s)
    Timeout.timeout(READ_DEADLINE_S, Timeout::Error, "no response: the frame was DROPPED (section 4.11)") do
      Wire.envelope_of_frame(Wire.read_frame(s))
    end
  end

  def with_peer
    peer = Peer.create(LOCAL_SEED)
    listener = Transport.start_listener(peer, 0)
    begin
      yield listener.port
    ensure
      listener.close
    end
  end

  def test_positive_control_answers_200
    # The control on its own, first. If this ever fails, nothing below is a reading
    # about the peer — it is a reading about this file.
    with_peer { |port| assert_equal [[200, "", "ctl-1"]], drive([hello_frame], 1, port) }
  end

  def test_correlated_refusals_keep_the_connection_serving
    # A COMPLETE frame the decoder refused: the framing is intact, so the peer answers
    # and KEEPS SERVING. Each refusal is followed by the control on the SAME
    # connection — the differential that says the answer was a refusal of the FRAME and
    # not the connection collapsing.
    good = good_entity
    mis_keyed = framed(Cbor.encode({ "root" => root_execute.to_cbor,
                                     "included" => { ("\x11".b * 33) => good.to_cbor } }))
    tagged = framed(tagged_execute_payload)
    # A root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
    # (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and NOT the silent drop
    # this peer used to answer it with.
    other_root = framed(Wire.frame_of_envelope(
                          Envelope.new(Entity.make("primitive/any", { "request_id" => "x-1" }))
                        ))
    with_peer do |port|
      got = drive([mis_keyed, tagged, other_root, hello_frame], 4, port)
      assert_equal [400, "hash_mismatch", "t1"], got[0]
      assert_equal [400, "non_canonical_ecf", "tag-1"], got[1]
      assert_equal [400, "invalid_request", "x-1"], got[2]
      assert_equal [200, "", "ctl-1"], got[3],
                   "the connection is still serving after three refusals"
    end
  end

  def test_uncorrelated_refusals_are_best_effort_frames
    # Where no `request_id` can be recovered, §4.11 prescribes "a best-effort coded
    # frame carrying no correlation" — an empty `request_id` IS that form. Guessing one
    # would correlate the refusal to somebody else's in-flight request.
    not_an_envelope = framed(Cbor.encode({ "nope" => 1 }))
    garbage = framed("\xff\xff\xff\xff".b)
    with_peer do |port|
      got = drive([not_an_envelope, garbage, hello_frame], 3, port)
      assert_equal [400, "invalid_request", ""], got[0]
      assert_equal [400, "invalid_request", ""], got[1]
      assert_equal [200, "", "ctl-1"], got[2], "the connection is still serving"
    end
  end

  def test_oversize_frame_is_answered_before_the_close
    # §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the length
    # prefix with the connection intact and nothing spent, so the 413 goes out FIRST
    # and the close comes after — the close is now IN ADDITION to the frame, not
    # instead of it. The peer's own listener is the control: it keeps serving other
    # connections.
    with_peer do |port|
      s = TCPSocket.new("127.0.0.1", port)
      begin
        s.write([Wire::MAX_FRAME + 1].pack("N")) # prefix only; no body ever sent
        s.flush
        env = read_one(s)
        assert_equal 413, Wire.response_status(env)
        assert_equal "payload_too_large", Wire.response_result(env).text("code")
        assert_equal "", env.root.text("request_id"), "no id was ever readable: best-effort"
      ensure
        s.close
      end
      assert_equal [[200, "", "ctl-1"]], drive([hello_frame], 1, port),
                   "the listener survived the refusal"
    end
  end

  def test_truncated_frame_is_answered
    # A length prefix that never completes — §4.11's framing arm names this input
    # outright. The write side is shut down so the peer sees EOF mid-frame rather than
    # an idle connection; the ordinary-hangup arm is covered at the unit level above.
    with_peer do |port|
      s = TCPSocket.new("127.0.0.1", port)
      begin
        s.write([4096].pack("N") + "\xa1".b) # declared 4096, sent 1
        s.flush
        s.close_write
        env = read_one(s)
        assert_equal 400, Wire.response_status(env)
        assert_equal "invalid_request", Wire.response_result(env).text("code")
      ensure
        s.close
      end
      assert_equal [[200, "", "ctl-1"]], drive([hello_frame], 1, port)
    end
  end

  def test_a_refusal_is_never_silence
    # The class obligation, stated once as its own assertion rather than inferred from
    # the rows above: EVERY pre-admission cause puts a frame on the wire.
    #
    # Dropping is §4.11's other non-conformant behaviour and is "the weaker of the two
    # precisely because nothing surfaces it" — a `next` with no write looks exactly
    # like a peer that is merely slow, and the caller learns nothing until its own
    # §6.11(c) deadline. A timeout here IS that failure.
    causes = [
      framed(Cbor.encode({ "nope" => 1 })),
      framed("\xff\xff\xff\xff".b),
      framed("".b),
      framed(Wire.frame_of_envelope(Envelope.new(Entity.make("primitive/any", {}))))
    ]
    assert_equal 4, causes.length
    with_peer do |port|
      got = drive(causes, causes.length, port)
      assert_equal 4, got.length
      got.each do |status, code, _|
        assert_equal 400, status
        refute_empty code, "every pre-admission refusal is coded, none is silence"
      end
    end
  end
end
