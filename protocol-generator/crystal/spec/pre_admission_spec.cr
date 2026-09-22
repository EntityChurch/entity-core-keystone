require "./spec_helper"
require "socket"

# §4.11 pre-admission refusals (0.8.2.25) — classification AND emission.
#
# §4.11's rule has two halves and they fail differently.
#
#   * "The frame obligation belongs to the class" is WIRE-VISIBLE, and the two
#     non-conformant behaviours it names are distinct: DROPPING the frame (no
#     response, no close — "the weaker of the two precisely because nothing surfaces
#     it") and CLOSING WITH NO CODED FRAME (indistinguishable from a network fault,
#     and on a multiplexed connection it destroys unrelated ADMITTED requests). This
#     peer had BOTH before 0.8.2.25: the un-salvageable decode arm and the
#     non-EXECUTE root dropped, the oversize and truncated arms closed bare.
#   * "The CODE belongs to the cause [MUST]" is a MAPPING, and a mapping is exactly
#     the thing that regresses silently when a new failure joins an existing branch.
#
# So both halves are covered here: the mapping at the unit level, and the emission
# over a real socket, because a green mapping over a transport that never calls it
# is the `check_path_permission` shape all over again.
#
# THE PINNED CHECK SET (778) HAS NO VECTOR ON THIS SURFACE, which is why the
# coverage is authored here rather than inherited.
#
# EVERY SOCKET CASE CARRIES A POSITIVE CONTROL in the same connection or the same
# run. A probe fails in the direction of the answer it is looking for: a malformed
# frame that is malformed in a SECOND way answers the code under measurement for the
# wrong reason, and without the control that publishes as a peer finding.
#
# THE READ DEADLINE IS AN ASSERTION, NOT A CONVENIENCE. §4.11's non-conformant
# behaviour is NO RESPONSE, so a socket read with no deadline HANGS on the defect
# instead of failing on it — and a hung spec is strictly worse than a red one: it
# reports nothing and blocks everything behind it. `read_timeout` on a Crystal
# TCPSocket raises IO::TimeoutError, which is the failure this file exists to catch.
include EntityCore

private READ_DEADLINE = 5.seconds

private def framed(payload : Bytes) : Bytes
  buf = Bytes.new(payload.size + 4)
  len = payload.size.to_u32
  buf[0] = ((len >> 24) & 0xFF).to_u8
  buf[1] = ((len >> 16) & 0xFF).to_u8
  buf[2] = ((len >> 8) & 0xFF).to_u8
  buf[3] = (len & 0xFF).to_u8
  payload.copy_to(buf.to_unsafe + 4, payload.size)
  buf
end

# A well-formed EXECUTE the peer MUST answer 200 — the positive control.
private def hello_frame : Bytes
  ident = Identity.of_seed(Bytes.new(32) { 0x2a_u8 })
  hello = Entity.build("system/protocol/connect/hello", {
    "peer_id"      => ident.peer_id,
    "nonce"        => Bytes.new(32) { 0x01_u8 },
    "protocols"    => ["entity-core/1.0"],
    "timestamp"    => 1,
    "hash_formats" => ["ecfv1-sha256"],
    "key_types"    => ["ed25519"],
  })
  env = Envelope.of(Wire.make_execute("ctl-1", "system/protocol/connect", "hello", hello))
  framed(Wire.frame_of_envelope(env))
end

private def with_peer(&)
  peer = Peer.create(Bytes.new(32) { 0x7b_u8 }, open_grants: false, conformance: false)
  listener = Transport.start_listener(peer, 0)
  begin
    yield listener.port
  ensure
    listener.close
  end
end

# Send `frames` on ONE connection and read `expect` responses, each under the
# deadline. A missing response is the §4.11 silent drop.
private def drive(frames : Array(Bytes), expect : Int32, port : Int32) : Array(Tuple(UInt64, String, String))
  s = TCPSocket.new("127.0.0.1", port)
  s.read_timeout = READ_DEADLINE
  begin
    frames.each { |f| s.write(f) }
    s.flush
    Array.new(expect) do
      payload = Wire.read_frame(s)
      raise "no response: the frame was DROPPED (section 4.11)" if payload.nil?
      env = Wire.envelope_of_frame(payload)
      res = Wire.response_result(env)
      {Wire.response_status(env), res ? (res.text("code") || "") : "",
       env.root.text("request_id") || ""}
    end
  ensure
    s.close
  end
end

describe "section 4.11 — the CODE belongs to the CAUSE (0.8.2.25, section 5.2a)" do
  # The mapping, one row at a time. Before 0.8.2.24 this peer answered
  # `400 non_canonical_ecf` for every one of these, which is the
  # code-under-the-wrong-reason defect §5.2a names: a mis-keyed `included` entry
  # carries NO TAG, its encoding is canonical, and *re-encode* is not the caller's
  # remedy.
  rows = [
    # §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14).
    {PayloadTooLargeError.new("x").as(Exception), 413, "payload_too_large"},
    # §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
    # non_canonical_ecf NON-CONFORMANT here.
    {HashMismatchError.new("x").as(Exception), 400, "hash_mismatch"},
    # ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
    {TagRejectedError.new("x").as(Exception), 400, "non_canonical_ecf"},
    # §4.7 / §4.11 framing arm: bytes that never become an Envelope.
    {TruncatedFrameError.new("x").as(Exception), 400, "invalid_request"},
    {TruncatedError.new("x").as(Exception), 400, "invalid_request"},
    {ProtocolError.new("x").as(Exception), 400, "invalid_request"},
    # The row that makes the subclass ORDERING load-bearing: a non-minimal head is
    # "non-canonical CBOR" BY NAME and is NOT the tag-policy arm. Put
    # NonCanonicalError before TagRejectedError in the classifier and this row and
    # the one above it swap.
    {NonCanonicalError.new("x").as(Exception), 400, "invalid_request"},
  ]

  it "maps each cause to its own status and code" do
    rows.size.should eq(7) # examined-N, not merely "no failures"
    rows.each do |exc, status, code|
      got_status, got_code, message = Wire.pre_admission_refusal(exc)
      {got_status, got_code}.should eq({status, code})
      message.ascii_only?.should be_true # a wire-visible message stays ASCII
    end
  end
end

describe "section 4.11 — read_frame separates an ordinary close from a refusal" do
  # A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a
  # stream that ends MID-FRAME is a framing refusal and is owed a coded frame. Both
  # surface as a short read, so the distinction can only be made where the frame
  # boundary is known — and getting it wrong in the other direction would answer 400
  # to every peer that simply hangs up.

  it "answers nil for a clean close at a frame boundary" do
    Wire.read_frame(IO::Memory.new(Bytes.new(0))).should be_nil
  end

  it "raises TruncatedFrameError for a PARTIAL LENGTH PREFIX" do
    # The arm the vanguard's first driver had no case for: its "truncated frame"
    # case sent a COMPLETE 4-byte prefix, so truncation was caught in the body read
    # and the prefix discrimination had nothing driving it.
    expect_raises(TruncatedFrameError) { Wire.read_frame(IO::Memory.new(Bytes[0x00, 0x00])) }
  end

  it "raises TruncatedFrameError for a declared body that never arrives" do
    expect_raises(TruncatedFrameError) do
      Wire.read_frame(IO::Memory.new(Bytes[0x00, 0x00, 0x10, 0x00, 0xa1]))
    end
  end

  it "raises PayloadTooLargeError for an over-limit prefix" do
    expect_raises(PayloadTooLargeError) do
      Wire.read_frame(IO::Memory.new(Bytes[0x02, 0x00, 0x00, 0x00]))
    end
  end

  it "treats a ZERO-LENGTH frame as COMPLETE, not truncated" do
    # It reaches the decoder and is refused there as bytes that never become an
    # Envelope — a different arm with a different answer.
    Wire.read_frame(IO::Memory.new(Bytes[0x00, 0x00, 0x00, 0x00])).should eq(Bytes.new(0))
  end
end

describe "section 4.11 — the decode boundary raises the CAUSE's type" do
  good = Entity.build("primitive/any", {"x" => 1})

  it "raises HashMismatchError for a MIS-KEYED included entry" do
    # The arc-probe B1/B2 input. The entry's ENCODING is canonical; what is false is
    # the claim the KEY makes.
    payload = Cbor.encode(Cbor.coerce({
      "root"     => Wire.make_execute("t1", "system/tree", "get", Wire.empty_params).to_cbor,
      "included" => {Bytes.new(33) { 0x11_u8 } => good.to_cbor},
    }))
    expect_raises(HashMismatchError) { Wire.envelope_of_frame(payload) }
  end

  it "raises HashMismatchError for an entity whose carried content_hash does not bind" do
    m = good.to_cbor.as(::Hash(Cbor::EcValue, Cbor::EcValue)).dup
    m["content_hash"] = Bytes.new(33) { 0x22_u8 }
    expect_raises(HashMismatchError) { Entity.from_cbor(m) }
  end

  it "raises TagRejectedError for a CBOR tag in a data-field position" do
    # Hand-spliced, because this peer's encoder cannot emit a tag by construction —
    # AND THE SPLICE IS ASSERTED. A mutation that is not verified to have landed is
    # not a mutation: an unverified splice leaves the frame perfectly well-formed,
    # the peer answers something correct to a question this test is not asking, and
    # that reads as a peer that does not implement the branch.
    payload = SpecTagSplice.tagged_execute_payload
    expect_raises(TagRejectedError) { Cbor.decode(payload) }
  end
end

# The splice, factored out so the socket cases below drive the SAME bytes the unit
# case above asserted are a tag and nothing else.
module SpecTagSplice
  extend self

  def tagged_execute_payload : Bytes
    root = Entity.build("system/protocol/execute", {
      "request_id" => "tag-1", "uri" => "system/tree", "operation" => "get",
      "params" => Wire.empty_params.to_cbor, "extra" => 0,
    })
    payload = Cbor.encode(Cbor.coerce({"root" => root.to_cbor}))
    # text(5) "extra", then uint 0.
    marker = Bytes[0x65, 'e'.ord.to_u8, 'x'.ord.to_u8, 't'.ord.to_u8, 'r'.ord.to_u8, 'a'.ord.to_u8, 0x00]
    at = index_of(payload, marker)
    raise "the splice target moved; the mutation is not a mutation" if at.nil?
    raise "the splice target is ambiguous" unless index_of(payload, marker, at + 1).nil?
    buf = Bytes.new(payload.size + 1)
    payload[0, at].copy_to(buf.to_unsafe, at)
    # 0xc1 = tag 1, inserted in front of the uint 0 the marker ends with.
    (buf.to_unsafe + at).copy_from(marker.to_unsafe, marker.size - 1)
    buf[at + marker.size - 1] = 0xc1_u8
    buf[at + marker.size] = 0x00_u8
    rest = payload.size - (at + marker.size)
    (buf.to_unsafe + at + marker.size + 1).copy_from(payload.to_unsafe + at + marker.size, rest) if rest > 0
    buf
  end

  private def index_of(hay : Bytes, needle : Bytes, from = 0) : Int32?
    i = from
    while i + needle.size <= hay.size
      return i if hay[i, needle.size] == needle
      i += 1
    end
    nil
  end
end

describe "section 4.11 — the frame obligation, over a real socket" do
  it "answers 200 to the positive control on its own" do
    # The control FIRST. If this ever fails, nothing below is a reading about the
    # peer — it is a reading about this file.
    with_peer { |port| drive([hello_frame], 1, port).should eq([{200_u64, "", "ctl-1"}]) }
  end

  it "answers a COMPLETE refused frame and keeps serving, with the code of the cause" do
    # The framing is intact on all three, so the peer answers and KEEPS SERVING.
    # Each refusal is followed by the control on the SAME connection — the
    # differential that says the answer was a refusal of the FRAME and not the
    # connection collapsing.
    good = Entity.build("primitive/any", {"x" => 1})
    mis_keyed = framed(Cbor.encode(Cbor.coerce({
      "root"     => Wire.make_execute("t1", "system/tree", "get", Wire.empty_params).to_cbor,
      "included" => {Bytes.new(33) { 0x11_u8 } => good.to_cbor},
    })))
    tagged = framed(SpecTagSplice.tagged_execute_payload)
    # A root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
    # (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and NOT the silent drop
    # this peer used to answer it with.
    other_root = framed(Wire.frame_of_envelope(
      Envelope.of(Entity.build("primitive/any", {"request_id" => "x-1"}))))
    with_peer do |port|
      got = drive([mis_keyed, tagged, other_root, hello_frame], 4, port)
      got[0].should eq({400_u64, "hash_mismatch", "t1"})
      got[1].should eq({400_u64, "non_canonical_ecf", "tag-1"})
      got[2].should eq({400_u64, "invalid_request", "x-1"})
      # the connection is still serving after three refusals
      got[3].should eq({200_u64, "", "ctl-1"})
    end
  end

  it "answers an UNCORRELATED refusal as a best-effort frame with an empty request_id" do
    # Where no `request_id` can be recovered, §4.11 prescribes "a best-effort coded
    # frame carrying no correlation" — an empty `request_id` IS that form. Guessing
    # one would correlate the refusal to somebody else's in-flight request.
    not_an_envelope = framed(Cbor.encode(Cbor.coerce({"nope" => 1})))
    garbage = framed(Bytes[0xff, 0xff, 0xff, 0xff])
    with_peer do |port|
      got = drive([not_an_envelope, garbage, hello_frame], 3, port)
      got[0].should eq({400_u64, "invalid_request", ""})
      got[1].should eq({400_u64, "invalid_request", ""})
      got[2].should eq({200_u64, "", "ctl-1"})
    end
  end

  it "answers 413 BEFORE the close on an oversize prefix" do
    # §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the length
    # prefix with the connection intact and nothing spent, so the 413 goes out FIRST
    # and the close comes after — the close is now IN ADDITION to the frame, not
    # instead of it. The peer's own listener is the control: it keeps serving other
    # connections.
    with_peer do |port|
      s = TCPSocket.new("127.0.0.1", port)
      s.read_timeout = READ_DEADLINE
      begin
        big = Wire::MAX_FRAME + 1
        s.write(Bytes[((big >> 24) & 0xFF).to_u8, ((big >> 16) & 0xFF).to_u8,
                      ((big >> 8) & 0xFF).to_u8, (big & 0xFF).to_u8]) # prefix only, no body
        s.flush
        env = Wire.envelope_of_frame(Wire.read_frame(s).not_nil!)
        Wire.response_status(env).should eq(413_u64)
        Wire.response_result(env).not_nil!.text("code").should eq("payload_too_large")
        # no id was ever readable: the best-effort form
        env.root.text("request_id").should eq("")
      ensure
        s.close
      end
      # the listener survived the refusal
      drive([hello_frame], 1, port).should eq([{200_u64, "", "ctl-1"}])
    end
  end

  it "answers a TRUNCATED frame" do
    # A declared body that never arrives — §4.11's framing arm names this input
    # outright. The write side is shut down so the peer sees EOF mid-frame rather
    # than an idle connection; the ordinary-hangup arm is covered at the unit level
    # above.
    with_peer do |port|
      s = TCPSocket.new("127.0.0.1", port)
      s.read_timeout = READ_DEADLINE
      begin
        s.write(Bytes[0x00, 0x00, 0x10, 0x00, 0xa1]) # declared 4096, sent 1
        s.flush
        s.close_write
        env = Wire.envelope_of_frame(Wire.read_frame(s).not_nil!)
        Wire.response_status(env).should eq(400_u64)
        Wire.response_result(env).not_nil!.text("code").should eq("invalid_request")
      ensure
        s.close
      end
      drive([hello_frame], 1, port).should eq([{200_u64, "", "ctl-1"}])
    end
  end

  it "never answers a pre-admission refusal with SILENCE" do
    # The class obligation, stated once as its own assertion rather than inferred
    # from the rows above: EVERY pre-admission cause puts a frame on the wire.
    #
    # Dropping is §4.11's other non-conformant behaviour and is "the weaker of the
    # two precisely because nothing surfaces it" — a `next` with no write looks
    # exactly like a peer that is merely slow, and the caller learns nothing until
    # its own §6.11(c) deadline. A deadline expiry here IS that failure.
    causes = [
      framed(Cbor.encode(Cbor.coerce({"nope" => 1}))),
      framed(Bytes[0xff, 0xff, 0xff, 0xff]),
      framed(Bytes.new(0)),
      framed(Wire.frame_of_envelope(Envelope.of(Entity.build("primitive/any", {} of String => Int32)))),
    ]
    causes.size.should eq(4)
    with_peer do |port|
      got = drive(causes, causes.size, port)
      got.size.should eq(4)
      got.each do |status, code, _|
        status.should eq(400_u64)
        code.empty?.should be_false # every pre-admission refusal is coded, none is silence
      end
    end
  end
end
