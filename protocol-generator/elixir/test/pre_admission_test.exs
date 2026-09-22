defmodule EntityCore.PreAdmissionTest do
  @moduledoc """
  §4.11 pre-admission refusals (0.8.2.25) — classification AND emission.

  §4.11's rule has two halves and they fail differently.

    * *"The frame obligation belongs to the class"* is WIRE-VISIBLE, and the two
      non-conformant behaviours it names are distinct: DROPPING the frame (no response,
      no close — *"the weaker of the two precisely because nothing surfaces it"*) and
      CLOSING WITH NO CODED FRAME (indistinguishable from a network fault, and on a
      multiplexed connection it destroys unrelated ADMITTED requests). This peer had
      BOTH before 0.8.2.25: the un-salvageable decode arm and the non-EXECUTE root
      dropped; the oversize arm closed bare.
    * *"The CODE belongs to the cause `[MUST]`"* is a MAPPING, and a mapping is exactly
      the thing that regresses silently when a new failure joins an existing branch.

  So both halves are covered here: the mapping at the unit level, and the emission over
  a real socket, because a green mapping over a transport that never calls it is the
  `check_path_permission` shape all over again.

  THE PINNED CHECK SET (778) HAS NO VECTOR ON THIS SURFACE, which is why the coverage is
  authored here rather than inherited.

  EVERY SOCKET CASE CARRIES A POSITIVE CONTROL in the same connection or the same run. A
  probe fails in the direction of the answer it is looking for: a malformed frame that is
  malformed in a SECOND way answers the code under measurement for the wrong reason, and
  without the control that publishes as a peer finding.
  """
  use ExUnit.Case, async: false

  alias EntityCore.{Cbor, Connection, Identity, Model, Peer, Transport, Wire}
  alias EntityCore.Model.Envelope

  @seed :binary.copy(<<0x7B>>, 32)

  # THE DEADLINE IS THE ASSERTION, not a convenience: §4.11's silent drop produces NO
  # response, so a dropped frame must SURFACE as a failure rather than hang the suite.
  @deadline 5000

  # ── 1. The mapping: §4.11's table, one row at a time ───────────────────────

  test "the pre-admission code is the CAUSE's" do
    rows = [
      # §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
      # non_canonical_ecf NON-CONFORMANT here.
      {%Model.HashMismatch{message: "x"}, 400, "hash_mismatch"},
      # ENTITY-CBOR-ENCODING §6.3 — the tag-policy arm keeps its own code.
      {%EntityCore.Error{kind: :non_canonical_ecf, detail: :cbor_tag}, 400, "non_canonical_ecf"},
      # §4.7 / §4.11 framing arm: bytes that never become an Envelope.
      {%Model.BadEntity{message: "x"}, 400, "invalid_request"},
      {%EntityCore.Error{kind: :truncated, detail: nil}, 400, "invalid_request"},
      # The one that makes the DETAIL discriminator load-bearing: an indefinite length is
      # "non-canonical CBOR" by KIND and is NOT the tag-policy arm.
      {%EntityCore.Error{kind: :non_canonical_ecf, detail: {:bad_argument, 31}}, 400,
       "invalid_request"}
    ]

    assert length(rows) == 5, "examined-N, not merely `no failures`"

    for {e, status, code} <- rows do
      {got_status, got_code, message} = Wire.pre_admission_refusal(e)
      assert {got_status, got_code} == {status, code}, inspect(e)
      assert String.valid?(message) and message == for(<<c <- message>>, c < 128, into: "", do: <<c>>),
             "a wire-visible message stays ASCII"
    end

    # The two arms that are not exceptions but fixed rows, asserted so the table is
    # complete rather than partly implied by the socket cases below.
    assert Wire.oversize_refusal() |> elem(0) == 413
    assert Wire.oversize_refusal() |> elem(1) == "payload_too_large"
    assert Wire.truncated_refusal() == {400, "invalid_request", "frame did not decode into an envelope"}
  end

  test "the tag discriminator is the DETAIL, pinned at its raise site" do
    # `ENTITY-CBOR-ENCODING` §6.3 is the sole definition of `non_canonical_ecf` in the
    # corpus and assigns it to a major-type-6 item in a data-field position. Everything
    # else this decoder calls non-canonical is §4.11's framing arm — and on this
    # substrate both arrive as the same `kind`, so the DETAIL is what separates them.
    assert {:error, %EntityCore.Error{kind: :non_canonical_ecf, detail: :cbor_tag}} =
             Cbor.decode(<<0xC1, 0x00>>)

    # An INDEFINITE-LENGTH array head: the same `kind`, a different `detail`, and
    # §4.11's framing arm rather than the tag-policy one.
    {:error, non_tag} = Cbor.decode(<<0x9F>>)
    assert non_tag.kind == :non_canonical_ecf and non_tag.detail != :cbor_tag
    assert Wire.pre_admission_refusal(non_tag) |> elem(1) == "invalid_request"
  end

  @tag :skip
  test "OUT OF SCOPE, RECORDED RATHER THAN FIXED: a non-minimal argument head decodes" do
    # `<<0x18, 0x01>>` is a uint8-argument head carrying the value 1, which the canonical
    # form encodes in the head byte itself. `Cbor.arg/2` accepts every well-formed head
    # width without comparing the decoded value to the minimal one, so this peer's strict
    # decoder answers `{:ok, 1}` where the sibling `ruby`, `python` and `go` peers refuse.
    #
    # FOUND BY THIS FILE AND DELIBERATELY NOT FIXED HERE. It is a CODEC change, outside
    # RULES A-G's scope, with an unmeasured blast radius on the S2 corpus (71/71 today)
    # and on S4; smoothing it into a §4.11 sweep would bury it. Recorded as a skipped
    # case so that it is a DECISION and not a drift, and so the next reader finds the
    # exact input.
    assert {:error, _} = Cbor.decode(<<0x18, 0x01>>)
  end

  # ── 2. The decode boundary: the causes arrive as DIFFERENT exceptions ──────

  defp good_entity, do: Model.make("primitive/any", %{"x" => 1})

  defp root_execute do
    Model.make("system/protocol/execute", %{
      "request_id" => "t1",
      "uri" => "system/tree",
      "operation" => "get",
      "params" => Model.to_cbor(Wire.empty_params())
    })
  end

  test "the decode boundary splits resolution integrity from structure" do
    # Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of these,
    # which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed `included`
    # entry carries NO TAG, its encoding is canonical, and *re-encode* is not the
    # caller's remedy.
    good = good_entity()

    # (a) MIS-KEYED included entry -> resolution integrity.
    assert_raise Model.HashMismatch, fn ->
      Model.envelope_of_cbor(%{
        "root" => Model.to_cbor(root_execute()),
        "included" => %{{:bytes, :binary.copy(<<0x11>>, 33)} => Model.to_cbor(good)}
      })
    end

    # (b) A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
    # class (§1.8 item 1) and takes the same code.
    assert_raise Model.HashMismatch, fn ->
      Model.of_cbor(%{
        "type" => good.type,
        "data" => good.data,
        "content_hash" => {:bytes, :binary.copy(<<0x22>>, 33)}
      })
    end

    # (c) STRUCTURAL faults stay `BadEntity` -> invalid_request. THIS IS THE
    # DISCRIMINATOR: if both causes were one exception the split above would pass
    # vacuously, so the NEGATIVE direction is asserted too.
    for bad <- [%{"data" => 1}, %{"type" => 7, "data" => 1}, %{"type" => "primitive/any"}] do
      assert_raise Model.BadEntity, fn -> Model.of_cbor(bad) end
    end

    assert_raise Model.BadEntity, fn -> Model.envelope_of_cbor(%{"nope" => 1}) end

    # (d) And the WELL-FORMED envelope must still decode, or every case above is
    # satisfied by a decoder that refuses everything.
    env =
      Model.envelope_of_cbor(%{
        "root" => Model.to_cbor(root_execute()),
        "included" => %{{:bytes, good.hash} => Model.to_cbor(good)}
      })

    assert Model.included_get(env, good.hash) != nil
  end

  # ── 3. Over the wire: the frame obligation, with a positive control ────────

  defp framed(payload), do: <<byte_size(payload)::32-big, payload::binary>>

  # A well-formed EXECUTE the peer MUST answer 200 — the positive control.
  defp hello_frame do
    ident = Identity.of_seed(:binary.copy(<<0x2A>>, 32))

    hello =
      Model.make("system/protocol/connect/hello", %{
        "peer_id" => ident.peer_id,
        "nonce" => {:bytes, :binary.copy(<<0x01>>, 32)},
        "protocols" => ["entity-core/1.0"],
        "timestamp" => 1,
        "hash_formats" => ["ecfv1-sha256"],
        "key_types" => ["ed25519"]
      })

    root =
      Model.make("system/protocol/execute", %{
        "request_id" => "ctl-1",
        "uri" => "system/protocol/connect",
        "operation" => "hello",
        "params" => Model.to_cbor(hello)
      })

    framed(Wire.frame_of_envelope(%Envelope{root: root, included: %{}}))
  end

  # A frame whose ONLY defect is a CBOR tag inside an entity's `data` map.
  #
  # Hand-spliced, because this peer's encoder cannot emit a tag by construction — AND
  # THE SPLICE IS ASSERTED. A mutation that is not verified to have landed is not a
  # mutation: an unverified splice leaves the frame perfectly well-formed, the peer
  # answers something correct to a question this test is not asking, and that reads as a
  # peer that does not implement the branch.
  defp tagged_execute_payload do
    root =
      Model.make("system/protocol/execute", %{
        "request_id" => "tag-1",
        "uri" => "system/tree",
        "operation" => "get",
        "params" => Model.to_cbor(Wire.empty_params()),
        "extra" => 0
      })

    payload = Cbor.encode(%{"root" => Model.to_cbor(root)})
    marker = <<0x65, "extra", 0x00>>
    assert length(:binary.matches(payload, marker)) == 1,
           "the splice target moved; the mutation is not a mutation"

    tagged = :binary.replace(payload, marker, <<0x65, "extra", 0xC1, 0x00>>, [])
    assert tagged != payload
    assert {:error, %EntityCore.Error{detail: :cbor_tag}} = Cbor.decode(tagged)
    tagged
  end

  defp with_peer(fun) do
    peer = Peer.create(@seed)
    {:ok, lsock, port} = Transport.listen(0)

    acceptor =
      spawn_link(fn ->
        accept = fn accept ->
          case :gen_tcp.accept(lsock) do
            {:ok, sock} ->
              {:ok, pid} = Connection.start(peer, sock)
              :ok = :gen_tcp.controlling_process(sock, pid)
              Connection.activate(pid)
              accept.(accept)

            {:error, _} ->
              :ok
          end
        end

        accept.(accept)
      end)

    try do
      fun.(port)
    after
      :gen_tcp.close(lsock)
      Process.unlink(acceptor)
      Process.exit(acceptor, :kill)
    end
  end

  defp connect(port) do
    {:ok, s} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false, packet: :raw], 5000)
    s
  end

  # One framed response, under the deadline. A `:timeout` here IS §4.11's silent drop.
  defp read_one(s) do
    case :gen_tcp.recv(s, 4, @deadline) do
      {:ok, <<len::32-big>>} ->
        {:ok, payload} = :gen_tcp.recv(s, len, @deadline)
        env = Wire.envelope_of_frame(payload)
        res = Model.map_get(Model.field(env.root, "result"), "data")

        {Model.uint_field(env.root, "status"), Model.map_get(res, "code") || "",
         Model.text_field(env.root, "request_id") || ""}

      other ->
        flunk("no response: the frame was DROPPED (section 4.11) — #{inspect(other)}")
    end
  end

  defp drive(frames, expect, port) do
    s = connect(port)

    try do
      for f <- frames, do: :ok = :gen_tcp.send(s, f)
      Enum.map(1..expect, fn _ -> read_one(s) end)
    after
      :gen_tcp.close(s)
    end
  end

  test "the positive control answers 200" do
    # The control on its own, first. If this ever fails, nothing below is a reading about
    # the peer — it is a reading about this file.
    with_peer(fn port -> assert drive([hello_frame()], 1, port) == [{200, "", "ctl-1"}] end)
  end

  test "correlated refusals keep the connection serving" do
    # A COMPLETE frame the decoder refused: the framing is intact, so the peer answers
    # and KEEPS SERVING. Each refusal is followed by the control on the SAME connection —
    # the differential that says the answer was a refusal of the FRAME and not the
    # connection collapsing.
    good = good_entity()

    mis_keyed =
      framed(
        Cbor.encode(%{
          "root" => Model.to_cbor(root_execute()),
          "included" => %{{:bytes, :binary.copy(<<0x11>>, 33)} => Model.to_cbor(good)}
        })
      )

    tagged = framed(tagged_execute_payload())

    # A root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
    # (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and NOT the silent drop this
    # peer used to answer it with.
    other_root =
      framed(
        Wire.frame_of_envelope(%Envelope{
          root: Model.make("primitive/any", %{"request_id" => "x-1"}),
          included: %{}
        })
      )

    with_peer(fn port ->
      # KEYED BY `request_id`, NOT BY ARRIVAL ORDER, and the reason is a real property of
      # this substrate rather than test hygiene: §4.8 dispatches an inbound EXECUTE on
      # its OWN process while the connect path is handled INLINE in the connection
      # process, so a spawned refusal can legitimately land after a later inline
      # response. §6.11 correlates by `request_id` for exactly that reason; asserting on
      # position would be asserting something the protocol does not promise.
      by_id =
        drive([mis_keyed, tagged, other_root, hello_frame()], 4, port)
        |> Map.new(fn {status, code, rid} -> {rid, {status, code}} end)

      assert map_size(by_id) == 4, "four frames, four correlated answers"
      assert by_id["t1"] == {400, "hash_mismatch"}
      assert by_id["tag-1"] == {400, "non_canonical_ecf"}
      assert by_id["x-1"] == {400, "invalid_request"}
      assert by_id["ctl-1"] == {200, ""}, "the connection is still serving after three refusals"
    end)
  end

  test "uncorrelated refusals are best-effort frames" do
    # Where no `request_id` can be recovered, §4.11 prescribes *"a best-effort coded
    # frame carrying no correlation"* — an empty `request_id` IS that form. Guessing one
    # would correlate the refusal to somebody else's in-flight request.
    not_an_envelope = framed(Cbor.encode(%{"nope" => 1}))
    garbage = framed(<<0xFF, 0xFF, 0xFF, 0xFF>>)

    with_peer(fn port ->
      got = drive([not_an_envelope, garbage, hello_frame()], 3, port)
      assert Enum.count(got, fn r -> r == {400, "invalid_request", ""} end) == 2
      assert {200, "", "ctl-1"} in got, "the connection is still serving"
    end)
  end

  test "an oversize frame is ANSWERED before the close" do
    # §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the length
    # prefix with the connection intact and nothing spent, so the 413 goes out FIRST and
    # the close comes after — the close is now IN ADDITION to the frame, not instead of
    # it. The peer's own listener is the control: it keeps serving other connections.
    with_peer(fn port ->
      s = connect(port)

      try do
        :ok = :gen_tcp.send(s, <<Wire.max_frame() + 1::32-big>>)
        assert read_one(s) == {413, "payload_too_large", ""}
      after
        :gen_tcp.close(s)
      end

      assert drive([hello_frame()], 1, port) == [{200, "", "ctl-1"}],
             "the listener survived the refusal"
    end)
  end

  test "a truncated frame is ANSWERED" do
    # A length prefix that never completes — §4.11's framing arm names this input
    # outright. The write side is shut down so the peer sees EOF mid-frame rather than an
    # idle connection.
    #
    # THIS CASE IS ALSO THE `exit_on_close: false` GATE. Under `:gen_tcp`'s default the
    # runtime closes our write side the instant the client's FIN arrives, so the peer
    # CANNOT answer and this test fails with no line of `Connection` being wrong.
    with_peer(fn port ->
      s = connect(port)

      try do
        :ok = :gen_tcp.send(s, <<4096::32-big, 0xA1>>)
        :ok = :gen_tcp.shutdown(s, :write)
        assert read_one(s) == {400, "invalid_request", ""}
      after
        :gen_tcp.close(s)
      end

      assert drive([hello_frame()], 1, port) == [{200, "", "ctl-1"}]
    end)
  end

  test "a refusal is NEVER silence" do
    # The class obligation, stated once as its own assertion rather than inferred from
    # the rows above: EVERY pre-admission cause puts a frame on the wire.
    #
    # Dropping is §4.11's other non-conformant behaviour and is *"the weaker of the two
    # precisely because nothing surfaces it"* — a `_ -> st` with no write looks exactly
    # like a peer that is merely slow, and the caller learns nothing until its own
    # §6.11(c) deadline. A timeout here IS that failure.
    causes = [
      framed(Cbor.encode(%{"nope" => 1})),
      framed(<<0xFF, 0xFF, 0xFF, 0xFF>>),
      framed(<<>>),
      framed(
        Wire.frame_of_envelope(%Envelope{
          root: Model.make("primitive/any", %{}),
          included: %{}
        })
      )
    ]

    assert length(causes) == 4

    with_peer(fn port ->
      got = drive(causes, length(causes), port)
      assert length(got) == 4

      for {status, code, _} <- got do
        assert status == 400
        assert code != "", "every pre-admission refusal is coded, none is silence"
      end
    end)
  end
end
