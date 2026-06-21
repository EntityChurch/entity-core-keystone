defmodule EntityCore.ReentryTest do
  @moduledoc """
  F2 / §6.11 reentry primitive over a real `EntityCore.Connection` process and a
  live socket pair (the Elixir twin of the OCaml `selftest.ml` socketpair test).
  Proves the demux end-to-end: a dispatch process writes an outbound EXECUTE via
  `Connection.outbound/2`, the reader routes the correlated EXECUTE_RESPONSE back
  by `request_id`, and the awaiting caller unblocks — without the reader stalling
  (§4.8). This is the machinery the §6.13(b) handler-facing outbound closure rides.
  """
  use ExUnit.Case, async: false

  alias EntityCore.{Connection, Model, Peer, Transport, Wire}
  alias EntityCore.Model.Envelope

  @seed :binary.copy(<<0x11>>, 32)

  test "outbound reentry round-trips the correlated response" do
    # A connected socket pair: server_sock is owned by the Connection process;
    # client_sock plays the reentry "remote".
    {:ok, lsock, port} = Transport.listen(0)
    {:ok, client_sock} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false, packet: :raw], 5000)
    {:ok, server_sock} = :gen_tcp.accept(lsock, 5000)
    :gen_tcp.close(lsock)

    peer = Peer.create(@seed)
    {:ok, conn_pid} = Connection.start(peer, server_sock)
    :ok = :gen_tcp.controlling_process(server_sock, conn_pid)
    Connection.activate(conn_pid)

    # The remote: read the outbound EXECUTE, echo a 200 with the same request_id.
    spawn(fn ->
      {:ok, <<len::32-big>>} = :gen_tcp.recv(client_sock, 4, 5000)
      {:ok, payload} = :gen_tcp.recv(client_sock, len, 5000)
      env = Wire.envelope_of_frame(payload)
      rid = Model.text_field(env.root, "request_id")
      resp = %Envelope{root: Wire.make_response(rid, 200, Wire.empty_params()), included: %{}}
      :gen_tcp.send(client_sock, Wire.encode_frame(Wire.frame_of_envelope(resp)))
    end)

    zero33 = :binary.copy(<<0>>, 33)

    req =
      Wire.make_execute(
        request_id: "out-1",
        uri: "system/tree",
        operation: "get",
        params: Wire.empty_params(),
        author: zero33,
        capability: zero33
      )

    # Originate from a separate process (the dispatch worker), as §6.13(b) does.
    task = Task.async(fn -> Connection.outbound(conn_pid, %Envelope{root: req, included: %{}}) end)
    response = Task.await(task, 5000)

    assert response != nil
    assert Model.text_field(response.root, "request_id") == "out-1"
    assert Model.uint_field(response.root, "status") == 200

    :gen_tcp.close(client_sock)
  end
end
