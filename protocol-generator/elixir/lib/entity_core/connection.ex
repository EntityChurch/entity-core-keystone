defmodule EntityCore.Connection do
  @moduledoc """
  One BEAM process per connection (L4 / §4.8 / §6.11) — the actor-model placement
  of the OCaml reader-thread + mutex + condvar. The connection process owns the
  socket and is the SINGLE WRITER (responses and outbound requests both route
  through it, so writes serialize without a mutex). It demuxes inbound frames
  (§6.11): an EXECUTE_RESPONSE is routed to its awaiting outbound caller by
  `request_id`; an inbound EXECUTE is dispatched on a SEPARATE process (§4.8) so a
  handler that originates an outbound EXECUTE (§6.13(b)) and awaits its response
  does NOT block the reader — the reader keeps reading and routes the response back.

  The `system/protocol/connect` handshake is handled INLINE in the connection
  process (it mutates per-connection state and never originates outbound); every
  other EXECUTE is spawned (unlinked, with a per-request try) so an adversarial
  request can never tear down the connection (§3.3 every EXECUTE gets a response).

  The §6.13(b) handler-facing outbound seam is `Peer.Conn.outbound`, a closure
  that calls `outbound/2` here: register a pending waiter keyed by `request_id`,
  write the frame, and block the calling (dispatch) process in a `receive` until
  the reader routes the correlated response (or a timeout / connection close).
  """

  use GenServer

  alias EntityCore.{Model, Peer, Wire}
  alias EntityCore.Model.Envelope

  @outbound_timeout_ms 30_000

  defstruct [:socket, :peer, :conn, buffer: <<>>, pending: %{}]

  # ── lifecycle ───────────────────────────────────────────────────────────

  @doc "Start a connection process for an accepted socket (unlinked: per-connection isolation)."
  @spec start(Peer.t(), :gen_tcp.socket()) :: GenServer.on_start()
  def start(peer, socket), do: GenServer.start(__MODULE__, {peer, socket})

  @impl true
  def init({peer, socket}) do
    # The outbound seam closure (§6.13(b)) — captured for this connection.
    self_pid = self()
    conn = %{Peer.new_conn() | outbound: fn env -> outbound(self_pid, env) end}
    {:ok, %__MODULE__{socket: socket, peer: peer, conn: conn}}
  end

  @doc "Arm the socket for reading once ownership has transferred (acceptor → conn process)."
  @spec activate(pid()) :: :ok
  def activate(pid), do: send(pid, :activate) && :ok

  # ── §6.13(b) outbound primitive ──────────────────────────────────────────

  @doc """
  Send an EXECUTE envelope and await its correlated EXECUTE_RESPONSE (§6.11). Runs
  in the dispatch process; the reader routes the response. Returns the response
  envelope, or `nil` on timeout / connection close.
  """
  @spec outbound(pid(), Envelope.t()) :: Envelope.t() | nil
  def outbound(conn_pid, %Envelope{} = env) do
    request_id = Model.text_field(env.root, "request_id") || ""
    :ok = GenServer.call(conn_pid, {:register_outbound, request_id, self(), env})

    receive do
      {:outbound_response, ^request_id, response} -> response
    after
      @outbound_timeout_ms -> nil
    end
  end

  @doc "Write a response envelope through the single-writer connection process."
  @spec write(pid(), Envelope.t()) :: :ok
  def write(conn_pid, %Envelope{} = env), do: GenServer.cast(conn_pid, {:write, env})

  # ── server ────────────────────────────────────────────────────────────────

  @impl true
  def handle_call({:register_outbound, request_id, caller, env}, _from, st) do
    do_write(st.socket, env)
    {:reply, :ok, %{st | pending: Map.put(st.pending, request_id, caller)}}
  end

  @impl true
  def handle_cast({:write, env}, st) do
    do_write(st.socket, env)
    {:noreply, st}
  end

  @impl true
  def handle_info(:activate, st) do
    :inet.setopts(st.socket, active: :once)
    {:noreply, st}
  end

  def handle_info({:tcp, socket, data}, %{socket: socket} = st) do
    case extract_frames(st.buffer <> data, []) do
      :frame_too_large ->
        {:stop, :normal, st}

      {frames, rest} ->
        st = Enum.reduce(frames, %{st | buffer: rest}, &process_frame/2)
        :inet.setopts(socket, active: :once)
        {:noreply, st}
    end
  end

  def handle_info({:tcp_closed, _socket}, st), do: {:stop, :normal, wake_pending(st)}
  def handle_info({:tcp_error, _socket, _reason}, st), do: {:stop, :normal, wake_pending(st)}
  def handle_info(_other, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, st) do
    wake_pending(st)
    (try do: :gen_tcp.close(st.socket), rescue: (_ -> :ok))
    :ok
  end

  # ── internals ─────────────────────────────────────────────────────────────

  # Decode and route/dispatch one frame. Malformed frames are dropped (§3.3) and
  # the connection survives.
  defp process_frame(payload, st) do
    case safe_decode(payload) do
      {:ok, %Envelope{root: %{type: "system/protocol/execute/response"}} = env} ->
        route_response(env, st)

      {:ok, %Envelope{root: %{type: "system/protocol/execute"}} = env} ->
        dispatch_inbound(env, st)

      _ ->
        # non-EXECUTE root, or malformed → drop, keep the connection open.
        st
    end
  end

  defp safe_decode(payload) do
    {:ok, Wire.envelope_of_frame(payload)}
  rescue
    _ -> :error
  end

  defp route_response(env, st) do
    request_id = Model.text_field(env.root, "request_id") || ""

    case Map.pop(st.pending, request_id) do
      {nil, _} ->
        st

      {caller, pending} ->
        send(caller, {:outbound_response, request_id, env})
        %{st | pending: pending}
    end
  end

  defp dispatch_inbound(env, st) do
    uri = Model.text_field(env.root, "uri") || ""

    if uri == "system/protocol/connect" do
      # Inline: the handshake mutates per-connection state; never originates outbound.
      {resp, conn} = Peer.dispatch(st.peer, st.conn, env)
      if resp, do: do_write(st.socket, resp)
      %{st | conn: conn}
    else
      # Separate process (§4.8): a reentrant outbound await must not block the reader.
      peer = st.peer
      conn = st.conn
      conn_pid = self()

      spawn(fn ->
        resp =
          try do
            {r, _conn} = Peer.dispatch(peer, conn, env)
            r
          rescue
            _ -> Peer.internal_error_response(env)
          end

        if resp, do: write(conn_pid, resp)
      end)

      st
    end
  end

  defp do_write(socket, %Envelope{} = env) do
    :gen_tcp.send(socket, Wire.encode_frame(Wire.frame_of_envelope(env)))
  rescue
    _ -> :ok
  end

  # Wake every pending outbound waiter (connection close / error).
  defp wake_pending(%{pending: pending} = st) do
    Enum.each(pending, fn {rid, caller} -> send(caller, {:outbound_response, rid, nil}) end)
    %{st | pending: %{}}
  end

  # Extract complete `[4-byte BE length][payload]` frames from the buffer.
  defp extract_frames(<<len::32-big, _rest::binary>>, _acc) when len > 16 * 1024 * 1024,
    do: :frame_too_large

  defp extract_frames(<<len::32-big, payload::binary-size(len), rest::binary>>, acc),
    do: extract_frames(rest, [payload | acc])

  defp extract_frames(buffer, acc), do: {Enum.reverse(acc), buffer}
end
