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
        # §4.11 + §4.10(a), whose mood was raised SHOULD -> MUST at 0.8.2.25 (N14):
        # the over-size condition is detected AT THE LENGTH PREFIX with the connection
        # intact and nothing spent, so the permissive mood had nothing to license. This
        # arm was a bare `{:stop, :normal, st}` — "closing with no coded frame", which
        # is indistinguishable from a network fault and, on a multiplexed connection,
        # destroys unrelated ADMITTED requests.
        #
        # The stream is desynchronized (an oversize body was never drained), so the
        # frame goes out and THEN the connection closes. §4.11 makes the frame
        # mandatory and leaves the close to us; closing is the only sound choice once
        # the framing is lost, and it is a CHOICE rather than an alternative to
        # answering. No request_id is recoverable from a frame whose body never
        # arrived, and guessing one would correlate the refusal to somebody else's
        # in-flight request, so this takes §4.11's uncorrelated best-effort form.
        refuse_pre_admission(st, "", Wire.oversize_refusal())
        {:stop, :normal, st}

      {frames, rest} ->
        st = Enum.reduce(frames, %{st | buffer: rest}, &process_frame/2)
        :inet.setopts(socket, active: :once)
        {:noreply, st}
    end
  end

  # A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a stream
  # that ends MID-FRAME is a §4.11 framing REFUSAL and is owed a coded frame. On this
  # substrate the leftover `buffer` is the only place that distinction survives — both
  # events arrive as the same `{:tcp_closed, _}` message — and getting it wrong in the
  # other direction would answer 400 to every peer that simply hangs up.
  #
  # Writing here requires `exit_on_close: false` on the socket (see `Transport.listen`):
  # under the default the runtime has already closed our write side by the time this
  # message arrives, and the mandatory coded response is refused by the RUNTIME rather
  # than by any line of this module.
  def handle_info({:tcp_closed, _socket}, st) do
    if st.buffer != <<>>, do: refuse_pre_admission(st, "", Wire.truncated_refusal())
    {:stop, :normal, wake_pending(st)}
  end
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

      # EVERY OTHER ROOT GOES TO DISPATCH, including one that is neither EXECUTE nor
      # EXECUTE_RESPONSE. That used to fall to a `_ -> st` drop here; §6.5's "Other
      # type?" arm now answers `400 invalid_request` (0.8.2.25 N12/N17) and it does so
      # in ONE place, `Peer.dispatch`, rather than in a second copy beside this clause
      # where the two could drift.
      {:ok, %Envelope{} = env} ->
        dispatch_inbound(env, st)

      {:error, e} ->
        # A COMPLETE frame the decoder refused. The framing is intact, so we answer and
        # KEEP SERVING — and the refusal MUST be a status rather than silence (§4.11;
        # §4.9(c) says the same from the other direction).
        #
        # THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered `non_canonical_ecf` for
        # every cause until 0.8.2.24/.25 pinned them apart: a mis-keyed `included` entry
        # is `400 hash_mismatch` (its encoding is canonical — what is false is the claim
        # the key makes), a tag-policy violation keeps `non_canonical_ecf`, and
        # everything else that never becomes an Envelope is `400 invalid_request`.
        refuse_pre_admission(st, salvage_request_id(payload), Wire.pre_admission_refusal(e))
        st
    end
  end

  # Recover ONLY the `request_id` from a frame the strict decoder rejected, so the
  # refusal can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort
  # frame. `""` when nothing is recoverable.
  #
  # The frame stays rejected: nothing is built from it, nothing is stored, and a tag is
  # never interpreted — the salvage decode exists solely to read back the correlation
  # key. The envelope and entity-wrapper shapes are fixed maps with no legal tag
  # position, so a frame whose ONLY defect is a tag inside some entity's `data` still
  # has a structurally sound root, which is exactly the case worth recovering (and the
  # one CAP-6a's >2^64 half arrives as — a bignum can only reach a peer as a
  # major-type-6 tag).
  defp salvage_request_id(payload) do
    with {:ok, %{"root" => %{"data" => %{"request_id" => rid}}}} when is_binary(rid) <-
           EntityCore.Cbor.decode_salvage(payload) do
      rid
    else
      _ -> ""
    end
  end

  # Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
  # refused BEFORE it becomes an admitted request.
  #
  # *"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
  # wire `[MUST]` — correlated by `request_id` where the id is available, and otherwise
  # as a best-effort coded frame carrying no correlation."*
  #
  # §4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"* and
  # therefore reaches none of these, which is why §4.11 exists. Both of the
  # non-conformant behaviours it names separately were present on this peer: DROPPING
  # the frame (the un-salvageable decode arm and the non-EXECUTE root, *"the weaker of
  # the two precisely because nothing surfaces it"*) and CLOSING with no coded frame
  # (the oversize arm's bare `{:stop, :normal, st}`).
  #
  # AN EMPTY `request_id` IS THE BEST-EFFORT FORM, not a bug: it is what the section
  # prescribes where no id can be recovered.
  defp refuse_pre_admission(st, request_id, {status, code, message}) do
    do_write(st.socket, %Envelope{
      root: Wire.make_response(request_id, status, Wire.error_result(code, message)),
      included: %{}
    })
  end

  defp safe_decode(payload) do
    {:ok, Wire.envelope_of_frame(payload)}
  rescue
    e -> {:error, e}
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
