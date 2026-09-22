defmodule EntityCore.Transport do
  @moduledoc """
  TCP listener + acceptor (L4 / §1.6 framing). Binds loopback; each accepted
  socket gets its own `EntityCore.Connection` process. Socket ownership transfers
  to the connection process (`controlling_process`) before reading is armed, so no
  inbound bytes are lost in the hand-off race.
  """

  alias EntityCore.{Connection, Peer}

  @doc "Listen on `127.0.0.1:port` (0 = auto-assign). Returns `{:ok, lsocket, bound_port}`."
  @spec listen(non_neg_integer()) :: {:ok, :gen_tcp.socket(), non_neg_integer()} | {:error, term()}
  def listen(port) do
    # `exit_on_close: false` IS A §4.11 REQUIREMENT ON THIS SUBSTRATE, not a tuning
    # knob — the BEAM's answer to Node's `allowHalfOpen`. Under the default (`true`)
    # `:gen_tcp` closes our WRITE side the moment the client sends FIN, so a frame that
    # is only knowable as TRUNCATED at end-of-stream can never be answered and the
    # peer's mandatory coded EXECUTE_RESPONSE is refused by the RUNTIME rather than by
    # any line of `Connection`. A half-close is exactly the state where an answer is
    # both deliverable and useful: the caller has stopped writing and is still reading.
    # Go's `TCPConn` has this behaviour by default, which is why the 0.8.2.25 vanguard
    # peers needed no equivalent line and neither would have predicted it.
    #
    # The connection process still owns its own close: `{:tcp_closed, _}` answers the
    # refusal and then stops, and `terminate/2` calls `:gen_tcp.close/1`.
    opts = [
      :binary,
      packet: :raw,
      active: false,
      reuseaddr: true,
      exit_on_close: false,
      ip: {127, 0, 0, 1},
      backlog: 64
    ]

    with {:ok, lsock} <- :gen_tcp.listen(port, opts),
         {:ok, bound} <- :inet.port(lsock) do
      {:ok, lsock, bound}
    end
  end

  @doc "Accept connections forever, starting a `Connection` process per socket."
  @spec accept_loop(Peer.t(), :gen_tcp.socket()) :: :ok
  def accept_loop(peer, lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, socket} ->
        {:ok, pid} = Connection.start(peer, socket)
        :ok = :gen_tcp.controlling_process(socket, pid)
        Connection.activate(pid)
        accept_loop(peer, lsock)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        accept_loop(peer, lsock)
    end
  end
end
