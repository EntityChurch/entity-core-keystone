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
    opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: {127, 0, 0, 1}, backlog: 64]

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
