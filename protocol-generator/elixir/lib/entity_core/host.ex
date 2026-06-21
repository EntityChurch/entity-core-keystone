defmodule EntityCore.Host do
  @moduledoc """
  Standalone peer host — the runnable target for S4 conformance (escript). Boots one
  `EntityCore.Peer` listener on a TCP port and blocks, so the entity-core-go
  `validate-peer` oracle can drive the live wire surface. Twin of the OCaml
  `bin/host.ml`, the C# `EntityCore.Protocol.Host`, and the TS `host.ts`.

      --port N               listen port (default 7777; 0 = auto-assign)
      --debug-open-grants    select the degenerate `default -> *` seed policy (so the
                             validator can reach grant-gated paths). DEPRECATED.
      --validate             conformance build (GUIDE-CONFORMANCE §7a): bootstrap the
                             system/validate/* test-handlers (echo + dispatch-outbound).
                             NOT core protocol; OFF by default (dispatch-outbound is a
                             standing outbound originator — never live in production).
      --name NAME            load a persistent Ed25519 identity from the standard
                             on-disk location ~/.entity/peers/NAME/keypair (the
                             entity-core PEM keypair: a base64-encoded 32-byte seed
                             between BEGIN/END ENTITY PRIVATE KEY lines — the same
                             convention the Go entity-peer --name and peer-manager use).
                             Without --name a fixed test seed is used (stable peer_id).

  A single `LISTENING …` line on stdout signals readiness.
  """

  alias EntityCore.{Peer, Transport}

  # Fixed 32-byte Ed25519 seed → stable peer identity across runs (no --name).
  @seed :binary.copy(<<0x11>>, 32)

  @spec main([String.t()]) :: no_return() | :ok
  def main(args) do
    opts = parse(args, %{port: 7777, open_grants: false, validate: false, seed: @seed})

    peer = Peer.create(opts.seed, open_grants: opts.open_grants, conformance: opts.validate)
    {:ok, lsock, bound} = Transport.listen(opts.port)

    IO.puts(
      "LISTENING 127.0.0.1:#{bound} peer_id=#{peer.local_peer} " <>
        "open_grants=#{opts.open_grants} validate=#{opts.validate}"
    )

    Transport.accept_loop(peer, lsock)
  end

  defp parse([], opts), do: opts
  defp parse(["--port", n | rest], opts), do: parse(rest, %{opts | port: String.to_integer(n)})
  defp parse(["--name", name | rest], opts), do: parse(rest, %{opts | seed: load_seed_from_name(name)})

  defp parse(["--debug-open-grants" | rest], opts) do
    IO.warn(
      "--debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — it now selects " <>
        "the degenerate `default -> *` seed policy. Prefer --seed-policy.",
      []
    )

    parse(rest, %{opts | open_grants: true})
  end

  defp parse(["--validate" | rest], opts), do: parse(rest, %{opts | validate: true})

  defp parse([h | _], _opts) when h in ["-h", "--help"] do
    IO.puts("usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]")
    System.halt(0)
  end

  defp parse([arg | _], _opts) do
    IO.puts(:stderr, "error: unknown argument '#{arg}'")
    System.halt(2)
  end

  # Load the 32-byte Ed25519 seed from the standard on-disk keypair (the Go
  # entity-peer --name / peer-manager convention): ~/.entity/peers/NAME/keypair,
  # a PEM whose body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
  @spec load_seed_from_name(String.t()) :: binary()
  defp load_seed_from_name(name) do
    home = System.get_env("HOME") || System.user_home!() || "/root"
    path = Path.join([home, ".entity", "peers", name, "keypair"])

    body =
      case File.read(path) do
        {:ok, contents} -> contents
        {:error, reason} ->
          IO.puts(:stderr, "error: --name #{name}: #{:file.format_error(reason)} (#{path})")
          System.halt(2)
      end

    seed =
      body
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(&1, "-"))
      |> Enum.join("")
      |> String.trim()
      |> decode_seed!(name)

    if byte_size(seed) != 32 do
      IO.puts(:stderr, "error: --name #{name}: expected a 32-byte seed, got #{byte_size(seed)} bytes")
      System.halt(2)
    end

    seed
  end

  @spec decode_seed!(String.t(), String.t()) :: binary()
  defp decode_seed!(b64, name) do
    case Base.decode64(b64) do
      {:ok, seed} ->
        seed

      :error ->
        IO.puts(:stderr, "error: --name #{name}: malformed base64 keypair body")
        System.halt(2)
    end
  end
end
