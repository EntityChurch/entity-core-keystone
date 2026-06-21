defmodule EntityCore.SmokeTest do
  @moduledoc """
  The S3 lifecycle smoke scenario over the REAL wire (`EntityCore.Transport` +
  `EntityCore.Connection`): boot a peer on a localhost port, complete the §4.1/§4.6
  handshake (hello → authenticate, 3 EXECUTE + 3 EXECUTE_RESPONSE), make an
  authorized request through the full §6.5 dispatch chain, hit an unregistered path
  (404), and confirm `request_id` echo. Exercises active-once framing, the
  controlling_process hand-off, and the §6.11 demux that the OCaml peer subsumed
  into validate-peer — here proven standalone.
  """
  use ExUnit.Case, async: false

  alias EntityCore.{Identity, Model, Peer, Signature, Transport, Wire}
  alias EntityCore.Model.Envelope

  @server_seed :binary.copy(<<0x11>>, 32)
  @client_seed :binary.copy(<<0x22>>, 32)

  setup do
    peer = Peer.create(@server_seed, open_grants: true)
    {:ok, lsock, port} = Transport.listen(0)
    acceptor = spawn(fn -> Transport.accept_loop(peer, lsock) end)
    on_exit(fn -> Process.exit(acceptor, :kill); :gen_tcp.close(lsock) end)
    {:ok, port: port, server: peer}
  end

  test "handshake → authorized listing → 404 → request_id echo", %{port: port} do
    {:ok, sock} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false, packet: :raw], 5000)
    client = Identity.of_seed(@client_seed)

    # ── 1. hello (no signature) ──
    hello_params =
      Model.make("system/protocol/connect/hello", %{
        "peer_id" => client.peer_id,
        "nonce" => {:bytes, :crypto.strong_rand_bytes(16)},
        "timestamp" => 0,
        "protocols" => ["entity-core/1.0"]
      })

    hello_resp = round_trip(sock, exec("h1", "system/protocol/connect", "hello", Model.to_cbor(hello_params)), %{})
    assert status(hello_resp) == 200
    assert request_id(hello_resp) == "h1"
    server_hello = Model.of_cbor(Model.field(hello_resp.root, "result"))
    server_nonce = Model.bytes_field(server_hello, "nonce")
    assert is_binary(server_nonce)

    # ── 2. authenticate (proof-of-possession over the auth entity hash) ──
    auth =
      Model.make("system/protocol/connect/authenticate", %{
        "public_key" => {:bytes, client.public_key},
        "nonce" => {:bytes, server_nonce},
        "peer_id" => client.peer_id,
        "key_type" => "ed25519"
      })

    auth_sig =
      Model.make("system/signature", %{
        "target" => {:bytes, auth.hash},
        "signer" => {:bytes, client.identity_hash},
        "algorithm" => "ed25519",
        "signature" => {:bytes, Signature.sign_raw(client.seed, auth.hash, :ed25519)}
      })

    auth_resp =
      round_trip(sock, exec("a1", "system/protocol/connect", "authenticate", Model.to_cbor(auth)), %{
        auth_sig.hash => auth_sig
      })

    assert status(auth_resp) == 200
    grant = Model.of_cbor(Model.field(auth_resp.root, "result"))
    token_hash = Model.bytes_field(grant, "token")
    token = Map.fetch!(auth_resp.included, token_hash)
    cap_sig = find_signature(auth_resp.included, token_hash)
    assert token.type == "system/capability/token"
    assert cap_sig != nil

    # ── 3. authorized tree get (no resource → list peer root) ──
    listing_resp = authorized(sock, "t1", "system/tree", "get", client, token, cap_sig)
    assert status(listing_resp) == 200
    assert request_id(listing_resp) == "t1"
    assert Model.of_cbor(Model.field(listing_resp.root, "result")).type == "system/tree/listing"

    # ── 4. unregistered path → 404 (reached only because the request is authorized) ──
    nf_resp = authorized(sock, "x1", "system/does-not-exist", "get", client, token, cap_sig)
    assert status(nf_resp) == 404
    assert request_id(nf_resp) == "x1"

    :gen_tcp.close(sock)
  end

  # ── client helpers ─────────────────────────────────────────────────────────

  defp exec(rid, uri, operation, params_cbor) do
    Model.make("system/protocol/execute", %{
      "request_id" => rid,
      "uri" => uri,
      "operation" => operation,
      "params" => params_cbor
    })
  end

  # A fully-authorized EXECUTE: signed by the author, carrying the cap + its signature.
  defp authorized(sock, rid, uri, operation, client, token, cap_sig) do
    e =
      Model.make("system/protocol/execute", %{
        "request_id" => rid,
        "uri" => uri,
        "operation" => operation,
        "params" => Model.to_cbor(Wire.empty_params()),
        "author" => {:bytes, client.identity_hash},
        "capability" => {:bytes, token.hash}
      })

    exec_sig =
      Model.make("system/signature", %{
        "target" => {:bytes, e.hash},
        "signer" => {:bytes, client.identity_hash},
        "algorithm" => "ed25519",
        "signature" => {:bytes, Signature.sign_raw(client.seed, e.hash, :ed25519)}
      })

    included =
      %{}
      |> Map.put(client.identity_hash, client.peer_entity)
      |> Map.put(token.hash, token)
      |> Map.put(cap_sig.hash, cap_sig)
      |> Map.put(exec_sig.hash, exec_sig)

    round_trip(sock, e, included)
  end

  defp round_trip(sock, root, included) do
    payload = Wire.frame_of_envelope(%Envelope{root: root, included: included})
    :ok = :gen_tcp.send(sock, Wire.encode_frame(payload))
    recv_frame(sock)
  end

  defp recv_frame(sock) do
    {:ok, <<len::32-big>>} = :gen_tcp.recv(sock, 4, 5000)
    {:ok, payload} = :gen_tcp.recv(sock, len, 5000)
    Wire.envelope_of_frame(payload)
  end

  defp find_signature(included, target) do
    Enum.find_value(included, fn {_h, e} ->
      if e.type == "system/signature" and Model.bytes_field(e, "target") == target, do: e, else: nil
    end)
  end

  defp status(%Envelope{root: root}), do: Model.uint_field(root, "status")
  defp request_id(%Envelope{root: root}), do: Model.text_field(root, "request_id")
end
