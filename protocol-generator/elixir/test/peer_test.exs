defmodule EntityCore.PeerTest do
  @moduledoc """
  Function-level peer-machinery checks (the Elixir twin of the OCaml `selftest.ml`):
  the v7.74 foundations (F1 register, F3 emit, §7a echo + dispatch-outbound reentry)
  exercised directly against the dispatch surface, plus bootstrap invariants. The
  live wire path is exercised by `smoke_test.exs`; the validate-peer oracle (S4) is
  the stronger superset.
  """
  use ExUnit.Case, async: false

  alias EntityCore.{Model, Peer, Store, Wire}
  alias EntityCore.Model.Envelope

  @seed :binary.copy(<<0x11>>, 32)

  defp at(peer, rel), do: "/" <> peer.local_peer <> "/" <> rel
  defp typ_at(peer, rel), do: with(%{type: t} <- Store.get_at(peer.store, at(peer, rel)), do: t, else: (_ -> nil))

  describe "F3 emit (§6.10 / §6.13(c))" do
    test "event-type derivation + no-op suppression + deletion-marker → modified" do
      {:ok, store} = Store.start_link()
      me = self()
      Store.register_tree_consumer(store, fn ev -> send(me, {:ev, ev.event_type}) end)
      mk = fn b -> Model.make("primitive/any", %{"v" => b}) end

      Store.bind(store, "/p/x", mk.("one"))
      Store.bind(store, "/p/x", mk.("two"))
      # no-op re-bind → suppressed
      Store.bind(store, "/p/x", mk.("two"))
      Store.unbind(store, "/p/x")
      assert drain() == ["created", "modified", "deleted"]

      # a deletion-marker bind fires "modified" (keys on null new_hash only), not "deleted".
      {:ok, store2} = Store.start_link()
      Store.register_tree_consumer(store2, fn ev -> send(me, {:ev, ev.event_type}) end)
      Store.bind(store2, "/p/z", mk.("live"))
      Store.bind(store2, "/p/z", Model.make("system/deletion-marker", %{}))
      assert drain() == ["created", "modified"]
    end
  end

  describe "F1 register live (§6.13(a) / §6.2)" do
    test "5 writes + entity-native dispatch round-trip + unregister symmetry" do
      peer = Peer.create(@seed, open_grants: true)
      pp = "app/test/echo"

      manifest = %{
        "pattern" => pp,
        "name" => "echo",
        "operations" => %{"compute" => %{}},
        "expression_path" => pp <> "/expr"
      }

      reg_req = Model.make("system/handler/register-request", %{"manifest" => manifest})

      reg_exec =
        Model.make("system/protocol/execute", %{
          "operation" => "register",
          "resource" => %{"targets" => ["system/handler/" <> pp]},
          "params" => Model.to_cbor(reg_req)
        })

      r = Peer.handlers_handler(peer, reg_exec)
      assert r.status == 200 and r.result.type == "system/handler/register-result"

      # the five normative writes
      assert typ_at(peer, pp) == "system/handler"
      assert typ_at(peer, "system/handler/" <> pp) == "system/handler/interface"
      assert typ_at(peer, "system/capability/grants/" <> pp) == "system/capability/token"
      g = Store.get_at(peer.store, at(peer, "system/capability/grants/" <> pp))
      assert Store.get_at(peer.store, at(peer, "system/signature/" <> Model.hex(g.hash))) != nil

      # entity-native dispatch: bind compute/literal(42) → compute/result 42
      Store.bind(peer.store, at(peer, pp <> "/expr"), Model.make("compute/literal", %{"value" => 42}))
      d = Peer.entity_native_dispatch(peer, at(peer, pp))
      assert d.status == 200 and d.result.type == "compute/result"
      assert Model.field(d.result, "value") == 42

      # unregister reverses the writes (incl. grant-sig)
      unreg_exec =
        Model.make("system/protocol/execute", %{
          "operation" => "unregister",
          "resource" => %{"targets" => ["system/handler/" <> pp]}
        })

      u = Peer.handlers_handler(peer, unreg_exec)
      assert u.status == 200
      assert Store.get_at(peer.store, at(peer, pp)) == nil
    end
  end

  describe "§7a conformance handlers (GUIDE-CONFORMANCE §7a)" do
    test "OFF by default; bootstrapped under conformance:" do
      cpeer = Peer.create(@seed, open_grants: true, conformance: true)
      plain = Peer.create(@seed, open_grants: true)
      assert Store.get_at(plain.store, "/" <> plain.local_peer <> "/system/validate/echo") == nil
      assert Store.get_at(cpeer.store, "/" <> cpeer.local_peer <> "/system/validate/echo") != nil
    end

    test "echo returns the params value verbatim (resolve→dispatch, closes A-011)" do
      cpeer = Peer.create(@seed, open_grants: true, conformance: true)
      params = Model.make("primitive/any", %{"value" => "ping-42"})
      exec = Model.make("system/protocol/execute", %{"operation" => "echo", "params" => Model.to_cbor(params)})
      e = Peer.echo_handler(cpeer, exec)
      assert e.status == 200 and Model.field(e.result, "value") == "ping-42"
    end

    test "dispatch-outbound originates reentry + round-trips the value (closes A-013)" do
      cpeer = Peer.create(@seed, open_grants: true, conformance: true)

      # A fake reentry connection reflects the inner params back (simulates the
      # caller's echo over §6.11 reentry); the handler originates + wraps the response.
      outbound = fn %Envelope{root: root} ->
        rid = Model.text_field(root, "request_id") || ""
        inner = case Model.field(root, "params") do
                  nil -> Model.make("primitive/any", %{})
                  pc -> Model.of_cbor(pc)
                end

        %Envelope{root: Wire.make_response(rid, 200, inner), included: %{}}
      end

      conn = %{Peer.new_conn() | outbound: outbound}
      {cap, capsig} = Peer.mint_token(cpeer, cpeer.identity.identity_hash, [])
      granter = cpeer.identity.peer_entity

      do_params =
        Model.make("primitive/any", %{
          "target" => "system/validate/echo",
          "operation" => "echo",
          "value" => "round-trip-99",
          "reentry_capability" => Model.to_cbor(cap),
          "reentry_granter" => Model.to_cbor(granter),
          "reentry_cap_signature" => Model.to_cbor(capsig)
        })

      do_exec = Model.make("system/protocol/execute", %{"operation" => "dispatch", "params" => Model.to_cbor(do_params)})
      dout = Peer.dispatch_outbound_handler(cpeer, conn, do_exec)
      assert dout.status == 200
      rc = Model.field(dout.result, "result")
      assert Model.field(Model.of_cbor(rc), "value") == "round-trip-99"
    end
  end

  describe "§6.9a peer-authority bootstrap" do
    test "self-owner capability + signature at L0; default seed policy present" do
      peer = Peer.create(@seed, open_grants: false)
      ih = peer.identity.identity_hash
      owner = Store.get_at(peer.store, at(peer, "system/capability/policy/" <> Model.hex(ih)))
      assert owner != nil and owner.type == "system/capability/token"
      assert Store.get_at(peer.store, at(peer, "system/signature/" <> Model.hex(owner.hash))) != nil
      assert Store.get_at(peer.store, at(peer, "system/capability/policy/default")) != nil
    end
  end

  defp drain(acc \\ []) do
    receive do
      {:ev, t} -> drain([t | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
