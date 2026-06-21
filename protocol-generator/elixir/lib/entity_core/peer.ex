defmodule EntityCore.Peer do
  @moduledoc """
  Peer assembly — bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2:
  tree, handler, capability, connect), the dispatch chain (§6.5), and per-connection
  state. The pure protocol brain: a `%Peer{}` context (identity + store pid +
  local_peer) plus a function from an inbound envelope to an outbound response.
  `EntityCore.Connection` owns the socket and the BEAM process structure.

  Spec-first: the §4.1/§4.6 three-check handshake, the §6.5 dispatch order
  (verify → resolve → check_permission → handler), and the §6.9a seed-policy
  bootstrap derive directly from V7.

  ## v7.74 foundations (resynced at S3 per A-ELX-001)
    * §6.13(a) handler register/unregister live (5 normative writes + entity-native
      dispatch seam) — NOT a 501 stub.
    * §6.13(b) handler-facing outbound dispatch via §6.11 reentry.
    * §6.10 emit (the Store consumer hooks; consumer-registration reachable).
    * §6.9a peer-owner capability + identity→capability seed policy.
    * §7a conformance test-handlers (`system/validate/*`), opt-in via `conformance:`,
      OFF by default.
  """

  alias EntityCore.{Capability, Identity, Model, Signature, Store, TypeDefs, Wire}
  alias EntityCore.Model.Envelope

  @enforce_keys [:identity, :store, :local_peer]
  defstruct [:identity, :store, :local_peer, open_grants: false, conformance: false]

  @type t :: %__MODULE__{
          identity: Identity.t(),
          store: pid(),
          local_peer: String.t(),
          open_grants: boolean(),
          conformance: boolean()
        }

  defmodule Conn do
    @moduledoc """
    Per-connection state (§4.2). `outbound` is the §6.13(b) reentry seam — a
    function `(envelope -> envelope | nil)` set by the transport, `nil` when the
    request did not arrive over a reentrant connection. The handshake fields are
    threaded back out of `dispatch/3` on the connect path.
    """
    defstruct established: false, issued_nonce: nil, hello_peer_id: nil, outbound: nil
    @type t :: %__MODULE__{}
  end

  @doc "A fresh per-connection state."
  @spec new_conn() :: Conn.t()
  def new_conn, do: %Conn{}

  # A handler outcome: status, result entity, and protocol entities to bundle.
  defp ok(result, included \\ %{}), do: %{status: 200, result: result, included: included}
  defp err(status, code, message \\ nil), do: %{status: status, result: Wire.error_result(code, message), included: %{}}

  defp now_ms, do: System.system_time(:millisecond)

  # ── grant construction (§4.4 / §5.4) ──────────────────────────────────────

  # An unconstrained dimension is present-with-empty-include (the §3.6 empty-scope
  # ruling), so "include" is always emitted; "exclude" only when non-empty.
  defp scope(incl, excl \\ []) do
    base = %{"include" => incl}
    if excl == [], do: base, else: Map.put(base, "exclude", excl)
  end

  defp grant(handlers, resources, operations, peers \\ nil) do
    base = %{"handlers" => scope(handlers), "resources" => scope(resources), "operations" => scope(operations)}
    if peers, do: Map.put(base, "peers", scope(peers)), else: base
  end

  # The §4.4 discovery floor: every authenticated identity gets at least this.
  defp discovery_floor do
    [
      grant(["system/tree"], ["system/type/*", "system/handler/*"], ["get"]),
      grant(["system/capability"], [], ["request"])
    ]
  end

  # The degenerate [default → *] (= retired --debug-open-grants).
  defp open_grants_scope do
    [grant(["*"], ["*", "/*/*"], ["*"], ["*"])]
  end

  # Full owner authority over the local namespace /{peer_id}/* (§6.9a).
  defp owner_grants(t), do: [grant(["*"], ["*"], ["*"], [t.local_peer])]

  # Raw grants list from a seed-policy entry (§6.9a.0 two shapes: a cap token —
  # detached-signature, verify at the §3.5 pointer before trusting — or a
  # policy-entry scope template).
  defp seed_entry_grants(t, e) do
    grants_of = fn ->
      case Model.field(e, "grants") do
        l when is_list(l) -> l
        _ -> []
      end
    end

    cond do
      e.type == "system/capability/token" ->
        sig_path = "/" <> t.local_peer <> "/system/signature/" <> Model.hex(e.hash)

        case Store.get_at(t.store, sig_path) do
          %{} = sgn ->
            if Identity.verify_signature(sgn, t.identity.peer_entity), do: grants_of.(), else: []

          _ ->
            []
        end

      e.type == "system/capability/policy-entry" ->
        grants_of.()

      true ->
        []
    end
  end

  # §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
  # then UNION the matched scope with the §4.4 discovery floor (v7.62 §8).
  defp derive_seed_grants(t, remote_peer, remote_peer_id) do
    base = "/" <> t.local_peer <> "/system/capability/policy/"

    entry =
      Store.get_at(t.store, base <> Model.hex(remote_peer.hash)) ||
        Store.get_at(t.store, base <> remote_peer_id) ||
        Store.get_at(t.store, base <> "default")

    floor = discovery_floor()
    policy_grants = if entry, do: seed_entry_grants(t, entry), else: []
    if policy_grants == [], do: floor, else: floor ++ policy_grants
  end

  @doc """
  Mint a root capability token granted by us to `grantee_hash`. Signs it. Returns
  `{token, signature}`.
  """
  @spec mint_token(t(), binary(), [term()], binary() | nil) :: {EntityCore.Entity.t(), EntityCore.Entity.t()}
  def mint_token(t, grantee_hash, grants, parent \\ nil) do
    data =
      %{
        "granter" => {:bytes, t.identity.identity_hash},
        "grantee" => {:bytes, grantee_hash},
        "grants" => grants,
        "created_at" => now_ms()
      }
      |> maybe_put("parent", parent && {:bytes, parent})

    token = Model.make("system/capability/token", data)
    {token, Identity.sign_entity(t.identity, token)}
  end

  defp maybe_put(map, _k, nil), do: map
  defp maybe_put(map, k, v), do: Map.put(map, k, v)

  # ── §6.13(b) handler-facing outbound dispatch ──────────────────────────────

  @doc """
  Build, sign (as the local peer), and send an outbound EXECUTE through the §6.11
  reentry seam on the serving connection, returning the correlated
  EXECUTE_RESPONSE envelope (or `nil` if no reentrant connection). The handler
  dispatches under its own authority (§6.8): it supplies the capability the target
  accepts plus the §5.8 chain bundle.
  """
  def outbound_dispatch(t, conn, opts) do
    case conn.outbound do
      nil ->
        nil

      send_fn ->
        uri = Keyword.fetch!(opts, :uri)
        operation = Keyword.fetch!(opts, :operation)
        params = Keyword.fetch!(opts, :params)
        capability = Keyword.fetch!(opts, :capability)
        granter_peer = Keyword.fetch!(opts, :granter_peer)
        capability_signature = Keyword.fetch!(opts, :capability_signature)
        resource = Keyword.get(opts, :resource)
        request_id = "out-" <> Integer.to_string(System.unique_integer([:positive, :monotonic]))

        exec =
          Wire.make_execute(
            request_id: request_id,
            uri: uri,
            operation: operation,
            params: params,
            resource: resource,
            author: t.identity.identity_hash,
            capability: capability.hash
          )

        exec_sig = Identity.sign_entity(t.identity, exec)

        included =
          %{}
          |> Map.put(capability.hash, capability)
          |> Map.put(granter_peer.hash, granter_peer)
          |> Map.put(t.identity.identity_hash, t.identity.peer_entity)
          |> Map.put(capability_signature.hash, capability_signature)
          |> Map.put(exec_sig.hash, exec_sig)

        send_fn.(%Envelope{root: exec, included: included})
    end
  end

  # ── connect handler (§4.1, §4.6) ──────────────────────────────────────────

  defp entity_field(e, key) do
    case Model.field(e, key) do
      nil -> nil
      c -> Model.of_cbor(c)
    end
  end

  # Returns {outcome, conn}.
  defp connect_handler(t, conn, exec, included) do
    case Model.text_field(exec, "operation") || "" do
      "hello" -> connect_hello(t, conn, exec)
      "authenticate" -> connect_authenticate(t, conn, exec, included)
      other -> {err(501, "unsupported_operation", "connect: " <> other), conn}
    end
  end

  defp connect_hello(t, conn, exec) do
    if conn.established do
      {err(409, "connection_already_established"), conn}
    else
      params = entity_field(exec, "params")

      str_array = fn key ->
        case params && Model.field(params, key) do
          l when is_list(l) -> Enum.filter(l, &is_binary/1)
          _ -> nil
        end
      end

      hash_ok = case str_array.("hash_formats") do
                  nil -> true
                  fmts -> "ecfv1-sha256" in fmts
                end

      key_ok = case str_array.("key_types") do
                 nil -> true
                 kts -> "ed25519" in kts
               end

      cond do
        not hash_ok ->
          {err(400, "incompatible_hash_format"), conn}

        not key_ok ->
          {err(400, "unsupported_key_type"), conn}

        true ->
          initiator_peer = params && Model.text_field(params, "peer_id")
          nonce = :crypto.strong_rand_bytes(32)

          hello =
            Model.make("system/protocol/connect/hello", %{
              "peer_id" => t.local_peer,
              "nonce" => {:bytes, nonce},
              "protocols" => ["entity-core/1.0"],
              "timestamp" => now_ms(),
              "hash_formats" => ["ecfv1-sha256"],
              "key_types" => ["ed25519"]
            })

          {ok(hello), %{conn | hello_peer_id: initiator_peer, issued_nonce: nonce}}
      end
    end
  end

  defp connect_authenticate(t, conn, exec, included) do
    cond do
      conn.established ->
        {err(409, "connection_already_established"), conn}

      conn.issued_nonce == nil ->
        # authenticate before hello (§4.6 step 1)
        {err(401, "invalid_nonce"), conn}

      true ->
        case entity_field(exec, "params") do
          nil ->
            {err(401, "authentication_failed"), conn}

          auth ->
            if unsupported_key_type?(auth) do
              {err(400, "unsupported_key_type"), conn}
            else
              authenticate_steps(t, conn, auth, included)
            end
        end
    end
  end

  # §4.6 hardening / AGILITY-UNKNOWN-1: reject an unsupported key_type carried in
  # the key_type field, a non-32-byte public_key, or the peer_id's leading byte.
  defp unsupported_key_type?(auth) do
    kt = Model.text_field(auth, "key_type")

    (kt != nil and kt != "ed25519") or
      (case Model.bytes_field(auth, "public_key") do
         p when is_binary(p) -> byte_size(p) != 32
         _ -> false
       end) or
      (case Model.text_field(auth, "peer_id") do
         nil ->
           false

         pid ->
           case EntityCore.PeerId.parse(pid) do
             {:ok, {key_type, _, _}} -> key_type != 0x01
             _ -> false
           end
       end)
  end

  defp authenticate_steps(t, conn, auth, included) do
    pub = Model.bytes_field(auth, "public_key")
    echoed = Model.bytes_field(auth, "nonce")
    claimed_peer = Model.text_field(auth, "peer_id")

    cond do
      # step 1: nonce-echo
      echoed != conn.issued_nonce ->
        {err(401, "invalid_nonce"), conn}

      pub == nil ->
        {err(401, "authentication_failed"), conn}

      # step 2: proof of possession
      not proof_of_possession?(auth, pub, included) ->
        {err(401, "authentication_failed"), conn}

      # step 3: identity binding
      claimed_peer != Identity.peer_id_of_pubkey(pub) ->
        {err(401, "identity_mismatch"), conn}

      conn.hello_peer_id != nil and conn.hello_peer_id != claimed_peer ->
        {err(401, "identity_mismatch"), conn}

      true ->
        # success: mint the §4.4 / §6.9a initial capability for the remote.
        remote_peer = Identity.peer_entity_of_pubkey(pub)
        grants = derive_seed_grants(t, remote_peer, claimed_peer || "")
        {token, sgn} = mint_token(t, remote_peer.hash, grants)

        grant_result =
          Model.make("system/capability/grant", %{"token" => {:bytes, token.hash}})

        included_out =
          %{}
          |> Map.put(token.hash, token)
          |> Map.put(t.identity.identity_hash, t.identity.peer_entity)
          |> Map.put(sgn.hash, sgn)

        {ok(grant_result, included_out), %{conn | established: true}}
    end
  end

  defp proof_of_possession?(auth, public_key, included) do
    case Capability.find_signature(auth.hash, included) do
      %{} = sgn ->
        case Model.bytes_field(sgn, "signature") do
          sb when is_binary(sb) -> Signature.verify_raw(public_key, auth.hash, sb, :ed25519)
          _ -> false
        end

      _ ->
        false
    end
  end

  # ── tree handler (§6.3) ────────────────────────────────────────────────────

  defp resource_target(exec) do
    case Model.field(exec, "resource") do
      nil ->
        nil

      r ->
        case Model.map_get(r, "targets") do
          [t | _] when is_binary(t) -> t
          _ -> nil
        end
    end
  end

  # §1.4 / §5.4 / CORE-TREE-PATH-FLEX-1: validate a caller-supplied target before
  # canonicalize. Reject NUL, a caller leading slash whose first segment is not a
  # peer-id, and ./ ../ // interior empty segments. A single trailing "/" is the
  # listing marker.
  defp path_flex_ok?(target) do
    if String.contains?(target, <<0>>) do
      false
    else
      segs0 = String.split(target, "/")

      {abs_ok, body} =
        if String.starts_with?(target, "/") do
          case segs0 do
            ["", first | _] -> {Capability.is_peer_id(first), tl(segs0)}
            _ -> {false, segs0}
          end
        else
          {true, segs0}
        end

      if not abs_ok do
        false
      else
        body =
          case Enum.reverse(body) do
            ["" | rest] -> Enum.reverse(rest)
            _ -> body
          end

        Enum.all?(body, fn s -> s != "" and s != "." and s != ".." end)
      end
    end
  end

  defp deletion_marker?(t, h) do
    case Store.get_by_hash(t.store, h) do
      %{type: "system/deletion-marker"} -> true
      _ -> false
    end
  end

  # Build a system/tree/listing (§3.9), omitting deletion-marker-bound leaves
  # (CORE-TREE-DELETE-1 / §6.3 filter).
  defp build_listing(t, path) do
    entries =
      Store.listing(t.store, path)
      |> Enum.reject(fn {_seg, hash, has_children} ->
        hash != nil and not has_children and deletion_marker?(t, hash)
      end)

    entry_map =
      for {seg, hash, has_children} <- entries, into: %{} do
        data = %{"has_children" => has_children}
        data = if hash, do: Map.put(data, "hash", {:bytes, hash}), else: data
        {seg, Model.to_cbor(Model.make("system/tree/listing-entry", data))}
      end

    ok(
      Model.make("system/tree/listing", %{
        "path" => path,
        "entries" => entry_map,
        "count" => length(entries),
        "offset" => 0
      })
    )
  end

  defp tree_handler(t, exec) do
    op = Model.text_field(exec, "operation") || ""
    target = resource_target(exec)

    cond do
      op in ["get", "put"] and target != nil and not path_flex_ok?(target) ->
        err(400, "invalid_path", target)

      op == "get" and target == nil ->
        # §6.3: empty resource → list the local peer root.
        build_listing(t, "/" <> t.local_peer <> "/")

      op == "get" and (target == "" or String.ends_with?(target, "/")) ->
        build_listing(t, Capability.canonicalize(t.local_peer, target))

      op == "get" ->
        tree_get(t, exec, target)

      op == "put" and target != nil ->
        tree_put(t, exec, target)

      target == nil ->
        err(400, "ambiguous_resource", "tree: missing resource target")

      true ->
        err(501, "unsupported_operation", "tree: " <> op)
    end
  end

  defp tree_get(t, exec, target) do
    path = Capability.canonicalize(t.local_peer, target)

    case Store.get_at(t.store, path) do
      %{} = e ->
        mode = with p when p != nil <- entity_field(exec, "params"), do: Model.text_field(p, "mode")

        if mode == "hash",
          do: ok(Model.make("system/hash", {:bytes, e.hash})),
          else: ok(e)

      nil ->
        err(404, "not_found", path)
    end
  end

  defp tree_put(t, exec, target) do
    path = Capability.canonicalize(t.local_peer, target)
    params = entity_field(exec, "params")
    entity = with p when p != nil <- params, do: entity_field(p, "entity")
    expected = with p when p != nil <- params, do: Model.bytes_field(p, "expected_hash")
    zero33 = :binary.copy(<<0>>, 33)

    expected_mode =
      case expected do
        nil -> :any
        ^zero33 -> :create_only
        h -> {:match, h}
      end

    case entity do
      %{} = e ->
        case Store.bind_cas(t.store, path, e, expected_mode) do
          :ok -> ok(Model.make("system/hash", {:bytes, e.hash}))
          :mismatch -> err(409, "hash_mismatch", path)
        end

      nil ->
        # §3.9 CAS check still applies even with no entity → mirror OCaml's order:
        # a CAS mismatch is 409; a present-but-missing entity is 400.
        case Store.hash_at(t.store, path) do
          current ->
            cas_ok =
              case expected_mode do
                :any -> true
                :create_only -> current == nil
                {:match, h} -> current == h
              end

            if cas_ok,
              do: err(400, "unexpected_params", "put: missing entity"),
              else: err(409, "hash_mismatch", path)
        end
    end
  end

  # ── capability handler (§6.2) ──────────────────────────────────────────────

  defp zero_hash?(h), do: h == :binary.copy(<<0>>, byte_size(h))

  defp req_grants_of(params) do
    case params && Model.field(params, "grants") do
      l when is_list(l) -> l
      _ -> []
    end
  end

  # mint a token bounded as a subset of the caller's authenticated cap (§6.2).
  defp mint_bounded(t, caller_cap, req_grants, grantee_hash, parent \\ nil) do
    bounded =
      case caller_cap do
        nil ->
          false

        cap ->
          parent_grants = Capability.grants_of_token(cap)

          Enum.all?(req_grants, fn cg ->
            c = Capability.parse_grant_entry(cg)
            Enum.any?(parent_grants, fn pg -> Capability.grant_subset_local(t.local_peer, c, pg) end)
          end)
      end

    if not bounded do
      err(403, "scope_exceeds_authority")
    else
      {token, sgn} = mint_token(t, grantee_hash, req_grants, parent)
      grant_result = Model.make("system/capability/grant", %{"token" => {:bytes, token.hash}})

      included =
        %{}
        |> Map.put(token.hash, token)
        |> Map.put(t.identity.identity_hash, t.identity.peer_entity)
        |> Map.put(sgn.hash, sgn)

      ok(grant_result, included)
    end
  end

  defp capability_handler(t, exec, caller_cap) do
    op = Model.text_field(exec, "operation") || ""
    params = entity_field(exec, "params")
    author = Model.bytes_field(exec, "author")

    case op do
      "request" ->
        case author do
          nil -> err(403, "capability_denied")
          grantee_hash -> mint_bounded(t, caller_cap, req_grants_of(params), grantee_hash)
        end

      "delegate" ->
        cap_delegate(t, exec, params, author, caller_cap)

      "revoke" ->
        cap_revoke(t, params)

      "configure" ->
        cap_configure(t, params)

      other ->
        err(501, "unsupported_operation", "capability: " <> other)
    end
  end

  defp cap_delegate(t, _exec, params, author, caller_cap) do
    case with p when p != nil <- params, do: Model.bytes_field(p, "parent") do
      nil ->
        err(400, "unexpected_params", "delegate: parent required")

      ph ->
        cond do
          zero_hash?(ph) ->
            err(400, "unexpected_params", "delegate: zero parent")

          # same-peer-only in v1 (closeout F1): a remote caller → 501, not 403.
          author != t.identity.identity_hash ->
            err(501, "unsupported_operation", "delegate: same-peer-only in v1")

          author == nil ->
            err(403, "capability_denied")

          true ->
            mint_bounded(t, caller_cap, req_grants_of(params), author, ph)
        end
    end
  end

  defp cap_revoke(t, params) do
    case with p when p != nil <- params, do: Model.bytes_field(p, "token") do
      nil ->
        err(400, "unexpected_params", "revoke: missing token")

      token_h ->
        if zero_hash?(token_h) do
          err(400, "unexpected_params", "revoke: zero token")
        else
          marker =
            Model.make("system/capability/revocation", %{
              "token" => {:bytes, token_h},
              "revoked_at" => now_ms()
            })

          Store.bind(t.store, "/" <> t.local_peer <> "/system/capability/revocations/" <> Model.hex(token_h), marker)
          ok(Wire.empty_params())
        end
    end
  end

  defp cap_configure(t, params) do
    case with p when p != nil <- params, do: Model.text_field(p, "peer_pattern") do
      nil ->
        err(400, "unexpected_params", "configure: missing peer_pattern")

      pp ->
        is_hex = byte_size(pp) == 66 and String.match?(pp, ~r/^[0-9a-f]+$/)

        if not (pp == "default" or is_hex or Capability.is_peer_id(pp)) do
          err(400, "invalid_peer_pattern", pp)
        else
          case params do
            %{} = p ->
              Store.bind(t.store, "/" <> t.local_peer <> "/system/capability/policy/" <> pp, p)
              ok(Wire.empty_params())

            _ ->
              err(400, "unexpected_params")
          end
        end
    end
  end

  # ── handlers handler (§6.2 / §6.13(a)) — register/unregister ────────────────

  defp register_pattern(exec) do
    case resource_target(exec) do
      nil ->
        {:error, err(400, "ambiguous_resource", "register/unregister require exactly one resource target")}

      target ->
        prefix = "system/handler/"

        if not String.starts_with?(target, prefix) or byte_size(target) == byte_size(prefix) do
          {:error, err(400, "invalid_resource", "resource target MUST be system/handler/{pattern}")}
        else
          {:ok, binary_part(target, byte_size(prefix), byte_size(target) - byte_size(prefix))}
        end
    end
  end

  # register (§6.2 / §6.13(a)): the five normative writes. A 501 stub is non-conformant.
  defp register(t, exec) do
    case register_pattern(exec) do
      {:error, e} ->
        e

      {:ok, pattern} ->
        case entity_field(exec, "params") do
          nil ->
            err(400, "unexpected_params", "register: missing params")

          %{type: type} = req when type != "system/handler/register-request" ->
            err(400, "unexpected_params", "register expects register-request, got " <> req.type)

          req ->
            do_register(t, pattern, req)
        end
    end
  end

  defp do_register(t, pattern, req) do
    manifest = Model.field(req, "manifest") || %{}
    name = case Model.map_get(manifest, "name") do
             s when is_binary(s) -> s
             _ -> pattern
           end

    operations = Model.map_get(manifest, "operations") || %{}
    expression_path = case Model.map_get(manifest, "expression_path") do
                        s when is_binary(s) -> s
                        _ -> nil
                      end

    internal_scope = Model.map_get(manifest, "internal_scope")

    # Grant scope = requested_scope ?? internal_scope ?? [] (§6.2 grant issuance).
    grant_scope =
      case {Model.field(req, "requested_scope"), internal_scope} do
        {l, _} when is_list(l) -> l
        {_, l} when is_list(l) -> l
        _ -> []
      end

    interface_rel = "system/handler/" <> pattern
    abs = fn rel -> "/" <> t.local_peer <> "/" <> rel end

    # (1) handler manifest (dispatch target) at the pattern path.
    handler_data =
      %{"interface" => interface_rel}
      |> maybe_put("expression_path", expression_path)
      |> then(fn d -> if internal_scope, do: Map.put(d, "internal_scope", internal_scope), else: d end)

    Store.bind(t.store, abs.(pattern), Model.make("system/handler", handler_data))

    # (2) associated types at system/type/{type_name}.
    case Model.field(req, "types") do
      m when is_map(m) ->
        Enum.each(m, fn
          {tn, v} when is_binary(tn) -> Store.bind(t.store, abs.("system/type/" <> tn), Model.make("system/type", v))
          _ -> :ok
        end)

      _ ->
        :ok
    end

    # (3) self-issued signed handler grant + (4) grant-signature at the §3.5 pointer.
    {token, sgn} = mint_token(t, t.identity.identity_hash, grant_scope)
    Store.bind(t.store, abs.("system/capability/grants/" <> pattern), token)
    Store.bind(t.store, abs.("system/signature/" <> Model.hex(token.hash)), sgn)

    # (5) handler interface entity (discovery index).
    iface = Model.make("system/handler/interface", %{"pattern" => pattern, "name" => name, "operations" => operations})
    Store.bind(t.store, abs.(interface_rel), iface)

    result = Model.make("system/handler/register-result", %{"pattern" => pattern, "grant" => token.data})
    ok(result)
  end

  # unregister (§6.2): reverse the five writes; grant-signature removed alongside the
  # grant (writer/unregister symmetry). Installed types left in place (A-OC-009).
  defp unregister(t, exec) do
    case register_pattern(exec) do
      {:error, e} ->
        e

      {:ok, pattern} ->
        abs = fn rel -> "/" <> t.local_peer <> "/" <> rel end

        case Store.get_at(t.store, abs.("system/capability/grants/" <> pattern)) do
          %{} = g ->
            Store.unbind(t.store, abs.("system/signature/" <> Model.hex(g.hash)))
            Store.unbind(t.store, abs.("system/capability/grants/" <> pattern))

          _ ->
            :ok
        end

        Store.unbind(t.store, abs.(pattern))
        Store.unbind(t.store, abs.("system/handler/" <> pattern))
        ok(Wire.empty_params())
    end
  end

  @doc false
  def handlers_handler(t, exec) do
    case Model.text_field(exec, "operation") || "" do
      "register" -> register(t, exec)
      "unregister" -> unregister(t, exec)
      other -> err(501, "unsupported_operation", "handler: " <> other)
    end
  end

  # Entity-native dispatch (v7.74 §6.13(a)): a dynamically-registered handler has no
  # in-process body — evaluate it at its expression_path. The minimal compute/literal
  # shape is the §10.1 register round-trip seam; richer bodies → 501 (A-ELX-010 / A-011).
  @doc false
  def entity_native_dispatch(t, handler_path) do
    case Store.get_at(t.store, handler_path) do
      nil ->
        err(404, "handler_not_found", handler_path)

      he ->
        case Model.text_field(he, "expression_path") do
          nil ->
            err(501, "no_handler_body", handler_path)

          expr_path ->
            abs = Capability.canonicalize(t.local_peer, expr_path)

            case Store.get_at(t.store, abs) do
              nil ->
                err(404, "expression_not_found", abs)

              %{type: "compute/literal"} = expr ->
                case Model.field(expr, "value") do
                  nil -> err(400, "unexpected_params", "compute/literal missing value")
                  value -> ok(Model.make("compute/result", %{"value" => value, "expression" => {:bytes, expr.hash}}))
                end

              expr ->
                err(501, "unsupported_expression", expr.type)
            end
        end
    end
  end

  defp types_handler(_t, exec) do
    err(501, "unsupported_operation", "type: " <> (Model.text_field(exec, "operation") || ""))
  end

  # ── §7a conformance test-handlers (the system/validate namespace) ───────────
  # NOT core protocol — conformance scaffolding (GUIDE-CONFORMANCE §7a), present only
  # under the conformance opt-in (--validate), off by default. echo closes A-011
  # (§6.13(a) resolve→dispatch), dispatch-outbound closes A-013 (§6.13(b)/§6.11 reentry).

  # system/validate/echo — return the params entity verbatim (no compute).
  @doc false
  def echo_handler(_t, exec) do
    case entity_field(exec, "params") do
      %{} = p -> ok(p)
      _ -> err(400, "invalid_params", "echo requires a params entity")
    end
  end

  # system/validate/dispatch-outbound — originate exactly one outbound EXECUTE via the
  # §6.11 reentry seam back to the caller; return the downstream response. The caller
  # carries the cap it minted for this peer in-band (three nested entities).
  @doc false
  def dispatch_outbound_handler(t, conn, exec) do
    case entity_field(exec, "params") do
      nil ->
        err(400, "invalid_params", "dispatch-outbound requires a params entity")

      p ->
        target = Model.text_field(p, "target") || ""
        operation = Model.text_field(p, "operation") || ""

        with value when value != nil <- Model.field(p, "value"),
             %{} = capability <- entity_field(p, "reentry_capability"),
             %{} = granter_peer <- entity_field(p, "reentry_granter"),
             %{} = capability_signature <- entity_field(p, "reentry_cap_signature") do
          # §7a.1: the `value` field IS the outbound params entity data — pass it
          # through directly (the reference's NewEntity("primitive/any", value)).
          # Re-wrapping as %{"value" => value} double-wraps, so the echo's
          # result.value comes back a map, not the sent value (keystone §7b t1_2).
          inner = Model.make("primitive/any", value)
          resource = %{"targets" => ["system/handler/" <> target]}

          case outbound_dispatch(t, conn,
                 uri: target,
                 operation: operation,
                 params: inner,
                 resource: resource,
                 capability: capability,
                 granter_peer: granter_peer,
                 capability_signature: capability_signature
               ) do
            nil ->
              err(503, "no_outbound_seam", "no live §6.11 reentry connection")

            %Envelope{} = env ->
              status = Model.uint_field(env.root, "status") || 0
              result_cbor = Model.field(env.root, "result") || %{}
              ok(Model.make("primitive/any", %{"status" => status, "result" => result_cbor}))
          end
        else
          _ -> err(400, "invalid_params", "dispatch-outbound requires value + reentry authority")
        end
    end
  end

  # ── dispatcher-level signature ingestion (§6.5) ─────────────────────────────

  defp ingest_signatures(t, %Envelope{} = env) do
    Enum.each(env.included, fn {_h, e} ->
      if e.type == "system/signature" do
        Store.put_entity(t.store, e)
        signer_h = Model.bytes_field(e, "signer")
        target = Model.bytes_field(e, "target")

        with signer_h when signer_h != nil <- signer_h,
             %{} = signer_peer <- Model.included_get(env, signer_h),
             target when target != nil <- target do
          Store.put_entity(t.store, signer_peer)
          # signer peer_id derived from its public_key (v7.65 peer has no peer_id field).
          case Model.bytes_field(signer_peer, "public_key") do
            pk when is_binary(pk) ->
              pid = Identity.peer_id_of_pubkey(pk)
              Store.bind(t.store, "/" <> pid <> "/system/signature/" <> Model.hex(target), e)

            _ ->
              :ok
          end
        else
          _ -> :ok
        end
      end
    end)
  end

  # ── handler resolution (§6.6) — backward tree-walk ─────────────────────────

  defp resolve_handler(t, path) do
    segs = String.split(path, "/")
    n = length(segs)

    Enum.find_value(n..1//-1, fn i ->
      prefix = segs |> Enum.take(i) |> Enum.join("/")

      case Store.get_at(t.store, prefix) do
        %{type: "system/handler"} ->
          {prefix, binary_part(path, byte_size(prefix), byte_size(path) - byte_size(prefix))}

        _ ->
          nil
      end
    end)
  end

  defp strip_local(t, pattern) do
    prefix = "/" <> t.local_peer <> "/"

    if String.starts_with?(pattern, prefix),
      do: binary_part(pattern, byte_size(prefix), byte_size(pattern) - byte_size(prefix)),
      else: pattern
  end

  # ── dispatch chain (§6.5) ──────────────────────────────────────────────────

  @doc """
  A 500 response envelope for a dispatch that raised — keeps the connection alive
  (§3.3 every EXECUTE gets a response) instead of closing it.
  """
  def internal_error_response(%Envelope{} = env) do
    request_id = Model.text_field(env.root, "request_id") || ""
    %Envelope{root: Wire.make_response(request_id, 500, Wire.error_result("internal_error")), included: %{}}
  end

  @doc """
  Dispatch one inbound envelope (§6.5). Returns `{response_envelope | nil, conn}`.
  The connect path threads the updated `conn`; every other path leaves `conn`
  unchanged. Non-EXECUTE roots return `{nil, conn}` (§3.3 server side ignores).
  """
  @spec dispatch(t(), Conn.t(), Envelope.t()) :: {Envelope.t() | nil, Conn.t()}
  def dispatch(t, conn, %Envelope{} = env) do
    exec = env.root

    if exec.type != "system/protocol/execute" do
      {nil, conn}
    else
      request_id = Model.text_field(exec, "request_id") || ""
      uri = Model.text_field(exec, "uri") || ""

      {outcome, conn} =
        try do
          if uri == "system/protocol/connect" do
            connect_handler(t, conn, exec, env.included)
          else
            {dispatch_request(t, conn, env, exec, uri), conn}
          end
        rescue
          # Per-request isolation (§3.3): any handler fault → 500, connection survives.
          _ -> {err(500, "internal_error"), conn}
        end

      response = Wire.make_response(request_id, outcome.status, outcome.result)
      {%Envelope{root: response, included: outcome.included}, conn}
    end
  end

  defp dispatch_request(t, conn, env, exec, uri) do
    ingest_signatures(t, env)

    case Capability.verify_request(t.local_peer, t.store, env) do
      :unresolvable_grantee -> err(401, "unresolvable_grantee")
      :req_authn_fail -> err(401, "authentication_failed")
      :req_authz_deny -> err(403, "capability_denied")
      :req_chain_too_deep -> err(400, "chain_depth_exceeded")
      :req_allow -> dispatch_authorized(t, conn, env, exec, uri)
    end
  end

  defp dispatch_authorized(t, conn, env, exec, uri) do
    path = Capability.canonicalize(t.local_peer, Capability.normalize_uri(uri))

    # §1.4: inbound dispatch must target the local peer.
    if Capability.extract_peer(t.local_peer, path) != t.local_peer do
      err(404, "handler_not_found", "not local peer")
    else
      case resolve_handler(t, path) do
        nil ->
          err(404, "handler_not_found", path)

        {pattern, _suffix} ->
          caller_cap =
            with c when c != nil <- Model.bytes_field(exec, "capability"), do: Model.included_get(env, c)

          case caller_cap do
            nil ->
              err(403, "capability_denied")

            cap ->
              # §PR-8: resolve the cap's granter once; grant resource patterns
              # canonicalize against it. Unresolvable / multisig → local frame.
              resolve_fn = fn h -> Map.get(env.included, h) || Store.get_by_hash(t.store, h) end
              granter_peer = Capability.resolve_granter_peer_id(resolve_fn, cap) || t.local_peer

              case Capability.check_permission(t.local_peer, granter_peer, exec, cap, pattern) do
                :deny ->
                  err(403, "capability_denied")

                :allow ->
                  route_to_handler(t, conn, exec, pattern, cap)
              end
          end
      end
    end
  end

  defp route_to_handler(t, conn, exec, pattern, caller_cap) do
    case strip_local(t, pattern) do
      "system/tree" -> tree_handler(t, exec)
      "system/capability" -> capability_handler(t, exec, caller_cap)
      "system/handler" -> handlers_handler(t, exec)
      "system/type" -> types_handler(t, exec)
      # §7a conformance handlers — only resolvable when bootstrapped under --validate.
      "system/validate/echo" -> echo_handler(t, exec)
      "system/validate/dispatch-outbound" -> dispatch_outbound_handler(t, conn, exec)
      # a dynamically-registered handler (§6.13(a)): dispatch its entity-native body.
      _ -> entity_native_dispatch(t, pattern)
    end
  end

  # ── bootstrap (§6.9 / §6.9a) ───────────────────────────────────────────────

  defp op_spec(input, output) do
    %{}
    |> maybe_put("input_type", input)
    |> maybe_put("output_type", output)
  end

  @bootstrap_handlers [
    {"system/tree", "Tree", [{"get", {nil, nil}}, {"put", {nil, nil}}]},
    {"system/handler", "Handlers",
     [
       {"register", {"system/handler/register-request", "system/handler/register-result"}},
       {"unregister", {"system/handler/unregister-request", nil}}
     ]},
    {"system/type", "Types", [{"validate", {"system/type/validate-request", "system/type/validate-result"}}]},
    {"system/capability", "Capability",
     [
       {"request", {"system/capability/request", "system/capability/grant"}},
       {"revoke", {"system/capability/revoke-request", nil}},
       {"configure", {"system/capability/policy-entry", nil}},
       {"delegate", {"system/capability/delegate-request", "system/capability/grant"}}
     ]},
    {"system/protocol/connect", "Connect", [{"hello", {nil, nil}}, {"authenticate", {nil, nil}}]}
  ]

  @doc """
  Create a peer: identity bundle, content store, the §9.5 core types, the §6.2 MUST
  handlers, the §6.9a peer-owner capability + seed policy, and (under
  `conformance: true`) the §7a test-handlers. Starts the Store process.
  """
  @spec create(binary(), keyword()) :: t()
  def create(seed, opts \\ []) do
    open_grants = Keyword.get(opts, :open_grants, false)
    conformance = Keyword.get(opts, :conformance, false)
    identity = Identity.of_seed(seed)
    {:ok, store} = Store.start_link()
    local_peer = identity.peer_id
    t = %__MODULE__{identity: identity, store: store, local_peer: local_peer, open_grants: open_grants, conformance: conformance}

    # local identity entity is in the store (root-granter resolution).
    Store.put_entity(store, identity.peer_entity)
    # publish the 53 core types (§9.5).
    TypeDefs.publish(store, local_peer)
    # bootstrap the §6.2 MUST handlers.
    Enum.each(@bootstrap_handlers, fn h -> bootstrap_handler(t, h) end)
    bootstrap_authority(t)

    # §7a conformance handlers — bootstrapped ONLY under conformance: (off by default).
    if conformance do
      Enum.each(
        [
          {"system/validate/echo", "validate-echo", [{"echo", {nil, nil}}]},
          {"system/validate/dispatch-outbound", "validate-dispatch-outbound", [{"dispatch", {nil, nil}}]}
        ],
        fn h -> bootstrap_handler(t, h) end
      )
    end

    t
  end

  defp bootstrap_handler(t, {pattern, name, ops}) do
    operations = for {o, {i, ou}} <- ops, into: %{}, do: {o, op_spec(i, ou)}
    handler_e = Model.make("system/handler", %{"interface" => "system/handler/" <> pattern})
    Store.bind(t.store, "/" <> t.local_peer <> "/" <> pattern, handler_e)

    iface = Model.make("system/handler/interface", %{"pattern" => pattern, "name" => name, "operations" => operations})
    Store.bind(t.store, "/" <> t.local_peer <> "/system/handler/" <> pattern, iface)

    {token, _} = mint_token(t, t.identity.identity_hash, [])
    Store.bind(t.store, "/" <> t.local_peer <> "/system/capability/grants/" <> pattern, token)
  end

  # §6.9a Peer Authority Bootstrap (L0 write-set): the self-owner capability (root
  # cap, full scope over /{peer_id}/*, grantee = own identity, §6.9a.0 detached-sig
  # shape) + the default scope-template entry, read back by authenticate.
  defp bootstrap_authority(t) do
    policy_base = "/" <> t.local_peer <> "/system/capability/policy/"
    {owner_token, owner_sig} = mint_token(t, t.identity.identity_hash, owner_grants(t))
    Store.bind(t.store, policy_base <> Model.hex(t.identity.identity_hash), owner_token)
    Store.bind(t.store, "/" <> t.local_peer <> "/system/signature/" <> Model.hex(owner_token.hash), owner_sig)

    default_grants = if t.open_grants, do: open_grants_scope(), else: discovery_floor()

    default_entry =
      Model.make("system/capability/policy-entry", %{"peer_pattern" => "default", "grants" => default_grants})

    Store.bind(t.store, policy_base <> "default", default_entry)
  end
end
