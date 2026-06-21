defmodule EntityCore.Store do
  @moduledoc """
  Storage — the two layers of §1.7, owned by one GenServer process (the BEAM
  idiom for shared mutable state; all access is serialized through it, so
  concurrent per-request dispatch (§4.8) and the atomic CAS put are race-free
  without locks):

      Content Store: hash → entity   (immutable, content-addressed, dedup)
      Entity Tree:   path → hash      (mutable location index)

  Paths are the canonical absolute form `/{peer_id}/rest` (§1.4); the peer
  canonicalizes before calling in.

  ## Emit pathway (§6.10 / v7.74 §6.13(c))

  Tree/content writes produce events delivered synchronously-inline (§9.4) to
  registered consumers. The hook is LIVE even with zero consumers (events are
  produced and discarded) so a future extension can register a consumer without
  the peer being rebuilt — the §6.13(c) MUST. A core-only peer registers zero.
  `event_type` derives from the null-`new_hash` rule alone: a bind to a
  `system/deletion-marker` fires `"modified"` (it has a new_hash), never
  `"deleted"`.
  """

  use GenServer

  alias EntityCore.Entity

  @type event :: %{event_type: String.t(), path: String.t(), new_hash: binary() | nil, previous_hash: binary() | nil}

  defstruct content: %{}, tree: %{}, content_consumers: [], tree_consumers: []

  # ── lifecycle ───────────────────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, :ok, opts)

  @impl true
  def init(:ok), do: {:ok, %__MODULE__{}}

  # ── consumer registration (§6.10) ────────────────────────────────────────

  @spec register_content_consumer(GenServer.server(), (map() -> any())) :: :ok
  def register_content_consumer(s, fun), do: GenServer.call(s, {:register_content_consumer, fun})

  @spec register_tree_consumer(GenServer.server(), (event() -> any())) :: :ok
  def register_tree_consumer(s, fun), do: GenServer.call(s, {:register_tree_consumer, fun})

  # ── content store ─────────────────────────────────────────────────────────

  @spec put_entity(GenServer.server(), Entity.t()) :: :ok
  def put_entity(s, %Entity{} = e), do: GenServer.call(s, {:put_entity, e})

  @spec get_by_hash(GenServer.server(), binary()) :: Entity.t() | nil
  def get_by_hash(s, h), do: GenServer.call(s, {:get_by_hash, h})

  # ── entity tree ─────────────────────────────────────────────────────────

  @spec bind(GenServer.server(), String.t(), Entity.t()) :: :ok
  def bind(s, path, %Entity{} = e), do: GenServer.call(s, {:bind, path, e})

  @doc """
  Atomic compare-and-set bind (§3.9): `expected` is `:create_only` (path must be
  unbound), `{:match, hash}` (current binding must equal `hash`), or `:any`.
  Returns `:ok` or `:mismatch`. Atomic because it executes in one GenServer call.
  """
  @spec bind_cas(GenServer.server(), String.t(), Entity.t(), :create_only | {:match, binary()} | :any) ::
          :ok | :mismatch
  def bind_cas(s, path, %Entity{} = e, expected), do: GenServer.call(s, {:bind_cas, path, e, expected})

  @spec unbind(GenServer.server(), String.t()) :: :ok
  def unbind(s, path), do: GenServer.call(s, {:unbind, path})

  @spec hash_at(GenServer.server(), String.t()) :: binary() | nil
  def hash_at(s, path), do: GenServer.call(s, {:hash_at, path})

  @spec get_at(GenServer.server(), String.t()) :: Entity.t() | nil
  def get_at(s, path), do: GenServer.call(s, {:get_at, path})

  @doc """
  One-level listing under `prefix`: `[{segment, hash | nil, has_children?}]`,
  sorted by segment (§3.9 / §1.7). A bound child contributes a hash; a path that
  is also a prefix of deeper paths contributes `has_children?`.
  """
  @spec listing(GenServer.server(), String.t()) :: [{String.t(), binary() | nil, boolean()}]
  def listing(s, prefix), do: GenServer.call(s, {:listing, prefix})

  # ── server ────────────────────────────────────────────────────────────────

  @impl true
  def handle_call({:register_content_consumer, fun}, _from, st),
    do: {:reply, :ok, %{st | content_consumers: [fun | st.content_consumers]}}

  def handle_call({:register_tree_consumer, fun}, _from, st),
    do: {:reply, :ok, %{st | tree_consumers: [fun | st.tree_consumers]}}

  def handle_call({:put_entity, e}, _from, st), do: {:reply, :ok, do_put(st, e)}

  def handle_call({:get_by_hash, h}, _from, st), do: {:reply, Map.get(st.content, h), st}

  def handle_call({:bind, path, e}, _from, st), do: {:reply, :ok, do_bind(st, path, e)}

  def handle_call({:bind_cas, path, e, expected}, _from, st) do
    current = Map.get(st.tree, path)

    ok? =
      case expected do
        :any -> true
        :create_only -> current == nil
        {:match, h} -> current == h
      end

    if ok?, do: {:reply, :ok, do_bind(st, path, e)}, else: {:reply, :mismatch, st}
  end

  def handle_call({:unbind, path}, _from, st) do
    previous = Map.get(st.tree, path)
    st = %{st | tree: Map.delete(st.tree, path)}

    if previous != nil do
      emit_tree(st, %{event_type: "deleted", path: path, new_hash: nil, previous_hash: previous})
    end

    {:reply, :ok, st}
  end

  def handle_call({:hash_at, path}, _from, st), do: {:reply, Map.get(st.tree, path), st}

  def handle_call({:get_at, path}, _from, st) do
    entity = with h when h != nil <- Map.get(st.tree, path), do: Map.get(st.content, h)
    {:reply, entity || nil, st}
  end

  def handle_call({:listing, prefix}, _from, st), do: {:reply, do_listing(st, prefix), st}

  # ── internals ─────────────────────────────────────────────────────────────

  # §6.10 Store step: a content-store event fires only when the entity is new.
  defp do_put(st, %Entity{hash: h} = e) do
    if Map.has_key?(st.content, h) do
      st
    else
      st = %{st | content: Map.put(st.content, h, e)}
      Enum.each(st.content_consumers, fn f -> f.(%{hash: h, entity: e}) end)
      st
    end
  end

  # §6.10 Bind step: bind runs Store then Bind; a tree-change event fires only
  # when the binding at the path changes (no event on a re-bind to current hash).
  defp do_bind(st, path, %Entity{hash: h} = e) do
    st = do_put(st, e)
    previous = Map.get(st.tree, path)
    changed = previous != h
    st = %{st | tree: Map.put(st.tree, path, h)}

    if changed do
      emit_tree(st, %{
        event_type: event_type(previous, h),
        path: path,
        new_hash: h,
        previous_hash: previous
      })
    end

    st
  end

  defp emit_tree(st, event), do: Enum.each(st.tree_consumers, fn f -> f.(event) end)

  defp event_type(nil, _new), do: "created"
  defp event_type(_prev, nil), do: "deleted"
  defp event_type(_prev, _new), do: "modified"

  defp do_listing(st, prefix) do
    prefix = if String.ends_with?(prefix, "/"), do: prefix, else: prefix <> "/"
    plen = byte_size(prefix)

    st.tree
    |> Enum.reduce(%{}, fn {path, hash}, acc ->
      if byte_size(path) > plen and String.starts_with?(path, prefix) do
        rest = binary_part(path, plen, byte_size(path) - plen)

        case :binary.match(rest, "/") do
          :nomatch ->
            # direct child, bound
            note(acc, rest, hash, false)

          {i, _} ->
            # deeper child path
            note(acc, binary_part(rest, 0, i), nil, true)
        end
      else
        acc
      end
    end)
    |> Enum.map(fn {seg, {hash, children}} -> {seg, hash, children} end)
    |> Enum.sort_by(fn {seg, _, _} -> seg end)
  end

  defp note(acc, seg, hash_opt, deeper) do
    Map.update(acc, seg, {hash_opt, deeper}, fn {h, c} ->
      {if(hash_opt != nil, do: hash_opt, else: h), c or deeper}
    end)
  end
end
