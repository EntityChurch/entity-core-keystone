defmodule EntityCore.TypeDefs do
  @moduledoc """
  Core type floor (V7 §9.5) — render-from-model. The 53 core type *models* live in
  `EntityCore.TypeDefsData` (an in-code override table generated from the cross-impl
  Go-rendered type shapes); here each is rendered to a materialized `system/type`
  entity and published at `system/type/{name}`.

  Render-from-model, not ingest-bytes: the entity's content_hash is computed by our
  own S2 codec over the model, then diffed against the canonical type-registry
  vectors. A core peer publishes exactly these 53 (§9.5).
  """

  alias EntityCore.{Entity, Model, Store, TypeDefsData}

  @doc "The 53 core types as `{name, system/type entity}` tuples."
  @spec all() :: [{String.t(), Entity.t()}]
  def all do
    for {name, data} <- TypeDefsData.core_types(), do: {name, Model.make("system/type", data)}
  end

  @doc "Publish every core type at `/{local_peer}/system/type/{name}`."
  @spec publish(GenServer.server(), String.t()) :: :ok
  def publish(store, local_peer) do
    Enum.each(all(), fn {name, e} ->
      Store.bind(store, "/" <> local_peer <> "/system/type/" <> name, e)
    end)
  end
end
