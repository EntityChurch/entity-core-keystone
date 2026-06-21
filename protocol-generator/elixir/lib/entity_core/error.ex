defmodule EntityCore.Error do
  @moduledoc """
  Canonical error for the codec surface.

  Public fallible functions return `{:error, %EntityCore.Error{}}`; the
  `!`-suffixed convenience variants raise this exception instead. `kind` is a
  stable atom (`:non_canonical_ecf`, `:truncated`, `:bad_seed`, ...); `detail`
  carries optional context (the offending byte, depth, etc.).
  """

  @type kind ::
          :non_canonical_ecf
          | :truncated
          | :trailing_bytes
          | :bad_argument
          | :bad_simple
          | :duplicate_key
          | :invalid_utf8
          | :unsupported
          | :bad_seed
          | atom()

  @type t :: %__MODULE__{kind: kind(), detail: term()}

  defexception [:kind, :detail]

  @impl true
  def message(%__MODULE__{kind: kind, detail: nil}), do: "entity-core codec error: #{kind}"

  def message(%__MODULE__{kind: kind, detail: detail}),
    do: "entity-core codec error: #{kind} (#{inspect(detail)})"
end
