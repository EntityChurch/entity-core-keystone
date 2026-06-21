defmodule EntityCore.Entity do
  @moduledoc """
  The materialized entity — the `{type, data, content_hash}` form (V7 §1.1, §3.4).

  `data` is a decoded ECF value (the native term form of `EntityCore.Cbor`: a map
  with binary keys, integers, lists, `{:bytes, _}`, …). `hash` is the 33-byte wire
  `content_hash` (format byte ‖ digest). An entity's content_hash covers only
  `{type, data}` (§1.1); the wire form additionally carries `content_hash` so
  entities are self-describing across serialization (§3.1).
  """

  @enforce_keys [:type, :data, :hash]
  defstruct [:type, :data, :hash]

  @type t :: %__MODULE__{type: String.t(), data: term(), hash: binary()}
end
