defmodule EntityCore.Model do
  @moduledoc """
  Entity construction, the protocol envelope (§3.1), and the field accessors the
  peer layer reads entity data through. Sits directly on the S2 codec
  (`EntityCore.Cbor` / `EntityCore.Hash`).

  Spec-first note (§1.8 fidelity): `of_cbor/1` recomputes the hash from
  `{type, data}` and validates it against the carried `content_hash` — we trust
  our own hash, not the wire bytes (§5.2 validate-before-trust). A mismatch (or a
  malformed entity/envelope) raises `EntityCore.Model.BadEntity`, which the wire
  layer maps to a dropped/closed connection (§3.3).
  """

  alias EntityCore.{Entity, Hash}

  defmodule BadEntity do
    @moduledoc "Raised on a malformed or fidelity-violating entity/envelope (§1.8)."
    defexception [:message]
  end

  @doc "Construct a materialized entity, computing its content_hash (format `code`, default 0)."
  @spec make(String.t(), term(), non_neg_integer()) :: Entity.t()
  def make(type, data, code \\ 0) when is_binary(type) do
    %Entity{type: type, data: data, hash: Hash.content_hash(%{"type" => type, "data" => data}, code)}
  end

  # ── field accessors (data is a map with binary keys) ──────────────────────

  @doc "Raw field value from an entity's data map (or `nil`)."
  @spec field(Entity.t(), String.t()) :: term()
  def field(%Entity{data: data}, key), do: map_get(data, key)

  @doc "Get a key from a decoded CBOR map (native form), or `nil` for non-maps/missing."
  @spec map_get(term(), String.t()) :: term()
  def map_get(data, key) when is_map(data), do: Map.get(data, key)
  def map_get(_other, _key), do: nil

  @doc "A text (string) field, or `nil`."
  @spec text_field(Entity.t(), String.t()) :: String.t() | nil
  def text_field(e, key) do
    case field(e, key) do
      s when is_binary(s) -> s
      _ -> nil
    end
  end

  @doc "A byte-string field's raw bytes, or `nil`."
  @spec bytes_field(Entity.t(), String.t()) :: binary() | nil
  def bytes_field(e, key) do
    case field(e, key) do
      {:bytes, b} -> b
      _ -> nil
    end
  end

  @doc "An unsigned-integer field, or `nil`."
  @spec uint_field(Entity.t(), String.t()) :: non_neg_integer() | nil
  def uint_field(e, key) do
    case field(e, key) do
      n when is_integer(n) and n >= 0 -> n
      _ -> nil
    end
  end

  @doc "Lowercase hex of a binary (tree-path / display use; never on the wire)."
  @spec hex(binary()) :: String.t()
  def hex(b) when is_binary(b), do: Base.encode16(b, case: :lower)

  # ── wire form: entity carries its content_hash ────────────────────────────

  @doc "Wire form of an entity (a CBOR map carrying `content_hash`)."
  @spec to_cbor(Entity.t()) :: map()
  def to_cbor(%Entity{type: type, data: data, hash: hash}) do
    %{"type" => type, "data" => data, "content_hash" => {:bytes, hash}}
  end

  @doc """
  Parse a wire entity (a decoded CBOR map), recompute its hash and validate
  against the carried `content_hash` (§1.8). Returns the recomputed-canonical
  entity. Raises `BadEntity` on a malformed entity or hash mismatch.
  """
  @spec of_cbor(term()) :: Entity.t()
  def of_cbor(c) do
    type =
      case map_get(c, "type") do
        s when is_binary(s) -> s
        _ -> raise BadEntity, message: "entity: missing/invalid type"
      end

    data =
      case map_get(c, "data") do
        nil -> raise BadEntity, message: "entity: missing data"
        d -> d
      end

    e = make(type, data)

    case map_get(c, "content_hash") do
      {:bytes, h} when h != e.hash ->
        raise BadEntity, message: "entity: content_hash mismatch (§1.8 fidelity)"

      _ ->
        e
    end
  end

  # ── envelope (§3.1) ────────────────────────────────────────────────────────

  defmodule Envelope do
    @moduledoc "Protocol envelope: a root entity + an included map (content_hash → entity)."
    @enforce_keys [:root]
    defstruct root: nil, included: %{}
    @type t :: %__MODULE__{root: EntityCore.Entity.t(), included: %{binary() => EntityCore.Entity.t()}}
  end

  @doc "Look up an included entity by its content_hash bytes."
  @spec included_get(Envelope.t(), binary()) :: Entity.t() | nil
  def included_get(%Envelope{included: included}, h), do: Map.get(included, h)

  @doc "Encode an envelope to its wire CBOR map."
  @spec envelope_to_cbor(Envelope.t()) :: map()
  def envelope_to_cbor(%Envelope{root: root, included: included}) do
    inc = for {h, e} <- included, into: %{}, do: {{:bytes, h}, to_cbor(e)}
    %{"root" => to_cbor(root), "included" => inc}
  end

  @doc """
  Parse an envelope from a decoded CBOR map. Validates each included entity's
  content_hash against its map key (§3.1). Raises `BadEntity` on violation.
  """
  @spec envelope_of_cbor(term()) :: Envelope.t()
  def envelope_of_cbor(c) do
    root =
      case map_get(c, "root") do
        nil -> raise BadEntity, message: "envelope: missing root"
        r -> of_cbor(r)
      end

    included =
      case map_get(c, "included") do
        nil ->
          %{}

        m when is_map(m) ->
          for {k, v} <- m, into: %{} do
            case k do
              {:bytes, h} ->
                e = of_cbor(v)

                if h != e.hash do
                  raise BadEntity, message: "envelope: included key != entity content_hash"
                end

                {h, e}

              _ ->
                raise BadEntity, message: "envelope: included key not a byte string"
            end
          end

        _ ->
          raise BadEntity, message: "envelope: included not a map"
      end

    %Envelope{root: root, included: included}
  end
end
