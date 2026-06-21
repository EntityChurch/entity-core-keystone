defmodule EntityCore.Wire do
  @moduledoc """
  Wire framing (§1.6) and the message builders (§3.2 EXECUTE, §3.3
  EXECUTE_RESPONSE). Frame := `[4-byte BE length][CBOR payload]`; the payload is a
  CBOR-encoded `system/protocol/envelope` (§3.1). The transport owns the socket
  (`:gen_tcp`); this module owns the byte shapes.
  """

  alias EntityCore.{Cbor, Entity, Model}
  alias EntityCore.Model.Envelope

  @max_frame 16 * 1024 * 1024

  @doc "The §1.6 SHOULD frame bound (16 MiB)."
  @spec max_frame() :: pos_integer()
  def max_frame, do: @max_frame

  # ── envelope <-> frame ────────────────────────────────────────────────────

  @doc "Encode an envelope to its CBOR frame payload (no length prefix)."
  @spec frame_of_envelope(Envelope.t()) :: binary()
  def frame_of_envelope(%Envelope{} = env), do: Cbor.encode(Model.envelope_to_cbor(env))

  @doc "Decode a CBOR frame payload to an envelope (raises on malformed bytes)."
  @spec envelope_of_frame(binary()) :: Envelope.t()
  def envelope_of_frame(payload) when is_binary(payload) do
    case Cbor.decode(payload) do
      {:ok, c} -> Model.envelope_of_cbor(c)
      {:error, err} -> raise err
    end
  end

  @doc "Prefix a payload with its 4-byte big-endian length (the on-wire frame)."
  @spec encode_frame(binary()) :: binary()
  def encode_frame(payload) when is_binary(payload), do: <<byte_size(payload)::32-big, payload::binary>>

  # ── EXECUTE_RESPONSE builder (§3.3) ───────────────────────────────────────

  @doc "Build an EXECUTE_RESPONSE entity (§3.3)."
  @spec make_response(String.t(), non_neg_integer(), Entity.t()) :: Entity.t()
  def make_response(request_id, status, %Entity{} = result) do
    Model.make("system/protocol/execute/response", %{
      "request_id" => request_id,
      "status" => status,
      "result" => Model.to_cbor(result)
    })
  end

  # ── EXECUTE builder (§3.2) — used by the §6.13(b) handler outbound seam ────

  @doc "Build an EXECUTE entity (§3.2). `resource` (a CBOR value) is optional."
  @spec make_execute(keyword()) :: Entity.t()
  def make_execute(opts) do
    request_id = Keyword.fetch!(opts, :request_id)
    uri = Keyword.fetch!(opts, :uri)
    operation = Keyword.fetch!(opts, :operation)
    %Entity{} = params = Keyword.fetch!(opts, :params)
    author = Keyword.fetch!(opts, :author)
    capability = Keyword.fetch!(opts, :capability)

    base = %{
      "request_id" => request_id,
      "uri" => uri,
      "operation" => operation,
      "params" => Model.to_cbor(params),
      "author" => {:bytes, author},
      "capability" => {:bytes, capability}
    }

    data =
      case Keyword.get(opts, :resource) do
        nil -> base
        resource -> Map.put(base, "resource", resource)
      end

    Model.make("system/protocol/execute", data)
  end

  @doc "Build a `system/protocol/error` result entity (§3.3)."
  @spec error_result(String.t(), String.t() | nil) :: Entity.t()
  def error_result(code, message \\ nil) do
    data = %{"code" => code}
    data = if message, do: Map.put(data, "message", message), else: data
    Model.make("system/protocol/error", data)
  end

  @doc "The §3.2 empty-params entity: `primitive/any` whose data is the empty map."
  @spec empty_params() :: Entity.t()
  def empty_params, do: Model.make("primitive/any", %{})
end
