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

  # ── §4.11 pre-admission refusal classification (0.8.2.25) ─────────────────

  @doc """
  The `{status, code, message}` §4.11 assigns a pre-admission failure's CAUSE.

  *"The frame obligation belongs to the class; the CODE belongs to the cause
  `[MUST]`"* — a single code for the class would answer an honest caller under the
  wrong reason and send them to the wrong layer.

  | cause | answer | stated at |
  |---|---|---|
  | connect-auth proof-of-possession | `401 authentication_failed` | §4.6/§4.7 — the connect handler's, not here |
  | envelope over the configured max | `413 payload_too_large` | §4.10(a), N14 |
  | resolution integrity (mis-keyed `included`) | `400 hash_mismatch` | §5.2a, §1.8 |
  | framing / never becomes an Envelope | `400 invalid_request` | §4.7, §4.11 |
  | root is neither EXECUTE nor EXECUTE_RESPONSE | `400 invalid_request` | §3.3, §4.11 — in `Peer.dispatch`, not here |

  THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
  non-conformant *"on the framing arm"* and gives its reason in the same sentence:
  `ENTITY-CBOR-ENCODING` defines it for CBOR tag-policy violations specifically, which
  that document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE
  rather than in conflict. Everything else this decoder calls non-canonical (a
  non-minimal head, an indefinite length, mis-ordered keys) is genuinely
  "non-canonical CBOR that never becomes an Envelope" and takes `invalid_request`.

  THE TAG DISCRIMINATOR IS `detail: :cbor_tag`, NOT THE MESSAGE. `EntityCore.Error`'s
  `detail` is part of its declared taxonomy and `:cbor_tag` is raised at exactly one
  site (`Cbor.do_decode`'s major-6 arm); `codec_test.exs` pins both the kind and the
  detail so the discriminator cannot drift silently. Matching on the rendered message
  would be one string edit away from re-collapsing the causes.

  The messages are a FIXED TABLE, never the internal exception text: a wire-visible
  string stays ASCII (two peers in this cohort have been killed at runtime by a
  non-ASCII byte in an encoded string, on two unrelated compilers), the internal texts
  carry section signs, and nothing here echoes attacker-supplied bytes back.
  """
  @spec pre_admission_refusal(Exception.t()) :: {non_neg_integer(), String.t(), String.t()}
  def pre_admission_refusal(%Model.HashMismatch{}),
    do: {400, "hash_mismatch", "an entity was addressed by a hash that does not bind to it"}

  def pre_admission_refusal(%EntityCore.Error{detail: :cbor_tag}),
    do: {400, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field"}

  def pre_admission_refusal(_other),
    do: {400, "invalid_request", "frame did not decode into an envelope"}

  @doc """
  The §4.10(a) over-size refusal (0.8.2.25 N14 raised its mood SHOULD -> MUST).

  Named here rather than inlined at the read site so the status/code pair lives beside
  the rest of §4.11's table and a test can assert the row without driving a socket.
  """
  @spec oversize_refusal() :: {non_neg_integer(), String.t(), String.t()}
  def oversize_refusal,
    do: {413, "payload_too_large", "inbound frame exceeds the configured maximum size"}

  @doc """
  The §4.11 framing refusal for a stream that ended MID-FRAME.

  A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing; a stream
  that ends mid-frame is a REFUSAL. On this substrate the distinction is the
  connection process's leftover `buffer` at `{:tcp_closed, _}` — non-empty means a
  frame that never completed, including a partial length prefix, which is why the test
  is "any bytes left" rather than "4 or more".
  """
  @spec truncated_refusal() :: {non_neg_integer(), String.t(), String.t()}
  def truncated_refusal,
    do: {400, "invalid_request", "frame did not decode into an envelope"}

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
