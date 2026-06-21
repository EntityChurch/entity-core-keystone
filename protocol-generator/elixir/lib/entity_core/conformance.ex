defmodule EntityCore.Conformance do
  @moduledoc """
  ECF conformance runner. Pure (no file IO): takes the corpus bytes, decodes
  them with this peer's own decoder (a decoder bug here is itself a conformance
  failure, per ENTITY-CBOR-ENCODING.md §E.3), and runs every vector.

  Vectors dispatch by category (the `id` prefix):

    * `content_hash` — `varint(format_code) <> SHA-2(ECF({type, data}))`
    * `peer_id`      — `ECF-text(Base58(varint(kt) <> varint(ht) <> digest))`
    * `signature`    — `Ed25519_sign(seed, ECF({type, data}))`
    * everything else (`float`/`int`/`map_keys`/`length`/`primitive`/`nested`/
      `envelope`) — plain `ECF encode(input)`
    * `decode_reject` — the decoder MUST reject the `canonical` wire bytes
  """

  alias EntityCore.{Cbor, Hash, PeerId, Signature}

  @type result :: {String.t(), :pass | {:fail, term()}}

  @doc """
  Run all encode_equal / decode_reject vectors in a decoded corpus.

  Returns a list of `{id, :pass | {:fail, detail}}`. Meta / non-vector entries
  (any `kind` outside the two conformance kinds) are skipped.
  """
  @spec run(binary()) :: [result()]
  def run(corpus_bytes) when is_binary(corpus_bytes) do
    {:ok, vectors} = Cbor.decode(corpus_bytes)

    vectors
    |> Enum.filter(&(is_map(&1) and &1["kind"] in ["encode_equal", "decode_reject"]))
    |> Enum.map(&run_vector/1)
  end

  defp run_vector(%{"id" => id, "kind" => "decode_reject", "canonical" => {:bytes, wire}}) do
    case Cbor.decode(wire) do
      {:error, _} -> {id, :pass}
      {:ok, value} -> {id, {:fail, {:expected_reject_but_decoded, value}}}
    end
  end

  defp run_vector(%{"id" => id, "kind" => "encode_equal", "input" => input, "canonical" => {:bytes, want}}) do
    got = produce(id, input)

    if got == want do
      {id, :pass}
    else
      {id, {:fail, %{got: hex(got), want: hex(want)}}}
    end
  rescue
    e -> {id, {:fail, {:raised, Exception.message(e)}}}
  end

  defp produce(id, input) do
    case category(id) do
      "content_hash" ->
        Hash.content_hash(input, Map.get(input, "format_code", 0))

      "peer_id" ->
        Cbor.encode(PeerId.format(input["key_type"], input["hash_type"], unwrap(input["digest"])))

      "signature" ->
        Signature.sign(unwrap(input["seed"]), input["entity"])

      _ ->
        Cbor.encode(input)
    end
  end

  defp category(id), do: id |> String.split(".") |> hd()

  defp unwrap({:bytes, b}), do: b

  defp hex(b), do: Base.encode16(b, case: :lower)
end
