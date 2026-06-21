defmodule EntityCore.Hash do
  @moduledoc """
  Content hash construction (ENTITY-CBOR-ENCODING.md §4.2):

      content_hash = varint(format_code) <> hash_alg(ECF({type, data}))

  The default format code `0x00` is `ecfv1-sha256`; `0x01` is `ecfv1-sha384`
  (agility). The `format_code` is NOT part of the hashed entity — only
  `{type, data}` is hashed. The varint prefix is multicodec-style LEB128, so a
  code ≥ 0x80 extends to multiple bytes (invariant N1).
  """

  alias EntityCore.{Cbor, Varint}

  @doc """
  Compute the wire content hash (varint format-code prefix + digest) over an
  entity. `entity` is a map carrying at least `"type"` and `"data"`.
  """
  @spec content_hash(map(), non_neg_integer()) :: binary()
  def content_hash(entity, format_code \\ 0) when is_map(entity) do
    hashed = %{"type" => Map.fetch!(entity, "type"), "data" => Map.fetch!(entity, "data")}
    digest = :crypto.hash(hash_alg(format_code), Cbor.encode(hashed))
    Varint.encode(format_code) <> digest
  end

  # Allocated content-hash format codes (V7 §1.2 / §4.3 registry — active set).
  @allocated_formats %{0 => :sha256, 1 => :sha384}

  @doc """
  Resolve an integer format code to its digest algorithm (receive side).

  Returns `{:ok, alg}` for an allocated code, or
  `{:error, :unsupported_content_hash_format}` otherwise. This is the strict
  receive-side interpretation; the construct side (`content_hash/2`) is lenient
  for synthetic high codes that the corpus pins only for the varint prefix.
  """
  @spec resolve_format(non_neg_integer()) :: {:ok, :sha256 | :sha384} | {:error, :unsupported_content_hash_format}
  def resolve_format(code) when is_integer(code) do
    case Map.fetch(@allocated_formats, code) do
      {:ok, alg} -> {:ok, alg}
      :error -> {:error, :unsupported_content_hash_format}
    end
  end

  @doc """
  Decode a multicodec-style LEB128 format-code prefix and resolve it (invariant
  N1 — the multi-byte varint decoder fires before the registry check, so a code
  ≥ 0x80 is decoded, not short-circuited).
  """
  @spec resolve_wire_format(binary()) :: {:ok, :sha256 | :sha384} | {:error, atom()}
  def resolve_wire_format(prefix) when is_binary(prefix) do
    case Varint.decode(prefix) do
      {:ok, code, _rest} -> resolve_format(code)
      {:error, _} = err -> err
    end
  end

  @doc "Display form: `ecfv1-sha256:<hex>` (logs/UI only — never on the wire)."
  @spec to_string(binary()) :: binary()
  def to_string(<<0x00, digest::binary-size(32)>>), do: "ecfv1-sha256:" <> Base.encode16(digest, case: :lower)
  def to_string(<<0x01, digest::binary-size(48)>>), do: "ecfv1-sha384:" <> Base.encode16(digest, case: :lower)

  # Map an allocated content-hash format code to its OTP :crypto digest atom.
  # Code 0x00 = SHA-256 (required floor); 0x01 = SHA-384 (agility). Codes outside
  # the allocated set still hash with SHA-256 here — the codec corpus exercises
  # only the varint *prefix* bytes for synthetic high codes (content_hash.4);
  # the peer layer (S3) rejects unallocated codes as unsupported_content_hash_format.
  defp hash_alg(0x01), do: :sha384
  defp hash_alg(_), do: :sha256
end
