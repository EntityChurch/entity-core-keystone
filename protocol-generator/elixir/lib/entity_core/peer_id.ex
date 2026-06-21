defmodule EntityCore.PeerId do
  @moduledoc """
  Peer-id formatting/parsing (V7 §1.2 / §7.3):

      peer_id = Base58(varint(key_type) <> varint(hash_type) <> digest)

  `key_type` and `hash_type` are multicodec-style LEB128 varints (invariant N1).
  """

  alias EntityCore.{Base58, Varint}

  # key_type codes (V7 §1.5 seed table).
  @key_type_codes %{ed25519: 1, ed448: 2}

  @doc "Map a curve atom to its key_type code (`:ed25519` -> 1, `:ed448` -> 2)."
  @spec key_type_code(:ed25519 | :ed448) :: non_neg_integer()
  def key_type_code(curve), do: Map.fetch!(@key_type_codes, curve)

  @doc """
  Resolve an integer key_type code to its curve atom (key registry, V7 §1.5).

  Returns `{:ok, curve}` for an allocated code (`1` = Ed25519, `2` = Ed448), or
  `{:error, :unsupported_key_type}` otherwise. Code `255` (and every other
  unallocated/reserved code) is refused — this is the peer-layer mint guard the
  agility corpus's `VARINT-RESERVED-FF` vector exercises ("the entity does not
  construct").
  """
  @spec resolve_key_type(non_neg_integer()) :: {:ok, :ed25519 | :ed448} | {:error, :unsupported_key_type}
  def resolve_key_type(1), do: {:ok, :ed25519}
  def resolve_key_type(2), do: {:ok, :ed448}
  def resolve_key_type(code) when is_integer(code), do: {:error, :unsupported_key_type}

  @doc """
  Derive a peer-id from a raw public key (V7 §1.5 identity derivation).

  Size-cutoff rule: a key ≤ 32 bytes is an *identity-multihash*
  (`hash_type = 0x00`, digest = the key itself); a larger key is SHA-256-form
  (`hash_type = 0x01`, digest = SHA-256(key)). So Ed25519 (32 B) maps to
  `(0x01, 0x00, pubkey)` and Ed448 (57 B) to `(0x02, 0x01, sha256(pubkey))`.
  """
  @spec from_public_key(binary(), :ed25519 | :ed448) :: binary()
  def from_public_key(public_key, curve) when is_binary(public_key) do
    {hash_type, digest} =
      if byte_size(public_key) <= 32 do
        {0, public_key}
      else
        {1, :crypto.hash(:sha256, public_key)}
      end

    format(key_type_code(curve), hash_type, digest)
  end

  @doc "Format a peer-id string from its components."
  @spec format(non_neg_integer(), non_neg_integer(), binary()) :: binary()
  def format(key_type, hash_type, digest) when is_binary(digest) do
    Base58.encode(Varint.encode(key_type) <> Varint.encode(hash_type) <> digest)
  end

  @doc """
  Parse a peer-id string back to `{key_type, hash_type, digest}`.

  Returns `{:ok, {key_type, hash_type, digest}}` or `{:error, reason}`.
  """
  @spec parse(binary()) :: {:ok, {non_neg_integer(), non_neg_integer(), binary()}} | {:error, atom()}
  def parse(str) when is_binary(str) do
    with {:ok, raw} <- Base58.decode(str),
         {:ok, key_type, rest1} <- Varint.decode(raw),
         {:ok, hash_type, digest} <- Varint.decode(rest1) do
      {:ok, {key_type, hash_type, digest}}
    end
  end
end
