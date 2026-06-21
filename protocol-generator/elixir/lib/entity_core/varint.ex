defmodule EntityCore.Varint do
  @moduledoc """
  Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3, invariant N1).

  Used for the format-code / key-type / hash-type framing in content hashes and
  peer-ids. The currently-allocated codes are all < 0x80 (single byte), but the
  framing is routed through a real varint primitive so a future code ≥ 0x80
  extends correctly instead of breaking silently.
  """

  import Bitwise

  @doc "Encode a non-negative integer as unsigned LEB128."
  @spec encode(non_neg_integer()) :: binary()
  def encode(n) when is_integer(n) and n >= 0, do: encode(n, <<>>)

  defp encode(n, acc) when n < 0x80, do: acc <> <<n>>
  defp encode(n, acc), do: encode(n >>> 7, acc <> <<(n &&& 0x7F) ||| 0x80>>)

  @doc """
  Decode an unsigned LEB128 varint from the front of `bin`.

  Returns `{:ok, value, rest}` or `{:error, reason}`.
  """
  @spec decode(binary()) :: {:ok, non_neg_integer(), binary()} | {:error, atom()}
  def decode(bin) when is_binary(bin), do: decode(bin, 0, 0)

  defp decode(<<1::1, low::7, rest::binary>>, shift, acc),
    do: decode(rest, shift + 7, acc ||| low <<< shift)

  defp decode(<<0::1, low::7, rest::binary>>, shift, acc),
    do: {:ok, acc ||| low <<< shift, rest}

  defp decode(<<>>, _shift, _acc), do: {:error, :truncated_varint}
end
