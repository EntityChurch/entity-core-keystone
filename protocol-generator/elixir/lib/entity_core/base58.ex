defmodule EntityCore.Base58 do
  @moduledoc """
  Base58 (Bitcoin alphabet) encode/decode, hand-rolled (no Hex dependency).

  Used for peer-id formatting/parsing (V7 §1.2). Leading zero bytes map to a
  leading `"1"` each, per the standard Base58 convention.
  """

  @alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @doc "The Bitcoin Base58 alphabet (peer-id segment-character membership test)."
  @spec alphabet() :: binary()
  def alphabet, do: @alphabet

  @doc "Encode a binary as a Base58 string."
  @spec encode(binary()) :: binary()
  def encode(bin) when is_binary(bin) do
    zeros = leading_zeros(bin, 0)
    body =
      case :binary.decode_unsigned(bin, :big) do
        0 -> []
        n -> encode_int(n, [])
      end

    String.duplicate("1", zeros) <> IO.iodata_to_binary(body)
  end

  @doc """
  Decode a Base58 string back to a binary.

  Returns `{:ok, binary}` or `{:error, reason}`.
  """
  @spec decode(binary()) :: {:ok, binary()} | {:error, atom()}
  def decode(str) when is_binary(str) do
    chars = :binary.bin_to_list(str)

    if Enum.all?(chars, &(:binary.match(@alphabet, <<&1>>) != :nomatch)) do
      ones = leading_ones(chars, 0)
      n = Enum.reduce(chars, 0, fn c, acc -> acc * 58 + index_of(c) end)
      body = if n == 0, do: <<>>, else: :binary.encode_unsigned(n, :big)
      {:ok, :binary.copy(<<0>>, ones) <> body}
    else
      {:error, :invalid_base58}
    end
  end

  defp encode_int(0, acc), do: acc
  defp encode_int(n, acc), do: encode_int(div(n, 58), [:binary.at(@alphabet, rem(n, 58)) | acc])

  defp leading_zeros(<<0, rest::binary>>, n), do: leading_zeros(rest, n + 1)
  defp leading_zeros(_, n), do: n

  defp leading_ones([?1 | rest], n), do: leading_ones(rest, n + 1)
  defp leading_ones(_, n), do: n

  defp index_of(char), do: index_of(char, 0)
  defp index_of(char, i), do: if(:binary.at(@alphabet, i) == char, do: i, else: index_of(char, i + 1))
end
