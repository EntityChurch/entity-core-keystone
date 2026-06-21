defmodule EntityCore.Cbor do
  @moduledoc """
  Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder/decoder
  (ENTITY-CBOR-ENCODING.md v1.5). No Hex CBOR library gives ECF's guarantees,
  so the canonical layer is owned here.

  ## Value representation

  The decoded form is native Elixir terms, with two deliberate distinctions:

    * text strings -> Elixir binaries; byte strings -> `{:bytes, binary}` tuples
      (so the encoder can re-emit major type 2 vs 3 faithfully)
    * finite floats -> Elixir floats (natively distinct from integers); the
      non-finite specials -> `:nan` / `:inf` / `:neg_inf`

  | CBOR | Elixir |
  |---|---|
  | unsigned / negative int | integer |
  | float (finite) | float |
  | float NaN / +Inf / -Inf | `:nan` / `:inf` / `:neg_inf` |
  | text string | binary |
  | byte string | `{:bytes, binary}` |
  | array | list |
  | map | map (keys: binary or `{:bytes, _}`) |
  | bool | `true` / `false` |
  | null | `nil` |

  ## Canonical rules enforced (ECF §4.1, §9.1)

    * minimal integer encoding (Rule 1)
    * map keys sorted by encoded-length-then-lexicographic (Rule 2)
    * definite lengths only (Rule 3)
    * shortest float preserving value, with the Rule 4a special-float bytes
    * recursive major-type-6 (tag) rejection on decode (invariant N2)
    * empty map is the single byte `0xA0` (invariant N3)
  """

  alias EntityCore.Error

  # ── Limits (ECF §10.2) ───────────────────────────────────────────────────
  @max_depth 64

  # ═══════════════════════════════════════════════════════════════════════
  # Encode
  # ═══════════════════════════════════════════════════════════════════════

  @doc "Encode an Elixir term to canonical ECF bytes."
  @spec encode(term()) :: binary()
  def encode(value), do: enc(value)

  # Non-finite float sentinels (Rule 4a — exact bytes, no implementation choice).
  defp enc(:nan), do: <<0xF9, 0x7E, 0x00>>
  defp enc(:inf), do: <<0xF9, 0x7C, 0x00>>
  defp enc(:neg_inf), do: <<0xF9, 0xFC, 0x00>>

  # Simple values.
  defp enc(nil), do: <<0xF6>>
  defp enc(false), do: <<0xF4>>
  defp enc(true), do: <<0xF5>>

  # Integers (major type 0 / 1), minimal encoding.
  defp enc(n) when is_integer(n) and n >= 0, do: head(0, n)
  defp enc(n) when is_integer(n), do: head(1, -1 - n)

  # Floats — shortest encoding preserving value.
  defp enc(f) when is_float(f), do: enc_float(f)

  # Byte string (major type 2) vs text string (major type 3).
  defp enc({:bytes, b}) when is_binary(b), do: head(2, byte_size(b)) <> b
  defp enc(s) when is_binary(s), do: head(3, byte_size(s)) <> s

  # Array (major type 4).
  defp enc(list) when is_list(list) do
    body = list |> Enum.map(&enc/1) |> IO.iodata_to_binary()
    head(4, length(list)) <> body
  end

  # Map (major type 5) — keys sorted by encoded bytes, length-first.
  defp enc(map) when is_map(map) do
    body =
      map
      |> Enum.map(fn {k, v} -> {enc(k), enc(v)} end)
      |> Enum.sort_by(fn {ek, _} -> {byte_size(ek), ek} end)
      |> Enum.map(fn {ek, ev} -> [ek, ev] end)
      |> IO.iodata_to_binary()

    head(5, map_size(map)) <> body
  end

  defp enc(other), do: raise(%Error{kind: :unsupported, detail: other})

  # CBOR head byte + minimal argument (used by majors 0-5).
  defp head(major, n) when n < 24, do: <<major::3, n::5>>
  defp head(major, n) when n < 0x100, do: <<major::3, 24::5, n::8>>
  defp head(major, n) when n < 0x10000, do: <<major::3, 25::5, n::16>>
  defp head(major, n) when n < 0x100000000, do: <<major::3, 26::5, n::32>>
  defp head(major, n) when n < 0x10000000000000000, do: <<major::3, 27::5, n::64>>
  defp head(_major, n), do: raise(%Error{kind: :unsupported, detail: {:bignum, n}})

  # Float ladder: -0.0, then f16, then f32, else f64. The f16/f32 candidate is
  # accepted only if its exponent is not all-ones (silent overflow-to-Inf, see
  # the BEAM probe) AND it round-trips exactly.
  defp enc_float(f) do
    cond do
      f === -0.0 -> <<0xF9, 0x80, 0x00>>
      fits_f16?(f) -> <<0xF9>> <> <<f::float-16>>
      fits_f32?(f) -> <<0xFA>> <> <<f::float-32>>
      true -> <<0xFB, f::float-64>>
    end
  end

  defp fits_f16?(f) do
    candidate = <<f::float-16>>
    <<_sign::1, exp::5, _mant::10>> = candidate

    if exp == 0b11111 do
      false
    else
      <<rt::float-16>> = candidate
      rt === f
    end
  end

  defp fits_f32?(f) do
    candidate = <<f::float-32>>
    <<_sign::1, exp::8, _mant::23>> = candidate

    if exp == 0xFF do
      false
    else
      <<rt::float-32>> = candidate
      rt === f
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Decode
  # ═══════════════════════════════════════════════════════════════════════

  @doc """
  Decode canonical ECF bytes to an Elixir term.

  Returns `{:ok, term}` or `{:error, %EntityCore.Error{}}`. Rejects CBOR tags
  (major type 6) anywhere in the input (invariant N2 / ECF §6.3), indefinite
  lengths, and trailing bytes.
  """
  @spec decode(binary()) :: {:ok, term()} | {:error, Error.t()}
  def decode(bin) when is_binary(bin) do
    {value, rest} = do_decode(bin, 0)

    if rest == <<>> do
      {:ok, value}
    else
      {:error, %Error{kind: :trailing_bytes, detail: byte_size(rest)}}
    end
  rescue
    e in Error -> {:error, e}
  end

  @doc "Decode bang variant — raises `EntityCore.Error` on failure."
  @spec decode!(binary()) :: term()
  def decode!(bin) do
    case decode(bin) do
      {:ok, value} -> value
      {:error, err} -> raise err
    end
  end

  defp do_decode(_bin, depth) when depth > @max_depth,
    do: raise(%Error{kind: :non_canonical_ecf, detail: :max_depth})

  defp do_decode(<<major::3, info::5, rest::binary>>, depth) do
    case major do
      0 ->
        arg(info, rest)

      1 ->
        {n, r} = arg(info, rest)
        {-1 - n, r}

      2 ->
        {len, r} = arg(info, rest)
        <<chunk::binary-size(len), r2::binary>> = r
        {{:bytes, chunk}, r2}

      3 ->
        {len, r} = arg(info, rest)
        <<chunk::binary-size(len), r2::binary>> = r
        unless String.valid?(chunk), do: raise(%Error{kind: :invalid_utf8, detail: chunk})
        {chunk, r2}

      4 ->
        {len, r} = arg(info, rest)
        read_seq(len, r, depth + 1, [])

      5 ->
        {len, r} = arg(info, rest)
        read_map(len, r, depth + 1, %{})

      6 ->
        # Invariant N2 / ECF §6.3 — tags MUST be rejected on any data field.
        raise(%Error{kind: :non_canonical_ecf, detail: :cbor_tag})

      7 ->
        read_simple(info, rest)
    end
  end

  defp do_decode(<<>>, _depth), do: raise(%Error{kind: :truncated, detail: :empty})

  # Argument decode for majors 0-5. Rejects reserved (28-30) and indefinite (31).
  defp arg(info, rest) when info < 24, do: {info, rest}
  defp arg(24, <<n::8, rest::binary>>), do: {n, rest}
  defp arg(25, <<n::16, rest::binary>>), do: {n, rest}
  defp arg(26, <<n::32, rest::binary>>), do: {n, rest}
  defp arg(27, <<n::64, rest::binary>>), do: {n, rest}
  defp arg(info, _rest), do: raise(%Error{kind: :non_canonical_ecf, detail: {:bad_argument, info}})

  defp read_seq(0, rest, _depth, acc), do: {Enum.reverse(acc), rest}

  defp read_seq(n, rest, depth, acc) do
    {item, r} = do_decode(rest, depth)
    read_seq(n - 1, r, depth, [item | acc])
  end

  defp read_map(0, rest, _depth, acc), do: {acc, rest}

  defp read_map(n, rest, depth, acc) do
    {k, r1} = do_decode(rest, depth)
    {v, r2} = do_decode(r1, depth)
    if Map.has_key?(acc, k), do: raise(%Error{kind: :duplicate_key, detail: k})
    read_map(n - 1, r2, depth, Map.put(acc, k, v))
  end

  defp read_simple(20, rest), do: {false, rest}
  defp read_simple(21, rest), do: {true, rest}
  defp read_simple(22, rest), do: {nil, rest}
  defp read_simple(25, <<bytes::binary-size(2), rest::binary>>), do: {decode_f16(bytes), rest}
  defp read_simple(26, <<bytes::binary-size(4), rest::binary>>), do: {decode_f32(bytes), rest}
  defp read_simple(27, <<bytes::binary-size(8), rest::binary>>), do: {decode_f64(bytes), rest}
  defp read_simple(info, _rest), do: raise(%Error{kind: :non_canonical_ecf, detail: {:bad_simple, info}})

  # Special-float bit patterns are caught before extraction (the BEAM refuses to
  # materialize a NaN/Inf float and would raise on the bit match).
  defp decode_f16(<<sign::1, 0x1F::5, mant::10>>), do: nonfinite(sign, mant)
  defp decode_f16(<<1::1, 0::5, 0::10>>), do: -0.0
  defp decode_f16(bytes), do: (fn <<v::float-16>> -> v end).(bytes)

  defp decode_f32(<<sign::1, 0xFF::8, mant::23>>), do: nonfinite(sign, mant)
  defp decode_f32(<<1::1, 0::8, 0::23>>), do: -0.0
  defp decode_f32(bytes), do: (fn <<v::float-32>> -> v end).(bytes)

  defp decode_f64(<<sign::1, 0x7FF::11, mant::52>>), do: nonfinite(sign, mant)
  defp decode_f64(<<1::1, 0::11, 0::52>>), do: -0.0
  defp decode_f64(bytes), do: (fn <<v::float-64>> -> v end).(bytes)

  defp nonfinite(_sign, mant) when mant != 0, do: :nan
  defp nonfinite(1, 0), do: :neg_inf
  defp nonfinite(0, 0), do: :inf
end
