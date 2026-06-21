defmodule EntityCore.Agility do
  @moduledoc """
  Crypto-agility conformance runner (v7.67 corpus). Unlike the OCaml peer
  (A-OC-002, hybrid FFI Ed448), Elixir reaches the *entire* agility higher bar
  natively — Ed448 and SHA-384 both come from OTP `:crypto` (OpenSSL). This
  runner proves the crypto byte-pins from the default build, no FFI.

  Scope at S2 (codec): the byte-pinned crypto outputs — Ed448 seed→pubkey,
  peer-id identity derivation, system/peer content hashes (SHA-256 and SHA-384),
  Ed448 signatures, the matrix peers' identities, and the multi-byte varint
  format-reject machinery (invariant N1). Deferred to S3 (peer layer): the
  matrix `root_cap` gates (capability-token §3.6 CBOR shape) and the key_type
  reserved-255 mint refusal (key registry).
  """

  alias EntityCore.{Cbor, Hash, PeerId, Signature}

  @type gate :: {String.t(), :pass | :skip | {:fail, term()}}

  @spec run(binary()) :: [gate()]
  def run(corpus_bytes) when is_binary(corpus_bytes) do
    {:ok, vectors} = Cbor.decode(corpus_bytes)

    vectors
    |> Enum.filter(&is_map/1)
    |> Enum.flat_map(&run_vector/1)
  end

  defp run_vector(%{"id" => id, "kind" => "ed448_seed_to_pubkey"} = v) do
    [gate("#{id}", Signature.public_key(unwrap(v["input"]), :ed448), unwrap(v["canonical"]))]
  end

  defp run_vector(%{"id" => id, "kind" => "peer_id_construct"} = v) do
    input = v["input"]
    curve = curve_atom(input["key_type"])
    [gate("#{id}", PeerId.from_public_key(unwrap(input["public_key"]), curve), v["canonical_base58"])]
  end

  defp run_vector(%{"id" => id, "kind" => "peer_entity_construct"} = v) do
    input = v["input"]

    [
      gate("#{id}.data_cbor", Cbor.encode(input["data"]), unwrap(v["canonical_data_cbor"])),
      gate("#{id}.content_hash", Hash.content_hash(input, 0), unwrap(v["canonical_content_hash"]))
    ]
  end

  defp run_vector(%{"id" => id, "kind" => "ed448_sign"} = v) do
    input = v["input"]
    sig = Signature.sign_raw(unwrap(input["secret_seed"]), unwrap(input["message"]), :ed448)
    [gate("#{id}", sig, unwrap(v["canonical"]))]
  end

  defp run_vector(%{"id" => id, "kind" => "inherited_corpus_pin"} = v) do
    [gate("#{id}", Hash.content_hash(v["input"], 0), unwrap(v["canonical_content_hash"]))]
  end

  defp run_vector(%{"id" => id, "kind" => "content_hash_under_format"} = v) do
    fmt = v["input"]["content_hash_format"]
    [gate("#{id}", Hash.content_hash(v["input"], fmt), unwrap(v["canonical_content_hash"]))]
  end

  defp run_vector(%{"id" => id, "kind" => "decode_reject"} = v) do
    cond do
      prefix = v["input_format_code_varint"] ->
        [reject_gate(id, Hash.resolve_wire_format(unwrap(prefix)))]

      byte = v["input_format_code_byte"] ->
        [reject_gate(id, Hash.resolve_wire_format(unwrap(byte)))]

      # key_type reserved-255 mint refusal (S3 peer-layer key registry, §1.5): the
      # decoded integer MUST NOT resolve to a curve ("the entity does not construct").
      kt = v["input_decoded_integer"] ->
        [reject_gate(id, PeerId.resolve_key_type(kt))]

      true ->
        [{id, :skip}]
    end
  end

  defp run_vector(%{"id" => id, "kind" => "matrix_flow"} = v) do
    check_matrix_peer("#{id}.peer_a", v["input_peer_a"], v, "a") ++
      check_matrix_peer("#{id}.peer_b", v["input_peer_b"], v, "b") ++
      check_root_cap("#{id}.root_cap", v)
  end

  defp run_vector(_other), do: []

  # ── Matrix root_cap (§3.6 cap-token shape, S3) ─────────────────────────────
  #
  # Construct the A→B root capability per SEEDS.md §2.3-§2.5: granter = A's
  # home-format identity hash (SingleSig = raw system/hash bytes), grantee = B's
  # SHA-256 identity hash, fixed-zero timestamps. The cap-token entity travels
  # under the ACTIVE format (SHA-256 in all three matrix vectors), so its
  # content_hash uses format 0. A signs the cap-token's wire content_hash
  # (RFC 8032 deterministic).
  defp check_root_cap(prefix, v) do
    cap_data = %{
      "granter" => {:bytes, peer_a_home_hash(v)},
      "grantee" => {:bytes, peer_b_sha256_hash(v)},
      "grants" => [
        %{
          "handlers" => %{"include" => []},
          "operations" => %{"include" => []},
          "resources" => %{"include" => ["system/validate/matrix/*"]}
        }
      ],
      "created_at" => 0,
      "expires_at" => 0
    }

    content_hash = Hash.content_hash(%{"type" => "system/capability/token", "data" => cap_data}, 0)

    a = v["input_peer_a"]
    sig = Signature.sign_raw(unwrap(a["secret_seed"]), content_hash, curve_atom(a["key_type"]))

    [
      gate("#{prefix}.content_hash", content_hash, unwrap(v["expected_root_cap_content_hash"])),
      gate("#{prefix}.signature", sig, unwrap(v["expected_root_cap_signature"]))
    ]
  end

  defp peer_a_home_hash(v) do
    unwrap(v["expected_peer_a_content_hash"] || v["expected_peer_a_content_hash_sha384"] || v["expected_peer_a_content_hash_sha256"])
  end

  defp peer_b_sha256_hash(v) do
    unwrap(v["expected_peer_b_content_hash"] || v["expected_peer_b_content_hash_sha256"])
  end

  # ── Matrix per-peer identity gates (pubkey / peer_id / content_hash@home) ──
  defp check_matrix_peer(prefix, peer, v, ab) do
    curve = curve_atom(peer["key_type"])
    seed = unwrap(peer["secret_seed"])
    home_fmt = peer["home_content_hash_format"]
    {pub, _} = :crypto.generate_key(:eddsa, curve, seed)
    pid = PeerId.from_public_key(pub, curve)

    entity = %{
      "type" => "system/peer",
      "data" => %{"key_type" => peer["key_type"], "public_key" => {:bytes, pub}}
    }

    [
      gate("#{prefix}.pubkey", pub, unwrap(v["expected_peer_#{ab}_pubkey"])),
      gate("#{prefix}.peer_id", pid, v["expected_peer_#{ab}_peer_id_base58"]),
      gate("#{prefix}.content_hash", Hash.content_hash(entity, home_fmt), expected_content_hash(v, ab))
    ]
  end

  # The expected content-hash key varies by home format (M2 plain; M3/M6 suffixed).
  defp expected_content_hash(v, ab) do
    key =
      Enum.find(
        ["expected_peer_#{ab}_content_hash", "expected_peer_#{ab}_content_hash_sha256", "expected_peer_#{ab}_content_hash_sha384"],
        &Map.has_key?(v, &1)
      )

    unwrap(v[key])
  end

  defp gate(id, got, want) when got == want, do: {id, :pass}
  defp gate(id, got, want), do: {id, {:fail, %{got: hex(got), want: hex(want)}}}

  defp reject_gate(id, {:error, _}), do: {id, :pass}
  defp reject_gate(id, {:ok, alg}), do: {id, {:fail, {:expected_reject_but_resolved, alg}}}

  defp curve_atom("ed25519"), do: :ed25519
  defp curve_atom("ed448"), do: :ed448

  defp unwrap({:bytes, b}), do: b
  defp unwrap(b) when is_binary(b), do: b

  defp hex(b) when is_binary(b), do: Base.encode16(b, case: :lower)
  defp hex(other), do: inspect(other)
end
