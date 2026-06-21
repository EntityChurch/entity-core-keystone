defmodule EntityCore.TypeRegistryTest do
  @moduledoc """
  A-OC-006 (peer #4 corroboration) — type-registry byte-diff. Renders all 53 core
  types (§9.5) from the in-code model (`EntityCore.TypeDefs`) and diffs each
  content_hash against the canonical type-registry-vectors-v1 (.diag
  source-of-truth). The peer-side dual of the S2 codec corpus: proves
  render-from-model output is byte-identical to the cross-impl Go-rendered registry.
  """
  use ExUnit.Case, async: true

  alias EntityCore.TypeDefs

  @diag System.get_env("TYPE_REGISTRY_DIAG") ||
          Path.join(["..", "shared", "test-vectors", "v0.8.0", "type-registry-vectors-v1.diag"])

  test "53 core types render byte-identical to the canonical registry vectors" do
    expected = parse_diag(File.read!(@diag))

    results =
      for {name, e} <- TypeDefs.all() do
        # our hash is 33 bytes: format byte 0x00 ‖ 32-byte digest. Compare the digest.
        <<_fmt, digest::binary-size(32)>> = e.hash
        got = Base.encode16(digest, case: :lower)
        {name, Map.get(expected, name), got}
      end

    failures = for {name, exp, got} <- results, exp != got, do: {name, exp, got}

    if failures != [] do
      IO.puts("\n=== type-registry failures (#{length(failures)}) ===")
      for {name, exp, got} <- failures, do: IO.puts("  #{name}\n    expected #{exp}\n    got      #{got}")
    end

    assert failures == [], "#{length(failures)} of #{length(results)} core types diverged"
    assert length(results) == 53
    IO.puts("\nType registry: #{length(results)}/53 core types byte-identical")
  end

  # Lines look like: { "name": "X", ... "content_hash": "ecf-sha256:<64hex>", ... }
  defp parse_diag(text) do
    re = ~r/"name":\s*"([^"]*)".*?"content_hash":\s*"ecf-sha256:([0-9a-f]+)"/

    Regex.scan(re, text)
    |> Map.new(fn [_, name, hex] -> {name, hex} end)
  end
end
