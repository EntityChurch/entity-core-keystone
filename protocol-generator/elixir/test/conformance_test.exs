defmodule EntityCore.ConformanceTest do
  use ExUnit.Case, async: true

  alias EntityCore.Conformance

  # Corpus path resolves from the project root (mix test CWD). Override with the
  # CORPUS env var to point at a different vendored version.
  @corpus System.get_env("CORPUS") ||
            Path.join(["..", "shared", "test-vectors", "v0.8.0", "conformance-vectors-v1.cbor"])

  test "ECF conformance corpus — byte-identical encode + decode-reject" do
    bytes = File.read!(@corpus)
    results = Conformance.run(bytes)

    failures = for {id, {:fail, detail}} <- results, do: {id, detail}
    passes = Enum.count(results, fn {_id, r} -> r == :pass end)

    if failures != [] do
      IO.puts("\n=== ECF conformance failures (#{length(failures)}/#{length(results)}) ===")
      for {id, detail} <- failures, do: IO.puts("  #{id}: #{inspect(detail, limit: :infinity)}")
    end

    assert failures == [], "#{length(failures)} vector(s) failed; #{passes}/#{length(results)} passed"
    assert passes == length(results)
    IO.puts("\nECF corpus: #{passes}/#{length(results)} PASS")
  end
end
