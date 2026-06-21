defmodule EntityCore.AgilityTest do
  use ExUnit.Case, async: true

  alias EntityCore.Agility

  @corpus System.get_env("AGILITY_CORPUS") ||
            Path.join(["..", "shared", "test-vectors", "v0.8.0", "agility-vectors-v1.cbor"])

  test "crypto-agility corpus — Ed448 + SHA-384 byte pins, native (no FFI)" do
    bytes = File.read!(@corpus)
    gates = Agility.run(bytes)

    failures = for {id, {:fail, detail}} <- gates, do: {id, detail}
    passes = Enum.count(gates, fn {_id, r} -> r == :pass end)
    skips = for {id, :skip} <- gates, do: id

    if failures != [] do
      IO.puts("\n=== agility failures (#{length(failures)}) ===")
      for {id, detail} <- failures, do: IO.puts("  #{id}: #{inspect(detail, limit: :infinity)}")
    end

    assert failures == [], "#{length(failures)} agility gate(s) failed"
    IO.puts("\nAgility corpus: #{passes} crypto byte-pins PASS, #{length(skips)} deferred to S3 (#{Enum.join(skips, ", ")})")
  end
end
