# Standalone conformance runner (non-ExUnit) — prints PASS/FAIL counts for the
# oracle loop. Usage (in-container):
#   mix run priv/conformance.exs
# Honors CORPUS / AGILITY_CORPUS env overrides.

defmodule Run do
  def main do
    ecf = System.get_env("CORPUS") || rel("conformance-vectors-v1.cbor")
    agi = System.get_env("AGILITY_CORPUS") || rel("agility-vectors-v1.cbor")

    ecf_results = ecf |> File.read!() |> EntityCore.Conformance.run()
    ecf_fail = Enum.count(ecf_results, &match?({_, {:fail, _}}, &1))
    ecf_pass = Enum.count(ecf_results, &match?({_, :pass}, &1))
    report("ECF corpus", ecf_pass, ecf_fail, ecf_results)

    agi_results = agi |> File.read!() |> EntityCore.Agility.run()
    agi_fail = Enum.count(agi_results, &match?({_, {:fail, _}}, &1))
    agi_pass = Enum.count(agi_results, &match?({_, :pass}, &1))
    agi_skip = Enum.count(agi_results, &match?({_, :skip}, &1))
    report("Agility corpus", agi_pass, agi_fail, agi_results)
    IO.puts("  (#{agi_skip} gates deferred to S3)")

    if ecf_fail + agi_fail > 0, do: System.halt(1)
  end

  defp rel(name), do: Path.join(["..", "shared", "test-vectors", "v0.8.0", name])

  defp report(label, pass, fail, results) do
    IO.puts("#{label}: #{pass}/#{pass + fail} PASS" <> if(fail > 0, do: " (#{fail} FAIL)", else: ""))
    for {id, {:fail, detail}} <- results, do: IO.puts("  FAIL #{id}: #{inspect(detail)}")
  end
end

Run.main()
