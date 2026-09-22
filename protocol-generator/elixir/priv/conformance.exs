# Standalone conformance runner (non-ExUnit) — prints PASS/FAIL counts for the
# oracle loop. Usage (in-container):
#   mix run priv/conformance.exs
# Honors CORPUS / AGILITY_CORPUS env overrides.

defmodule Run do
  def main do
    ecf = System.get_env("CORPUS") || rel("ecf-conformance/conformance-vectors.cbor")
    agi = System.get_env("AGILITY_CORPUS") || rel("crypto-agility/agility-vectors.cbor")

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

  # `name` carries its own corpus directory: each corpus is identified by NAME,
  # not by a shared version component (GUIDE-CONFORMANCE.md §5.1).
  defp rel(name), do: Path.join(["..", "shared", "test-vectors", name])

  defp report(label, pass, fail, results) do
    IO.puts("#{label}: #{pass}/#{pass + fail} PASS" <> if(fail > 0, do: " (#{fail} FAIL)", else: ""))
    for {id, {:fail, detail}} <- results, do: IO.puts("  FAIL #{id}: #{inspect(detail)}")
  end
end

Run.main()
