require "./spec_helper"

# The normative gate: run the full 71-vector wire-conformance corpus through this
# peer's OWN decoder + encoder and assert 71/71 byte-identical (66 encode_equal +
# 5 decode_reject). Corroboration/generator-robustness — a green verdict is
# COHORT-CONSISTENT (all impls pass one author's cross-blessed vectors), NOT
# independent convergence (ADR-0012).
describe EntityCore::Conformance do
  results = EntityCore::Conformance.run(SpecHelper.corpus_bytes)

  it "runs the expected number of vectors (71: 66 encode_equal + 5 decode_reject)" do
    results.size.should eq(71)
  end

  it "passes every vector byte-identical" do
    failures = results.select { |r| r.status != :pass }
    unless failures.empty?
      lines = failures.map { |r| "  #{r.id}: #{r.detail}" }.join("\n")
      fail "#{failures.size}/#{results.size} vector(s) failed:\n#{lines}"
    end
    results.count { |r| r.status == :pass }.should eq(71)
  end

  # Per-vector expectations so a regression names the exact failing id.
  EntityCore::Conformance.run(SpecHelper.corpus_bytes).each do |r|
    it "vector #{r.id} passes" do
      r.status.should eq(:pass), r.detail || ""
    end
  end
end
