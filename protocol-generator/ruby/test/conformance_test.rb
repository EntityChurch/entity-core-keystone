# frozen_string_literal: true

require_relative "test_helper"

class ConformanceTest < Minitest::Test
  def test_ecf_conformance_corpus_byte_identical
    bytes = File.binread(CorpusPaths.conformance_corpus)
    results = EntityCore::Conformance.run(bytes)

    failures = results.select { |r| r.status == :fail }
    passes = results.count { |r| r.status == :pass }

    unless failures.empty?
      puts "\n=== ECF conformance failures (#{failures.size}/#{results.size}) ==="
      failures.each { |r| puts "  #{r.id}: #{r.detail}" }
    end

    assert_empty failures, "#{failures.size} vector(s) failed; #{passes}/#{results.size} passed"
    assert_equal results.size, passes
    puts "\nECF corpus: #{passes}/#{results.size} PASS"
  end
end
