# frozen_string_literal: true

require_relative "test_helper"

class AgilityTest < Minitest::Test
  def test_crypto_agility_corpus_byte_pins_native
    bytes = File.binread(CorpusPaths.agility_corpus)
    gates = EntityCore::Agility.run(bytes)

    failures = gates.select { |g| g.status == :fail }
    passes = gates.count { |g| g.status == :pass }
    skips = gates.select { |g| g.status == :skip }.map(&:id)

    unless failures.empty?
      puts "\n=== agility failures (#{failures.size}) ==="
      failures.each { |g| puts "  #{g.id}: #{g.detail}" }
    end

    assert_empty failures, "#{failures.size} agility gate(s) failed"
    puts "\nAgility corpus: #{passes} crypto byte-pins PASS, " \
         "#{skips.size} deferred to S3 (#{skips.join(', ')})"
  end
end
