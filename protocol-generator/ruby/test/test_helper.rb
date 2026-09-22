# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "entity_core"

module CorpusPaths
  # Vendored test-vector corpus root (relative to protocol-generator/ruby/).
  VECTORS_DIR = File.expand_path("../../shared/test-vectors", __dir__)

  module_function

  # Each corpus is identified by its NAME, never a version stamp
  # (GUIDE-CONFORMANCE.md §5.1) — so the two live in separate directories and
  # there is no single "corpus version" component to join.
  def conformance_corpus
    ENV["CORPUS"] || File.join(VECTORS_DIR, "ecf-conformance", "conformance-vectors.cbor")
  end

  def agility_corpus
    ENV["AGILITY_CORPUS"] || File.join(VECTORS_DIR, "crypto-agility", "agility-vectors.cbor")
  end
end
