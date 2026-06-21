# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "entity_core"

module CorpusPaths
  # Vendored test-vector corpus root (relative to protocol-generator/ruby/).
  VECTORS_DIR = File.expand_path("../../shared/test-vectors", __dir__)

  module_function

  def corpus_version
    ENV.fetch("CORPUS_VERSION", "v0.8.0")
  end

  def conformance_corpus
    ENV["CORPUS"] || File.join(VECTORS_DIR, corpus_version, "conformance-vectors-v1.cbor")
  end

  def agility_corpus
    ENV["AGILITY_CORPUS"] || File.join(VECTORS_DIR, corpus_version, "agility-vectors-v1.cbor")
  end
end
