require "spec"
require "../src/entity_core"

module SpecHelper
  extend self

  # The pinned v0.8.0 wire-conformance corpus, relative to this repo's crystal
  # working dir (spec/ -> ../ -> crystal/ -> ../shared/...).
  CORPUS_PATH = File.expand_path(
    File.join(__DIR__, "..", "..", "shared", "test-vectors", "ecf-conformance", "conformance-vectors.cbor")
  )

  def corpus_bytes : Bytes
    File.open(CORPUS_PATH, "rb") do |f|
      slice = Bytes.new(f.size)
      f.read_fully(slice)
      slice
    end
  end

  def hex(str : String) : Bytes
    str.hexbytes
  end
end
