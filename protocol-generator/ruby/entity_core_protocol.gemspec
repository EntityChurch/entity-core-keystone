# frozen_string_literal: true

require_relative "lib/entity_core/version"

Gem::Specification.new do |spec|
  spec.name        = "entity_core_protocol"
  spec.version     = EntityCore::VERSION # "0.1.0.pre" — the keystone 0.1.0-pre line (A-RUBY-010)
  spec.summary     = "Entity Core Protocol — native Ruby core peer (V7 Layers 0-4)"
  spec.description = "A spec-first, zero-runtime-gem-dependency Ruby core peer for the " \
                     "Entity Core protocol (V7 Layers 0-4): a hand-rolled canonical ECF " \
                     "CBOR codec (length-then-lex map order, shortest-float, recursive " \
                     "tag-6 rejection), hand-rolled base58 + multicodec LEB128 varint, and " \
                     "Ed25519 + Ed448 identity/signatures + SHA-256/384 via stdlib openssl " \
                     "(no FFI). validate-peer --profile core: 0 FAIL against the Go oracle."
  spec.authors  = ["Entity Core Protocol contributors"]
  spec.license  = "Apache-2.0"

  # Ruby 3.2 is the floor: `Data.define` (immutable value objects) is a 3.2
  # feature the model layer uses; the stdlib openssl raw-EdDSA + Ed448 surface
  # used by the crypto shim needs the openssl gem >= 3.0 (bundled with 3.2+).
  spec.required_ruby_version = ">= 3.2"

  # Shipped surface: the library only. exe/ holds the S4 conformance host +
  # wire-conformance driver (test/oracle tooling, NOT a published executable) and
  # is intentionally excluded; test/ and the status docs are likewise not packed.
  spec.files = Dir["lib/**/*.rb"] + ["LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]

  # Core peer has ZERO runtime gem dependencies — crypto + hashing from stdlib
  # openssl/digest; CBOR/base58/varint hand-rolled; Minitest + Rake are dev-only
  # DEFAULT gems (ship with Ruby) declared in the Gemfile, not here.
  spec.metadata["rubygems_mfa_required"]   = "true"
  # homepage / source_code_uri / homepage_uri / changelog_uri are intentionally
  # left UNSET: RubyGems validates link-metadata as real http(s) URLs, and the
  # repository_url is TBD until first publish ([publishing] in profile.toml; the
  # peer lives in-repo under protocol-generator/ruby/ today). The operator sets
  # these to the published URLs at publish time (see status/PHASE-S5.md §handoff).
end
