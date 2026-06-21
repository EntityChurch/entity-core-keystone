# frozen_string_literal: true

module EntityCore
  # Gem version. The keystone "0.1.0-pre" release line (lifecycle §Version-pin).
  #
  # RubyGems-correct pre-release spelling is DOT-separated `0.1.0.pre`, NOT the
  # SemVer-dash `0.1.0-pre`: `Gem::Version` treats a literal `-` as a `.pre.`
  # separator, so `Gem::Version.new("0.1.0-pre")` canonicalizes to the malformed
  # `0.1.0.pre.pre` (the dash -> `.pre`, then the literal `pre` appended). The
  # dotted `0.1.0.pre` canonicalizes to itself and `.prerelease?` is true -- the
  # idiomatic RubyGems pre-release channel (verified in-container, Ruby 3.4.4 /
  # RubyGems 3.6.7; see SPEC-AMBIGUITY-LOG A-RUBY-010). Prose/CHANGELOG/README
  # carry the cohort "0.1.0-pre" label; the gem coordinate is `0.1.0.pre`.
  VERSION = "0.1.0.pre"
end
