defmodule EntityCore.MixProject do
  use Mix.Project

  @version "0.1.0-pre"
  # Keystone-naming peer id; the Hex registry id is the idiomatic snake_case
  # `entity_core_protocol` (a Hex package IS a BEAM package — the "elixir" suffix
  # is implicit). See profile.toml [publishing] + status/PHASE-S5.md.
  @source_url "https://github.com/entity-systems/entity-core-keystone"

  # entity-core-protocol-elixir — peer #4. Full core protocol peer (V7).
  # Zero runtime Hex dependencies: crypto is OTP stdlib :crypto; CBOR/base58/
  # varint are hand-rolled; the peer layer is GenServer/process-based (no deps);
  # ExUnit (tests) is stdlib.
  def project do
    [
      app: :entity_core_protocol,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_options: [warnings_as_errors: true],
      escript: escript(),
      deps: deps(),
      description: description(),
      package: package(),
      name: "entity_core_protocol",
      source_url: @source_url,
      docs: docs()
    ]
  end

  defp description do
    "A native-Elixir core protocol peer for the Entity Core protocol (V7): " <>
      "canonical-CBOR (ECF) codec, Ed25519/Ed448 identity + signatures, capability " <>
      "authorization, and the handshake/dispatch machinery. Zero runtime Hex dependencies."
  end

  # Hex package metadata (S5). License Apache-2.0 (S9 default, not overridden by
  # the Elixir profile). priv/ holds test fixtures only and is excluded; the
  # escript artifact + status/run scripts are not part of the library tarball.
  defp package do
    [
      name: "entity_core_protocol",
      licenses: ["Apache-2.0"],
      maintainers: ["Entity Core Protocol contributors"],
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE),
      links: %{
        "Keystone (generator)" => @source_url,
        "Conformance report" =>
          @source_url <> "/blob/main/protocol-generator/elixir/status/CONFORMANCE-REPORT.md"
      }
    ]
  end

  # Standalone conformance host (S3/S4): `mix escript.build` → ./entity_core_protocol
  defp escript do
    [main_module: EntityCore.Host, name: "entity_core_protocol"]
  end

  # HexDocs config. ex_doc is intentionally NOT a dependency yet (zero-dep +
  # sealed-offline stance; see PHASE-S5 §4) — this block is the spec hexdocs will
  # render from once ex_doc is added at publish-prep. `mix hex.build` does not
  # require it.
  defp docs do
    [
      main: "EntityCore",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}"
    ]
  end

  def application do
    # :crypto is the OTP stdlib app backing Ed25519/Ed448/SHA-2 (OpenSSL).
    [extra_applications: [:crypto]]
  end

  # Zero runtime Hex deps — see module comment. ex_doc/dialyxir deferred to
  # publish-prep (dev-only, pinned then) to keep the build sealed-offline.
  defp deps, do: []
end
