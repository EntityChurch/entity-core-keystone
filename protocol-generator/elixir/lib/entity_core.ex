defmodule EntityCore do
  @moduledoc """
  Entity Core Protocol — codec layer (peer #4, Elixir).

  Hand-rolled canonical CBOR (Entity Canonical Form) + content hashing + peer-id
  + Ed25519/Ed448 signatures, with zero runtime Hex dependencies (crypto is OTP
  stdlib `:crypto`; CBOR/base58/varint are hand-rolled).

  Entry points:

    * `EntityCore.Cbor` — ECF encode/decode
    * `EntityCore.Hash` — content hash construction
    * `EntityCore.PeerId` — peer-id format/parse
    * `EntityCore.Signature` — sign/verify/derive-pubkey
  """
end
