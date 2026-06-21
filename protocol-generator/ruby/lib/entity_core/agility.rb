# frozen_string_literal: true

require_relative "cbor"
require_relative "hash"
require_relative "peer_id"
require_relative "signature"

module EntityCore
  # Crypto-agility conformance runner (v7.67 corpus). Ruby reaches the *entire*
  # agility higher bar natively — Ed448 and SHA-384 both come from stdlib
  # +openssl+ (OpenSSL 3.x). This runner proves the crypto byte-pins from the
  # default container build, no FFI (contrast OCaml's hybrid-FFI Ed448).
  #
  # Scope at S2 (codec): the byte-pinned crypto outputs — Ed448 seed->pubkey,
  # peer-id §1.5 derivation, system/peer content hashes (SHA-256 + SHA-384),
  # Ed448 signatures, and each matrix peer's identity (pubkey/peer_id/
  # content_hash). At S3 (peer layer) the 7 remaining gates are picked up: the 3
  # matrix +root_cap+ gates (capability-token §3.6 CBOR shape — content_hash +
  # signature) and the 4 registry-interpretation +decode_reject+ gates (key_type
  # reserved-255 mint refusal + unallocated/reserved content-hash format codes).
  # All 35 pins now pass byte-identically (A-RUBY-007).
  module Agility
    Result = Struct.new(:id, :status, :detail)

    module_function

    def run(corpus_bytes)
      vectors = Cbor.decode(corpus_bytes)
      vectors.select { |v| v.is_a?(::Hash) }.flat_map { |v| run_vector(v) }
    end

    def run_vector(vector)
      id = vector["id"]
      case vector["kind"]
      when "ed448_seed_to_pubkey"
        [gate(id, Signature.public_key(vector["input"], :ed448), vector["canonical"])]
      when "peer_id_construct"
        input = vector["input"]
        produced = PeerId.from_public_key(input["public_key"], curve(input["key_type"]))
        [gate(id, produced, vector["canonical_base58"])]
      when "peer_entity_construct"
        input = vector["input"]
        [
          gate("#{id}.data_cbor", Cbor.encode(input["data"]), vector["canonical_data_cbor"]),
          gate("#{id}.content_hash", Hash.content_hash(input, 0), vector["canonical_content_hash"])
        ]
      when "ed448_sign"
        input = vector["input"]
        sig = Signature.sign_raw(input["secret_seed"], input["message"], :ed448)
        [gate(id, sig, vector["canonical"])]
      when "inherited_corpus_pin"
        [gate(id, Hash.content_hash(vector["input"], 0), vector["canonical_content_hash"])]
      when "content_hash_under_format"
        fmt = vector["input"]["content_hash_format"]
        [gate(id, Hash.content_hash(vector["input"], fmt), vector["canonical_content_hash"])]
      when "matrix_flow"
        check_peer("#{id}.peer_a", vector["input_peer_a"], vector, "a") +
          check_peer("#{id}.peer_b", vector["input_peer_b"], vector, "b") +
          check_root_cap("#{id}.root_cap", vector)
      when "decode_reject"
        check_decode_reject(id, vector)
      else
        []
      end
    end
    private_class_method :run_vector

    # Matrix root_cap (§3.6 cap-token shape — S3 peer-layer gate). Construct the
    # A→B root capability: granter = A's HOME-format identity hash (SingleSig =
    # raw system/hash bytes), grantee = B's SHA-256 identity hash, fixed-zero
    # timestamps. The cap-token entity travels under the ACTIVE format (SHA-256
    # in all three matrix vectors), so its content_hash uses format 0; A signs
    # the 33-byte wire content_hash (RFC-8032 deterministic). Field ordering is
    # handled by the codec's length-then-lex map sort.
    def check_root_cap(prefix, vector)
      grant = vector["input_cap_token_payload"]["grants"][0]
      cap_data = {
        "granter" => peer_a_home_hash(vector),
        "grantee" => peer_b_sha256_hash(vector),
        "grants" => [
          {
            "handlers" => { "include" => grant.dig("handlers", "include") || [] },
            "operations" => { "include" => grant.dig("operations", "include") || [] },
            "resources" => { "include" => grant.dig("resources", "include") || [] }
          }
        ],
        "created_at" => 0,
        "expires_at" => 0
      }
      token = { "type" => "system/capability/token", "data" => cap_data }
      content_hash = Hash.content_hash(token, 0)

      a = vector["input_peer_a"]
      sig = Signature.sign_raw(a["secret_seed"], content_hash, curve(a["key_type"]))

      [
        gate("#{prefix}.content_hash", content_hash, vector["expected_root_cap_content_hash"]),
        gate("#{prefix}.signature", sig, vector["expected_root_cap_signature"])
      ]
    end
    private_class_method :check_root_cap

    def peer_a_home_hash(vector)
      vector["expected_peer_a_content_hash"] ||
        vector["expected_peer_a_content_hash_sha384"] ||
        vector["expected_peer_a_content_hash_sha256"]
    end
    private_class_method :peer_a_home_hash

    def peer_b_sha256_hash(vector)
      vector["expected_peer_b_content_hash"] ||
        vector["expected_peer_b_content_hash_sha256"]
    end
    private_class_method :peer_b_sha256_hash

    # decode_reject (registry interpretation — S3 peer-layer key/hash registries).
    # An unallocated/reserved format code MUST surface as a non-resolving format
    # (the peer maps that to 400 unsupported_content_hash_format); a reserved
    # key_type (255) MUST NOT resolve to a curve ("the entity does not
    # construct"). Branch order matters: format-code framings (varint / single
    # byte) first, then the key_type integer (vector 2 carries only
    # input_decoded_integer + input_key_type_varint, no format-code field).
    def check_decode_reject(id, vector)
      if (prefix = vector["input_format_code_varint"])
        [reject_gate(id, Hash.resolve_wire_format(prefix))]
      elsif (byte = vector["input_format_code_byte"])
        [reject_gate(id, Hash.resolve_wire_format(byte))]
      elsif (kt = vector["input_decoded_integer"])
        [reject_gate(id, PeerId.resolve_key_type(kt))]
      else
        [skip(id)]
      end
    end
    private_class_method :check_decode_reject

    # A decode_reject gate PASSES when the registry lookup did NOT resolve (nil)
    # — i.e. the reserved/unallocated code is correctly refused.
    def reject_gate(id, resolved)
      if resolved.nil?
        Result.new(id, :pass, nil)
      else
        Result.new(id, :fail, { expected: :reject, resolved: resolved })
      end
    end
    private_class_method :reject_gate

    # Each matrix peer pins its identity derivation: seed -> pubkey -> peer_id +
    # the system/peer content_hash (the cross-key/cross-hash byte gates).
    def check_peer(prefix, input, vector, ab)
      c = curve(input["key_type"])
      pub = Signature.public_key(input["secret_seed"], c)
      peer_id = PeerId.from_public_key(pub, c)
      entity = {
        "type" => "system/peer",
        "data" => { "key_type" => input["key_type"], "public_key" => pub }
      }
      fmt = input["home_content_hash_format"] || 0
      content_hash = Hash.content_hash(entity, fmt)

      # The content-hash pin is named by the home format: M2 uses the plain
      # `..._content_hash`; M3/M6 use a format-suffixed `..._content_hash_sha256`
      # / `_sha384`. Resolve whichever the vector carries.
      suffix = { 0 => "sha256", 1 => "sha384" }[fmt]
      ch_want = vector["expected_peer_#{ab}_content_hash"] ||
                vector["expected_peer_#{ab}_content_hash_#{suffix}"]

      [
        gate("#{prefix}.pubkey", pub, vector["expected_peer_#{ab}_pubkey"]),
        gate("#{prefix}.peer_id", peer_id, vector["expected_peer_#{ab}_peer_id_base58"]),
        gate("#{prefix}.content_hash", content_hash, ch_want)
      ]
    end
    private_class_method :check_peer

    def curve(key_type)
      case key_type
      when "ed25519" then :ed25519
      when "ed448" then :ed448
      else raise UnsupportedValueError, "unknown matrix key_type: #{key_type.inspect}"
      end
    end
    private_class_method :curve

    def gate(id, got, want)
      if got == want
        Result.new(id, :pass, nil)
      else
        Result.new(id, :fail, { got: hexify(got), want: hexify(want) })
      end
    end
    private_class_method :gate

    def skip(id)
      Result.new(id, :skip, nil)
    end
    private_class_method :skip

    def hexify(value)
      value.is_a?(String) && value.encoding == Encoding::BINARY ? value.unpack1("H*") : value
    end
    private_class_method :hexify
  end
end
