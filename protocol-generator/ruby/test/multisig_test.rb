# frozen_string_literal: true

require_relative "test_helper"

# §3.6 / §5.5 K-of-N multi-signature ACCEPT-path unit checks.
#
# The Go validate-peer oracle's `multisig` category is dominated by malformed→403
# REJECT probes, which a fail-closed peer passes VACUOUSLY (it rejects
# everything). Its one accept probe (valid_2of3_peer_signed_accepted) only runs
# when the harness provisions the peer keypair so the validator can co-sign AS
# the peer — before that it SKIPs, hiding a frame-only implementation. This test
# guards the genuine-accept direction unconditionally: it builds a real 2-of-3
# quorum cap and drives Capability.verify_capability_chain directly — a valid
# co-signed quorum → :allow; each broken invariant → :deny (M3 structure, M4
# distinct-signer threshold, M6 local ∈ signers).
class MultisigTest < Minitest::Test
  include EntityCore

  LOCAL = ("\x11".b * 32)
  S2 = ("\x22".b * 32)
  S3 = ("\x33".b * 32)
  S4 = ("\x44".b * 32)

  # Build a K-of-N quorum cap + its envelope-included set. +signers+ = the seed
  # list of the quorum members; +signer_seeds+ = which of them actually co-sign;
  # the verifying peer is LOCAL.
  def build(signers:, threshold:, signer_seeds:)
    ids = signers.map { |s| Identity.of_seed(s) }
    grantee = Identity.of_seed(S4)
    cap = Entity.make(
      "system/capability/token",
      {
        "granter" => { "signers" => ids.map(&:identity_hash), "threshold" => threshold },
        "grantee" => grantee.identity_hash,
        "grants" => [{
          "resources" => { "include" => ["/*/*"] },
          "operations" => { "include" => ["*"] },
          "handlers" => { "include" => ["*"] }
        }]
      }
    )
    sigs = signer_seeds.map { |s| Identity.of_seed(s).sign(cap) }
    entities = ids.map(&:peer_entity) + [grantee.peer_entity] + sigs
    included = entities.map { |e| Envelope::Included.new(hash: e.content_hash, entity: e) }
    [cap, included]
  end

  def verify(cap, included)
    Capability.verify_capability_chain(Identity.of_seed(LOCAL).peer_id, Store.new, cap, included)
  end

  # The accept path the oracle's reject-only probes cannot cover.
  def test_valid_2of3_peer_signed_accepted
    cap, incl = build(signers: [LOCAL, S2, S3], threshold: 2, signer_seeds: [LOCAL, S2])
    assert_equal :allow, verify(cap, incl),
                 "a valid co-signed 2-of-3 quorum (M4 met + M6 local∈signers) must be ALLOWed"
  end

  def test_below_threshold_denied
    cap, incl = build(signers: [LOCAL, S2, S3], threshold: 2, signer_seeds: [LOCAL])
    assert_equal :deny, verify(cap, incl),
                 "only 1 of 2 required signatures (M4 quorum unmet) must be DENYed"
  end

  def test_local_not_in_signers_denied
    cap, incl = build(signers: [S2, S3, S4], threshold: 2, signer_seeds: [S2, S3])
    assert_equal :deny, verify(cap, incl),
                 "local peer absent from the signer set (M6) must be DENYed"
  end

  def test_duplicate_signers_denied
    cap, incl = build(signers: [LOCAL, S2, S2], threshold: 2, signer_seeds: [LOCAL, S2])
    assert_equal :deny, verify(cap, incl),
                 "duplicate signers in the quorum (M3 structure) must be DENYed"
  end

  def test_threshold_below_two_denied
    cap, incl = build(signers: [LOCAL, S2, S3], threshold: 1, signer_seeds: [LOCAL, S2])
    assert_equal :deny, verify(cap, incl),
                 "threshold < 2 (degenerate quorum, M3 structure) must be DENYed"
  end
end
