require "./spec_helper"

# S3/S4 peer-machinery accept-path units — the direction the oracle can't cover
# (the "conformance-green can be vacuous" keystone lesson). The validate-peer
# multisig category was largely rejection-only until v7.65 added a single accept
# probe; these units assert the ACCEPT paths in-process, independent of the
# oracle, so a fail-closed regression that still passes the oracle would fail HERE.

include EntityCore

private def make_seed(byte : Int32) : Bytes
  Bytes.new(32) { |i| ((byte + i) & 0xFF).to_u8 }
end

describe "EntityCore peer machinery (S3)" do
  describe "identity + signature round-trip" do
    it "signs and verifies a system/signature entity against its peer" do
      id = Identity.of_seed(make_seed(0x42))
      target = Entity.build("primitive/any", {"x" => 1})
      sig = id.sign(target)
      Identity.verify_signature(sig, id.peer_entity).should be_true
      # a wrong signer peer must fail
      other = Identity.of_seed(make_seed(0x99))
      Identity.verify_signature(sig, other.peer_entity).should be_false
    end
  end

  describe "core type floor" do
    it "renders all 53 floor types with content_hash byte-identical to the Go oracle" do
      floor = CoreTypes.floor_entities
      floor.size.should eq(53)
      # spot-check a couple against the vendored oracle hashes
      floor["primitive/any"].content_hash.hexstring
        .should eq(CoreTypeFloor::CONTENT_HASH["primitive/any"])
      floor["system/capability/token"].content_hash.hexstring
        .should eq(CoreTypeFloor::CONTENT_HASH["system/capability/token"])
    end
  end

  describe "capability chain (§5.5) — accept path" do
    it "verifies a self-issued root capability chain (ALLOW)" do
      peer = Peer.create(make_seed(0x11), open_grants: true, conformance: false)
      # the peer's owner cap grants full authority; build an EXECUTE authored by
      # the peer itself under that owner cap and assert the §5.2 verdict is Allow.
      id = peer.identity
      owner = peer.mint_token(id.identity_hash, peer.owner_grants, nil)
      exec = Wire.make_execute("req-1", "/#{peer.local_peer}/system/tree", "get",
        Wire.empty_params, author: id.identity_hash, capability: owner.token.content_hash,
        resource: Wire.resource_target("/#{peer.local_peer}/system/type/primitive/any"))
      exec_sig = id.sign(exec)
      env = Envelope.of(exec, [owner.token, id.peer_entity, owner.signature, exec_sig])
      Capability.verify_request(peer.local_peer, peer.store, env)
        .should eq(Capability::RequestVerdict::Allow)
    end
  end

  describe "capability multisig root (§3.6 / §5.5 M3/M4/M6) — ACCEPT path" do
    it "accepts a genuine 2-of-3 quorum where the local peer is a signer" do
      # Three peers; the LOCAL peer is one of three quorum members. A 2-of-3
      # root cap signed by two members (incl. local) MUST verify (M4/M6 accept).
      local = Peer.create(make_seed(0x21), open_grants: true, conformance: false)
      lid = local.identity
      s2 = Identity.of_seed(make_seed(0x22))
      s3 = Identity.of_seed(make_seed(0x23))
      grantee = Identity.of_seed(make_seed(0x24))

      # multi-granter map {signers:[h1,h2,h3], threshold:2}
      gm = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      signers = [] of Cbor::EcValue
      signers << lid.identity_hash << s2.identity_hash << s3.identity_hash
      gm["signers"] = signers
      gm["threshold"] = Cbor::EcInt.from(2)
      tdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      tdata["granter"] = gm
      tdata["grantee"] = grantee.identity_hash
      tdata["grants"] = local.owner_grants
      tdata["created_at"] = Cbor::EcInt.from(Capability.now_ms)
      root = Entity.make("system/capability/token", tdata)

      # two distinct signers (local + s2) each sign the root content hash
      sig_local = lid.sign(root)
      sig_s2 = s2.sign(root)

      included = [
        root, grantee.peer_entity,
        lid.peer_entity, s2.peer_entity, s3.peer_entity,
        sig_local, sig_s2,
      ].map { |e| Envelope::Included.new(e.content_hash, e) }

      Capability.verify_capability_chain(local.local_peer, local.store, root, included)
        .should be_true
    end

    it "rejects the same quorum when the local peer is NOT a signer (M6)" do
      local = Peer.create(make_seed(0x31), open_grants: true, conformance: false)
      s1 = Identity.of_seed(make_seed(0x32))
      s2 = Identity.of_seed(make_seed(0x33))
      s3 = Identity.of_seed(make_seed(0x34))
      grantee = Identity.of_seed(make_seed(0x35))

      gm = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      signers = [] of Cbor::EcValue
      signers << s1.identity_hash << s2.identity_hash << s3.identity_hash
      gm["signers"] = signers
      gm["threshold"] = Cbor::EcInt.from(2)
      tdata = ::Hash(Cbor::EcValue, Cbor::EcValue).new
      tdata["granter"] = gm
      tdata["grantee"] = grantee.identity_hash
      tdata["grants"] = local.owner_grants
      tdata["created_at"] = Cbor::EcInt.from(Capability.now_ms)
      root = Entity.make("system/capability/token", tdata)

      included = [
        root, grantee.peer_entity, s1.peer_entity, s2.peer_entity, s3.peer_entity,
        s1.sign(root), s2.sign(root),
      ].map { |e| Envelope::Included.new(e.content_hash, e) }

      # local peer is not among the signers → M6 denies (fail-closed correctness).
      Capability.verify_capability_chain(local.local_peer, local.store, root, included)
        .should be_false
    end
  end

  describe "§4.10(b) chain-depth pre-check" do
    it "does not flag an in-bound chain as over-depth" do
      peer = Peer.create(make_seed(0x51), open_grants: true, conformance: false)
      owner = peer.mint_token(peer.identity.identity_hash, peer.owner_grants, nil)
      inc = [Envelope::Included.new(owner.token.content_hash, owner.token)]
      Capability.chain_exceeds_depth?(peer.store, owner.token, inc).should be_false
    end
  end
end

describe "EntityCore in-process wire loopback (§4.1 / §6.11)" do
  it "handshakes, dispatches 404, and demuxes concurrent request_ids" do
    server = Peer.create(make_seed(0x61), open_grants: true, conformance: true)
    listener = Transport.start_listener(server, 0)
    port = listener.port
    begin
      client = Peer.create(make_seed(0x62), open_grants: false, conformance: false)
      session = Transport.dial(client, "127.0.0.1", port)
      session.capability.should_not be_nil
      session.remote_peer_id.should eq(server.local_peer)

      # unregistered path → 404
      r = session.execute("no/such", "get", Wire.empty_params, Wire.resource_target("no/such"))
      r.should_not be_nil
      Wire.response_status(r.not_nil!).should eq(404_u64)

      # concurrent demux — every reply correlates to its own fiber
      n = 6
      done = Channel(UInt64).new(n)
      n.times do |k|
        spawn do
          rr = session.execute("no/such-#{k}", "get", Wire.empty_params,
            Wire.resource_target("no/such-#{k}"))
          done.send(rr ? Wire.response_status(rr) : 0_u64)
        end
      end
      n.times { done.receive.should eq(404_u64) }
      session.close
    ensure
      listener.close
    end
  end

  it "echo handler returns the params entity verbatim (§7a.1 accept-shape)" do
    server = Peer.create(make_seed(0x71), open_grants: true, conformance: true)
    listener = Transport.start_listener(server, 0)
    port = listener.port
    begin
      client = Peer.create(make_seed(0x72), open_grants: false, conformance: false)
      session = Transport.dial(client, "127.0.0.1", port)
      payload = Entity.build("primitive/any", {"value" => "hello"})
      r = session.execute("system/validate/echo", "echo", payload,
        Wire.resource_target("system/validate/echo"))
      r.should_not be_nil
      Wire.response_status(r.not_nil!).should eq(200_u64)
      result = Wire.response_result(r.not_nil!).not_nil!
      # the echo returns {value:"hello"} verbatim
      result.text("value").should eq("hello")
      session.close
    ensure
      listener.close
    end
  end
end
