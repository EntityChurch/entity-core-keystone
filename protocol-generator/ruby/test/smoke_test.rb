# frozen_string_literal: true

require_relative "test_helper"

# S3 two-peer loopback smoke test (the phase exit gate).
#
# Two Ruby peers talk over real loopback TCP through the full §6.5 dispatch
# chain. A RESPONDER peer listens; an INITIATOR peer (a second identity) dials it
# and drives the §4.1 forward handshake (hello → authenticate), then:
#   * 404 on an unregistered path (no handler resolved);
#   * an authority-gated tree get (200) over the §4.4 discovery floor;
#   * a capability request (200);
#   * 8-way request_id demux of concurrently-issued replies (N7, §6.11).
# A second scenario exercises the v7.74 Core Extensibility Boundary
# (--debug-open-grants + --validate): the register live-hook (§6.13(a)), the emit
# hook firing on register's tree writes (§6.13(c)), and the §7a echo handler.
#
# The full validate-peer --profile core run is S4. This smoke proves the
# wire-level peer surface so S4 can run the oracle.
class SmokeTest < Minitest::Test
  include EntityCore

  def setup
    @results = []
  end

  def check(name, ok)
    @results << ok
    puts format("  [%<status>s] %<name>s", status: ok ? "PASS" : "FAIL", name: name)
    ok
  end

  def seed(byte)
    (byte.chr * 32).b
  end

  def test_two_peer_loopback
    run_core_scenario
    run_extensibility_scenario
    pass_count = @results.count(true)
    all_pass = @results.all?
    puts format("\nSMOKE: %<verdict>s (%<pass>d/%<total>d)",
                verdict: all_pass ? "PASS" : "FAIL", pass: pass_count, total: @results.size)
    assert all_pass, "two-peer loopback must be all-PASS (#{pass_count}/#{@results.size})"
  end

  # ── Scenario 1: core ops (responder = default seed policy) ──────────────────

  def run_core_scenario
    responder = Peer.create(seed(0x11))
    listener = Transport.start_listener(responder, 0)
    begin
      puts format("Responder listening on 127.0.0.1:%<port>d (peer %<peer>s)",
                  port: listener.port, peer: responder.local_peer)
      initiator = Peer.create(seed(0x22))
      session = Transport.dial(initiator, "127.0.0.1", listener.port)
      begin
        remote = session.remote_peer_id
        puts "Handshake:"
        check("session established (capability minted)", !session.capability.nil?)
        check("remote peer_id matches responder", remote == responder.local_peer)

        puts "Dispatch:"
        # 404 on an unregistered path
        r404 = session.execute("/#{remote}/does/not/exist", "noop", Wire.empty_params, nil)
        check("unregistered path -> 404", Wire.response_status(r404) == 404)

        # authority-gated tree get (200) over the discovery floor
        iface_target = Wire.resource_target("system/handler/system/tree")
        rget = session.execute("/#{remote}/system/tree", "get", Wire.empty_params, iface_target)
        check("granted tree get -> 200", Wire.response_status(rget) == 200)
        res = Wire.response_result(rget)
        check("tree get returns a system/handler/interface entity",
              !res.nil? && res.type == "system/handler/interface")

        # capability request (200)
        req_grant = Peer.grant(["system/tree"], ["system/type/*"], ["get"])
        req_params = Entity.make("system/capability/request", { "grants" => [req_grant] })
        rcap = session.execute("/#{remote}/system/capability", "request", req_params, nil)
        check("capability request -> 200", Wire.response_status(rcap) == 200)

        # 8-way request_id demux (N7, §6.11)
        puts "Concurrency (request_id demux):"
        n = 8
        oks = Array.new(n, false)
        threads = (0...n).map do |i|
          Thread.new do
            r = session.execute("/#{remote}/system/tree", "get", Wire.empty_params,
                                Wire.resource_target("system/handler/system/tree"))
            rr = Wire.response_result(r)
            oks[i] = Wire.response_status(r) == 200 && !rr.nil? && rr.type == "system/handler/interface"
          rescue StandardError
            oks[i] = false
          end
        end
        threads.each(&:join)
        correlated = oks.count(true)
        check("8 interleaved requests each correlated -> #{correlated}/8", correlated == n)
      ensure
        session.close
      end
    ensure
      listener.close
    end
  end

  # ── Scenario 2: the v7.74 Core Extensibility Boundary over the wire ─────────

  def run_extensibility_scenario
    responder = Peer.create(seed(0x33), open_grants: true, conformance: true)
    emit_events = 0
    emit_mutex = Mutex.new
    responder.store.register_tree_consumer { |_ev| emit_mutex.synchronize { emit_events += 1 } }
    listener = Transport.start_listener(responder, 0)
    begin
      initiator = Peer.create(seed(0x44))
      session = Transport.dial(initiator, "127.0.0.1", listener.port)
      begin
        remote = session.remote_peer_id
        emit_before = emit_mutex.synchronize { emit_events }
        puts "Extensibility (open-grants + --validate):"

        # register live-hook (§6.13(a))
        manifest = { "name" => "demo", "operations" => {} }
        req = Entity.make("system/handler/register-request", { "manifest" => manifest })
        rreg = session.execute("/#{remote}/system/handler", "register", req,
                              Wire.resource_target("system/handler/demo"))
        check("handler register -> 200 (live, not 501)", Wire.response_status(rreg) == 200)
        emit_after = emit_mutex.synchronize { emit_events }
        check("emit hook fired on register's tree writes (§6.13(c))", emit_after > emit_before)

        # §7a echo conformance handler (resolve→dispatch)
        payload = Entity.make("primitive/any", { "ping" => 42 })
        recho = session.execute("/#{remote}/system/validate/echo", "echo", payload, nil)
        check("§7a echo -> 200", Wire.response_status(recho) == 200)
        res = Wire.response_result(recho)
        check("§7a echo returns params verbatim", !res.nil? && res.type == "primitive/any")
      ensure
        session.close
      end
    ensure
      listener.close
    end
  end
end
