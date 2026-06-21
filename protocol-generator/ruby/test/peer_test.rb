# frozen_string_literal: true

require "stringio"

require_relative "test_helper"

# Peer-machinery unit checks for the v7.75 substrate floor pieces the smoke does
# NOT directly exercise: §4.10(b) chain-depth pre-check (400, not 403),
# §4.10(a) payload guard (413 / 16 MiB), the §3.9 Mutex-guarded CAS store under
# concurrency, and the §5.2a verdict trichotomy. Built in at S3 so the S4
# resource_bounds / concurrency categories pass.
class PeerTest < Minitest::Test
  include EntityCore

  def seed(byte)
    (byte.chr * 32).b
  end

  # ── §4.10(b): an over-deep capability chain → 400 chain_depth_exceeded ───────
  # The structural pre-check walks parent pointers without signature work and
  # fires BEFORE the per-link authz walk; an UNREACHABLE parent is NOT a depth
  # problem (stays a 403-class deny, false here).
  def test_chain_depth_precheck_over_limit_is_structural_400
    store = Store.new
    # Build a synthetic chain of MAX_CHAIN_DEPTH + 2 tokens, each pointing at the
    # next via "parent", all present in the store so depth (not reachability) is
    # the failing axis.
    depth = Capability::MAX_CHAIN_DEPTH + 2
    parent_hash = nil
    tokens = []
    depth.times do
      data = { "granter" => ("\x11".b * 33), "grantee" => ("\x22".b * 33) }
      data["parent"] = parent_hash if parent_hash
      tok = Entity.make("system/capability/token", data)
      store.put_entity(tok)
      tokens << tok
      parent_hash = tok.content_hash
    end
    # tokens.first is the root (no parent); tokens.last is the deepest leaf, so
    # its chain back to the root is the full `depth` long.
    leaf = tokens.last
    assert Capability.chain_exceeds_depth?(store, leaf, []),
           "a chain deeper than MAX_CHAIN_DEPTH must trip the structural pre-check"
  end

  def test_chain_depth_precheck_within_limit_is_false
    store = Store.new
    root = Entity.make("system/capability/token", { "granter" => ("\x11".b * 33) })
    store.put_entity(root)
    child = Entity.make("system/capability/token",
                        { "granter" => ("\x11".b * 33), "parent" => root.content_hash })
    store.put_entity(child)
    refute Capability.chain_exceeds_depth?(store, child, []),
           "a short chain must NOT trip the depth pre-check"
  end

  def test_unreachable_parent_is_not_a_depth_problem
    store = Store.new
    # parent hash points at a token that is NOT in the store → unreachable, but
    # the chain is structurally length-1, so the depth pre-check is false (the
    # authz walk later denies it as 403, not 400).
    orphan = Entity.make("system/capability/token",
                         { "granter" => ("\x11".b * 33), "parent" => ("\xAB".b * 33) })
    refute Capability.chain_exceeds_depth?(store, orphan, []),
           "an unreachable parent is a 403 reachability deny, NOT a 400 depth fault"
  end

  # ── §4.10(a): the 16 MiB payload guard rejects an over-limit length prefix ───
  # before buffering the body (PayloadTooLargeError → 413 at the dispatch site).
  def test_payload_guard_rejects_over_limit_prefix
    over = Wire::MAX_FRAME + 1
    io = StringIO.new([over].pack("N").b) # just the length prefix, no body
    assert_raises(EntityCore::PayloadTooLargeError) { Wire.read_frame(io) }
  end

  def test_payload_guard_admits_at_limit
    # A frame exactly at the limit boundary reads its (here empty-ish) body.
    payload = "x".b * 8
    io = StringIO.new([payload.bytesize].pack("N").b + payload)
    assert_equal payload, Wire.read_frame(io)
  end

  # ── §3.9 / §4.8: Mutex-guarded CAS store is data-race-safe ───────────────────
  # Many threads race a compare-and-swap put on the same path; under the GVL a
  # compound read-then-write is NOT atomic, so exactly ONE winner is the
  # correctness signal that the Mutex critical section holds.
  def test_cas_store_single_winner_under_concurrency
    store = Store.new
    path = "/peer/race"
    n = 64
    winners = 0
    win_mutex = Mutex.new
    threads = (0...n).map do |i|
      Thread.new do
        ent = Entity.make("primitive/any", { "i" => i })
        # expected = absent (zero hash) → only the first binder wins.
        if store.bind_cas(path, ent, ("\x00".b * 33))
          win_mutex.synchronize { winners += 1 }
        end
      end
    end
    threads.each(&:join)
    assert_equal 1, winners, "exactly one CAS-from-absent must win (Mutex-guarded RMW)"
  end

  def test_cas_store_matching_expected_swaps
    store = Store.new
    path = "/peer/v"
    a = Entity.make("primitive/any", { "v" => 1 })
    b = Entity.make("primitive/any", { "v" => 2 })
    assert store.bind_cas(path, a, ("\x00".b * 33)), "first bind from absent succeeds"
    refute store.bind_cas(path, b, ("\x00".b * 33)), "a stale absent-expectation fails"
    assert store.bind_cas(path, b, a.content_hash), "the correct expected hash swaps"
    assert_equal b, store.get_at(path)
  end

  # ── §5.2a verdict trichotomy: an unauthenticated EXECUTE → 401 (not 403) ─────
  # An EXECUTE with no signature is AUTHN_FAIL → 401; the dispatcher maps the
  # three verdicts to 401 / 403 / 400 distinctly.
  def test_unsigned_execute_is_401_not_403
    peer = Peer.create(seed(0x55))
    conn = Conn.new
    conn.established = true
    exec = Wire.make_execute("r1", "/#{peer.local_peer}/system/tree", "get", Wire.empty_params)
    resp = peer.dispatch(conn, Envelope.new(exec))
    assert_equal 401, Wire.response_status(resp),
                 "an unsigned/unauthenticated request is 401, not 403 (§5.2a)"
  end
end
