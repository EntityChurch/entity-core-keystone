# frozen_string_literal: true

require_relative "entity"

module EntityCore
  # Storage (foundation, §1.7): the two layers.
  #
  #   Content Store: hash → entity   (immutable, content-addressed, dedup)
  #   Entity Tree:   path → hash     (mutable location index)
  #
  # In-memory minimal impl. Paths are the canonical absolute form
  # +/{peer_id}/rest+ (§1.4); the peer canonicalizes before calling in. The
  # content store is keyed by the LOWERCASE-HEX content_hash (A-CL-009 trap), so
  # an ASCII-8BIT byte hash works as a String map key.
  #
  # == §4.8 data-race safety (the Ruby concurrency correctness point)
  #
  # The transport dispatches concurrent inbound EXECUTEs on separate threads,
  # each of which may read-then-write the store (§3.9 CAS put, §6.13(a) register
  # multi-bind). Under MRI the GVL serializes Ruby BYTECODE, but it is RELEASED
  # on blocking IO AND does NOT make a compound read-then-write atomic (a Thread
  # can be pre-empted between the two ops). So a single +Mutex+ guards EVERY
  # mutating critical section here — +bind+, +put_entity+, +bind_cas+, +unbind+
  # — making each one indivisible. This is required for correctness, not
  # decoration (profile [async].store_safety = mutex-guarded). Read-only
  # accessors also lock so they observe a consistent snapshot.
  #
  # == Emit pathway (§6.10 / v7.74 §6.13(c)) — the Core Extensibility Boundary
  #
  # Tree/content writes produce events delivered to registered consumers. The
  # hook is LIVE even with ZERO consumers (events are produced and discarded) so
  # a future extension can register a consumer WITHOUT rebuilding the peer — the
  # §6.13(c) MUST. Consumers fire OUTSIDE the lock (after the write commits) so a
  # consumer cannot deadlock on a re-entrant store call.
  class Store
    # A tree-change event (§6.10 Bind step).
    TreeEvent = Data.define(:event_type, :path, :new_hash, :previous_hash)
    # A content-store event (§6.10 Store step).
    ContentEvent = Data.define(:hash, :entity)

    def initialize
      @content = {}                 # hash-hex → Entity
      @tree = {}                    # path → hash-hex
      @content_consumers = []
      @tree_consumers = []
      @mutex = Mutex.new
    end

    # ── emit consumer registration (§6.10 consumer-registration primitive) ─────
    # Reachable any time, including post-bootstrap. Delivery is sync-inline (§9.4).

    def register_content_consumer(&block)
      @mutex.synchronize { @content_consumers << block }
    end

    def register_tree_consumer(&block)
      @mutex.synchronize { @tree_consumers << block }
    end

    # ── content store (§6.10 Store step: event fires only when entity is new) ──

    def put_entity(entity)
      event = nil
      @mutex.synchronize do
        k = hex(entity.content_hash)
        unless @content.key?(k)
          @content[k] = entity
          event = ContentEvent.new(hash: entity.content_hash, entity: entity)
        end
      end
      emit_content(event) if event
      nil
    end

    def get_by_hash(hash)
      @mutex.synchronize { @content[hex(hash)] }
    end

    # ── entity tree (§6.10 Bind step: event fires when the binding changes) ────

    def bind(path, entity)
      content_event, tree_event = @mutex.synchronize { commit_bind(path, entity) }
      emit_content(content_event) if content_event
      emit_tree(tree_event) if tree_event
      nil
    end

    # §3.9 compare-and-swap bind. +expected+ is the 33-byte hash the caller
    # believes is currently bound (a zero/empty hash means "expected absent").
    # The compare AND the swap happen in ONE critical section — the GVL alone
    # does NOT make this atomic (another thread can bind between a separate
    # read and write). Returns true on success, false on a CAS miss.
    def bind_cas(path, entity, expected)
      event = nil
      ok =
        @mutex.synchronize do
          current = @tree[path]
          matches =
            if expected.nil?
              true
            elsif zero_hash?(expected)
              current.nil?
            else
              current == hex(expected)
            end
          if matches
            event = commit_bind(path, entity)
            true
          else
            false
          end
        end
      if event
        content_event, tree_event = event
        emit_content(content_event) if content_event
        emit_tree(tree_event) if tree_event
      end
      ok
    end

    def unbind(path)
      event = nil
      @mutex.synchronize do
        prev = @tree.delete(path)
        event = TreeEvent.new(event_type: "deleted", path: path, new_hash: nil, previous_hash: prev) if prev
      end
      emit_tree(event) if event
      nil
    end

    # The hex content_hash bound at +path+, or nil.
    def hash_at(path)
      @mutex.synchronize { @tree[path] }
    end

    def get_at(path)
      @mutex.synchronize do
        h = @tree[path]
        h && @content[h]
      end
    end

    # One-level listing entry: a segment, its bound hash (or nil), and whether
    # the segment has deeper descendants.
    ListEntry = Data.define(:segment, :hash_hex, :has_children)

    # One-level listing under +prefix+ (a path; a trailing slash is added if
    # absent). Returns entries sorted by segment (§3.9).
    def listing(prefix)
      p = prefix.end_with?("/") ? prefix : "#{prefix}/"
      acc = {}                       # segment → [hash_or_nil, deeper]
      @mutex.synchronize do
        @tree.each do |path, hash|
          next unless path.length > p.length && path.start_with?(p)

          rest = path[p.length..]
          slash = rest.index("/")
          if slash
            seg = rest[0...slash]
            cell = (acc[seg] ||= [nil, false])
            cell[1] = true
          else
            cell = (acc[rest] ||= [nil, false])
            cell[0] = hash
          end
        end
      end
      acc.keys.sort.map { |seg| ListEntry.new(segment: seg, hash_hex: acc[seg][0], has_children: acc[seg][1]) }
    end

    private

    # MUST be called with @mutex held. Inserts the entity into the content store
    # and binds the path. Returns +[content_event_or_nil, tree_event_or_nil]+ for
    # the caller to emit AFTER releasing the lock (so a consumer cannot deadlock
    # on a re-entrant store call).
    def commit_bind(path, entity)
      k = hex(entity.content_hash)
      content_new = !@content.key?(k)
      @content[k] = entity if content_new
      content_event = content_new ? ContentEvent.new(hash: entity.content_hash, entity: entity) : nil
      prev = @tree[path]
      @tree[path] = k
      tree_event =
        if k == prev
          nil
        else
          TreeEvent.new(event_type: derive_event_type(prev, k), path: path, new_hash: k, previous_hash: prev)
        end
      [content_event, tree_event]
    end

    def derive_event_type(prev, nxt)
      return "created" if prev.nil?
      return "deleted" if nxt.nil?

      "modified"
    end

    def emit_content(event)
      @content_consumers.each { |c| c.call(event) }
    end

    def emit_tree(event)
      @tree_consumers.each { |c| c.call(event) }
    end

    def hex(bytes)
      bytes.b.unpack1("H*")
    end

    def zero_hash?(bytes)
      bytes.each_byte.all?(&:zero?)
    end
  end
end
