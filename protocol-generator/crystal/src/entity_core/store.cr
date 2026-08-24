require "./entity"

module EntityCore
  # Storage (foundation, §1.7): the two layers.
  #
  #   Content Store: hash → entity   (immutable, content-addressed, dedup)
  #   Entity Tree:   path → hash     (mutable location index)
  #
  # In-memory minimal impl. Paths are the canonical absolute form
  # `/{peer_id}/rest` (§1.4); the peer canonicalizes before calling in. Both maps
  # are keyed by the LOWERCASE-HEX content_hash / the path string, so a byte hash
  # works as a stable String key.
  #
  # == §4.8 data-race safety (the Crystal concurrency correctness point)
  #
  # The transport dispatches each inbound EXECUTE on its OWN fiber (§4.8), and a
  # handler may compound-read-then-write the store (§3.9 CAS put, §6.13(a)
  # register multi-bind). Under Crystal's DEFAULT single-OS-thread scheduler,
  # fibers are cooperatively scheduled and only yield at explicit suspension
  # points (blocking IO, `Channel`, `sleep`, `Fiber.yield`) — NEVER pre-empted
  # mid-computation. Every mutating method here is pure in-memory CPU with NO
  # suspension point, so a compound read-then-write executes atomically w.r.t.
  # other fibers by construction — no `Mutex` needed (profile [async].store_safety
  # = single-thread-default). This structural guarantee is documented, not
  # bolted-on; under `-Dpreview_mt` (not used at core) each mutating section would
  # need an explicit `Mutex` (the raw-thread posture, A-CRY-005).
  #
  # == Emit pathway (§6.10 / §6.13(c)) — the Core Extensibility Boundary
  #
  # Tree/content writes produce events delivered to registered consumers. The hook
  # is LIVE even with ZERO consumers (events are produced and discarded) so a
  # future extension can register a consumer WITHOUT rebuilding the peer (the
  # §6.13(c) MUST). Consumers fire AFTER the write commits so a consumer cannot
  # observe a torn state.
  class Store
    # A tree-change event (§6.10 Bind step).
    struct TreeEvent
      getter event_type : String
      getter path : String
      getter new_hash : String?
      getter previous_hash : String?

      def initialize(@event_type, @path, @new_hash, @previous_hash)
      end
    end

    # A content-store event (§6.10 Store step).
    struct ContentEvent
      getter hash : Bytes
      getter entity : Entity

      def initialize(@hash, @entity)
      end
    end

    # One-level listing entry: a segment, its bound hash-hex (or nil), and whether
    # the segment has deeper descendants.
    struct ListEntry
      getter segment : String
      getter hash_hex : String?
      getter has_children : Bool

      def initialize(@segment, @hash_hex, @has_children)
      end
    end

    def initialize
      @content = {} of String => Entity       # hash-hex → Entity
      @tree = {} of String => String          # path → hash-hex
      @content_consumers = [] of ContentEvent -> Nil
      @tree_consumers = [] of TreeEvent -> Nil
    end

    # ── emit consumer registration (§6.10 consumer-registration primitive) ──────

    def register_content_consumer(&block : ContentEvent -> Nil)
      @content_consumers << block
    end

    def register_tree_consumer(&block : TreeEvent -> Nil)
      @tree_consumers << block
    end

    # ── content store ───────────────────────────────────────────────────────────

    def put_entity(entity : Entity) : Nil
      k = entity.content_hash.hexstring
      unless @content.has_key?(k)
        @content[k] = entity
        emit_content(ContentEvent.new(entity.content_hash, entity))
      end
      nil
    end

    def get_by_hash(hash : Bytes) : Entity?
      @content[hash.hexstring]?
    end

    # ── entity tree ──────────────────────────────────────────────────────────────

    def bind(path : String, entity : Entity) : Nil
      commit_bind(path, entity)
      nil
    end

    # §3.9 compare-and-swap bind. `expected` is the 33-byte hash the caller
    # believes is currently bound (a zero/empty hash means "expected absent"). The
    # compare AND the swap happen with no intervening suspension point, so it is
    # atomic w.r.t. other fibers. Returns true on success, false on a CAS miss.
    def bind_cas(path : String, entity : Entity, expected : Bytes?) : Bool
      current = @tree[path]?
      matches =
        if expected.nil?
          true
        elsif zero_hash?(expected)
          current.nil?
        else
          current == expected.hexstring
        end
      return false unless matches
      commit_bind(path, entity)
      true
    end

    def unbind(path : String) : Nil
      prev = @tree.delete(path)
      if prev
        emit_tree(TreeEvent.new("deleted", path, nil, prev))
      end
      nil
    end

    # The hex content_hash bound at `path`, or nil.
    def hash_at(path : String) : String?
      @tree[path]?
    end

    def get_at(path : String) : Entity?
      h = @tree[path]?
      h ? @content[h]? : nil
    end

    # One-level listing under `prefix` (a path; a trailing slash is added if
    # absent). Returns entries sorted by segment (§3.9).
    def listing(prefix : String) : Array(ListEntry)
      p = prefix.ends_with?("/") ? prefix : "#{prefix}/"
      # segment → {hash_hex_or_nil, has_deeper}
      acc = {} of String => {String?, Bool}
      @tree.each do |path, hash|
        next unless path.size > p.size && path.starts_with?(p)
        rest = path[p.size..]
        slash = rest.index('/')
        if slash
          seg = rest[0...slash]
          cur = acc[seg]?
          acc[seg] = {cur ? cur[0] : nil, true}
        else
          cur = acc[rest]?
          acc[rest] = {hash, cur ? cur[1] : false}
        end
      end
      acc.keys.sort.map do |seg|
        cell = acc[seg]
        ListEntry.new(seg, cell[0], cell[1])
      end
    end

    # ── private ──────────────────────────────────────────────────────────────────

    private def commit_bind(path : String, entity : Entity) : Nil
      k = entity.content_hash.hexstring
      content_new = !@content.has_key?(k)
      @content[k] = entity if content_new
      prev = @tree[path]?
      @tree[path] = k
      emit_content(ContentEvent.new(entity.content_hash, entity)) if content_new
      if k != prev
        emit_tree(TreeEvent.new(derive_event_type(prev, k), path, k, prev))
      end
      nil
    end

    private def derive_event_type(prev : String?, nxt : String?) : String
      return "created" if prev.nil?
      return "deleted" if nxt.nil?
      "modified"
    end

    private def emit_content(event : ContentEvent) : Nil
      @content_consumers.each &.call(event)
    end

    private def emit_tree(event : TreeEvent) : Nil
      @tree_consumers.each &.call(event)
    end

    private def zero_hash?(bytes : Bytes) : Bool
      bytes.all? &.zero?
    end
  end
end
