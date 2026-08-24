require "./entity"
require "./envelope"
require "./wire"

module EntityCore
  # A handler outcome: a status, a result entity, and any protocol entities to
  # carry in the response envelope's `included` (§3.1) — caps, peer identities,
  # signatures.
  struct Outcome
    getter status : Int32
    getter result : Entity
    getter included : Array(Entity)

    def initialize(@status : Int32, @result : Entity, @included : Array(Entity) = [] of Entity)
    end

    def self.ok(result : Entity, included : Array(Entity) = [] of Entity) : Outcome
      new(200, result, included)
    end

    def self.err(status : Int32, code : String, message : String? = nil) : Outcome
      new(status, Wire.error_result(code, message), [] of Entity)
    end
  end

  # Per-connection state (§4.2). Holds the §4.1 handshake progress (issued nonce,
  # the initiator's claimed peer_id, established flag) and the §6.13(b)
  # handler-facing outbound seam.
  #
  # The `outbound` seam sends an EXECUTE envelope over THIS connection and awaits
  # its correlated EXECUTE_RESPONSE (§6.11 reentry); the transport sets it. It is
  # nil when the request did not arrive over a reentrant connection.
  class Conn
    property established : Bool = false
    property issued_nonce : Bytes? = nil
    property hello_peer_id : String? = nil
    # The §6.13(b) outbound primitive: send a request envelope, await the
    # correlated EXECUTE_RESPONSE (nil if the connection closes first).
    property outbound : (Envelope -> Envelope?)? = nil

    @out_counter : UInt64 = 0_u64

    # Monotonic per-connection outbound request counter. Fiber-safe on the single
    # thread (no suspension point between read and increment).
    def next_out_counter : UInt64
      @out_counter += 1
      @out_counter
    end
  end

  # The §6.6 HandlerContext: everything a handler needs to service one operation —
  # the EXECUTE entity, the per-connection state, the envelope's `included`, the
  # resolved caller capability (nil for the unauthenticated connect path), and the
  # full envelope.
  struct HandlerContext
    getter exec : Entity
    getter conn : Conn
    getter included : Array(Envelope::Included)
    getter caller_cap : Entity?
    getter env : Envelope

    def initialize(@exec, @conn, @included, @caller_cap, @env)
    end

    # The EXECUTE's params entity, or nil.
    def params : Entity?
      exec.entity_field("params")
    end
  end

  # A core system handler (§6.2). The §6.6 backward tree-walk resolves a request
  # URI to a bootstrapped handler instance; `handle` then dispatches the
  # operation.
  #
  # == Idiom axis — the static operation ladder
  #
  # Where the dynamic Ruby peer reaches its ops by reflection (`send("op_#{name}")`
  # over a metaprogrammed table), the COMPILED Crystal peer uses an explicit,
  # exhaustively-typed `case operation` in each subclass's `#handle` — the
  # unknown-operation → 501 arm is the `else`. Static dispatch: the router is a
  # compiler-checked switch, not a runtime method-table lookup. This is the
  # extension seam — a community handler subclasses `Handler` and overrides
  # `#handle`.
  abstract class Handler
    # Dispatch `operation` on `ctx`. The default rejects everything with 501; a
    # concrete handler overrides with its `case operation` ladder.
    abstract def handle(operation : String, ctx : HandlerContext) : Outcome
  end
end
