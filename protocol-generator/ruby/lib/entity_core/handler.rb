# frozen_string_literal: true

require_relative "entity"
require_relative "wire"

module EntityCore
  # A handler outcome: a status, a result entity, and any protocol entities to
  # carry in the response envelope's +included+ (§3.1) — caps, peer identities,
  # signatures.
  Outcome = Data.define(:status, :result, :included) do
    def self.ok(result, included = [])
      new(status: 200, result: result, included: included)
    end

    def self.err(status, code, message = nil)
      new(status: status, result: Wire.error_result(code, message), included: [])
    end
  end

  # The §6.6 HandlerContext: everything a handler needs to service one operation
  # — the EXECUTE entity, the per-connection state, the envelope's +included+,
  # the resolved caller capability (nil for the unauthenticated connect path),
  # and the full envelope.
  HandlerContext = Data.define(:exec, :conn, :included, :caller_cap, :env) do
    # The EXECUTE's params entity, or nil.
    def params
      exec.entity_field("params")
    end
  end

  # A core system handler (§6.2). The §6.6 backward tree-walk resolves a request
  # URI to a bootstrapped handler instance; +handle+ then dispatches the
  # operation.
  #
  # == Idiom axis — the duck-typed operation ladder
  #
  # Ruby's dynamic dispatch makes the operation ladder a metaprogramming choice
  # rather than a +switch+ (Java) or a CLOS generic (Common Lisp): a subclass
  # declares its ops as +op :name+ and a method +op_<name>(ctx)+; the base maps
  # the wire operation string to a method via +send+, with the "unknown
  # operation → 501" arm as the +respond_to?+ fallthrough. This is the
  # dynamic-language seam — the router is the object's own method table, reached
  # by reflection, not an explicit dispatch construct.
  class Handler
    def self.ops
      @ops ||= []
    end

    # Declare a supported operation +name+ (string), serviced by +op_<name>+.
    def self.op(name)
      ops << name.to_s
    end

    def handle(operation, ctx)
      meth = "op_#{operation}"
      if self.class.ops.include?(operation) && respond_to?(meth, true)
        send(meth, ctx)
      else
        Outcome.err(501, "unsupported_operation", operation)
      end
    end
  end

  # Per-connection state (§4.2). Holds the §4.1 handshake progress (issued
  # nonce, the initiator's claimed peer_id, established flag) and the §6.13(b)
  # handler-facing outbound seam.
  #
  # The +outbound+ seam (a callable) sends an EXECUTE envelope over THIS
  # connection and awaits its correlated EXECUTE_RESPONSE (§6.11 reentry); the
  # transport sets it. It is nil when the request did not arrive over a
  # reentrant connection.
  class Conn
    attr_accessor :established, :issued_nonce, :hello_peer_id, :outbound

    def initialize
      @established = false
      @issued_nonce = nil
      @hello_peer_id = nil
      @outbound = nil
      @out_counter = 0
      @mutex = Mutex.new
    end

    def next_out_counter
      @mutex.synchronize { @out_counter += 1 }
    end
  end
end
