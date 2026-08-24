# Handler interface contract (foundation). The extension surface stops HERE: concrete domain
# handlers (system/tree, system/capability, and every standard extension) are COMMUNITY-installed
# ABOVE this boundary — the core peer ships the contract + the dispatcher, not the handlers
# (PROMPT-CONSTANTS "what you don't do").
#
# A handler is any callable `(ctx::HandlerContext) -> HandlerResult`. `HandlerResult` is the
# triple `(status::Int, result::Entity, included)` — the idiomatic Julia return-tuple, not an
# out-param (profile [error_model]: exceptions for faults, values for outcomes). Registration is
# a plain `Dict{String,Function}` keyed by handler PATTERN, resolved by longest-prefix at §6.5.
#
# §6.11 outbound-dispatch reentry: `ctx.reenter` is the seam a handler calls to ORIGINATE an
# outbound EXECUTE back over the same connection and await its correlated reply. On the single
# Task scheduler this is a plain Channel handoff (no cross-thread demux, no correlation-map tax)
# — the transport binds it per-connection (transport.jl); a handler with no reentry need ignores
# it. This is what makes a core peer able to host an extension that dispatches outbound.
module Handlers

using ..Model: Entity

export HandlerContext, HandlerResult, NO_INCLUDED

const HandlerResult = Tuple{Int,Entity,Vector{Pair{Vector{UInt8},Entity}}}
const NO_INCLUDED = Pair{Vector{UInt8},Entity}[]

struct HandlerContext
    peer::Any                     # ::Peer.Peer (untyped: Handlers is included before Peer)
    conn::Any                     # the connection state
    exec::Entity                  # the EXECUTE root
    env::Any                      # ::Model.Envelope (for by-hash `included` resolution)
    author::Union{Nothing,Entity} # the verified caller's system/peer, or nothing on connect-path
    reenter::Any                  # (uri, operation, params::Entity) -> Model.Envelope | nothing (§6.11)
end

end # module Handlers
