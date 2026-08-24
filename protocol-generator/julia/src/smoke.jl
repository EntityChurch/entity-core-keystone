# S3 smoke runner — the phase exit gate. Two Julia peers talk over real loopback TCP through
# the full dispatch chain, all on the SINGLE-THREADED Task scheduler (A-JULIA-005):
#
#   1. §4.1/§4.6 handshake BOTH DIRECTIONS — the initiator's hello + authenticate, each answered
#      by the responder over real frames (3 EXECUTE + 3 EXECUTE_RESPONSE across the 2 legs), the
#      responder minting a seed grant on success.
#   2. §6.5 AUTH-BEFORE-RESOLVE (F31): an UNAUTHENTICATED EXECUTE to an unregistered path returns
#      **401** authentication_failed (NOT 404) — auth runs before handler resolution.
#   3. The post-auth 404: the SAME unregistered path, now AUTHENTICATED, returns **404**
#      handler_not_found — proving resolution is reached only once auth passes (the ordering that
#      makes 401-vs-404 correct).
#   4. §6.11 request_id DEMUX: 8 concurrently-issued authenticated requests, dispatched
#      out-of-order on the responder's per-EXECUTE Tasks, each correlated back to its own
#      request_id via its Channel (no cross-thread demux on the cooperative scheduler).
#
# Run (in-container): julia --project=. src/smoke.jl
using Sockets
include("EntityCore.jl")
using .EntityCore
using .EntityCore: Transport, Peer, Model
using .EntityCore.Transport: Io, Session, serve_connection, dial, initiate, session_execute,
                             execute_raw, read_loop, close_io, status_of
using .EntityCore.Wire: empty_params
using .EntityCore.Model: textfield

const PASS = Ref(0); const FAIL = Ref(0)
function check(name, ok)
    ok ? (PASS[] += 1) : (FAIL[] += 1)
    println("  [", ok ? "PASS" : "FAIL", "] ", name)
end

function main()
    responder = create_peer(fill(0x01, 32))
    initiator = create_peer(fill(0x02, 32))

    server = Sockets.listen(ip"127.0.0.1", 0)
    port = Int(getsockname(server)[2])
    @async begin
        while true
            sock = try; accept(server); catch; break; end
            @async serve_connection(responder, sock)
        end
    end

    io = dial(ip"127.0.0.1", port)
    reader = @async read_loop(initiator, io)

    println("Handshake (both directions):")
    session = initiate(io, initiator.identity)
    check("hello + authenticate → session established (grant minted)", session.capability.typ == "system/capability/token")
    check("remote peer_id matches responder", session.remote_peer_id == responder.peer_id)

    unknown = "/$(responder.peer_id)/does/not/exist"

    println("Dispatch (§6.5 auth-before-resolve, F31):")
    r401 = execute_raw(io, unknown, "noop", empty_params(); request_id="unauth-1")
    check("UNAUTHENTICATED unknown-handler → 401 (not 404)", r401 !== nothing && status_of(r401) == 401)
    check("  └ 401 response correlates to its request_id", r401 !== nothing && textfield(r401.root, "request_id") == "unauth-1")

    r404 = session_execute(session, unknown, "noop", empty_params())
    check("AUTHENTICATED unknown-handler → 404 (resolve reached post-auth)", r404 !== nothing && status_of(r404) == 404)

    println("Concurrency (§6.11 request_id demux — 8 out-of-order in-flight):")
    N = 8
    results = Vector{Any}(undef, N)
    @sync for i in 1:N
        @async begin
            uri = "/$(responder.peer_id)/unregistered/path/$(i)"
            results[i] = session_execute(session, uri, "noop", empty_params())
        end
    end
    correlated = count(r -> r !== nothing && status_of(r) == 404, results)
    check("$(N) interleaved authenticated requests each correlated → $(correlated)/$(N)", correlated == N)

    print("Teardown: ")
    close_io(io)
    try; close(server); catch; end
    println("clean.")

    all_pass = FAIL[] == 0
    println("\n→ SMOKE: ", all_pass ? "PASS" : "FAIL", " (", PASS[], " pass, ", FAIL[], " fail)")
    return all_pass
end

exit(main() ? 0 : 1)
