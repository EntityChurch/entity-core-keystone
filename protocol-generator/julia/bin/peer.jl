#!/usr/bin/env julia
# entity-core-protocol-julia peer executable — the process `validate-peer` drives in S4.
#
# Startup convention (keystone AGENTS.md): `--name NAME` loads the Ed25519 identity from
# ~/.entity/peers/NAME/keypair (entity-core PEM = base64 of a 32-byte seed) → persistent identity
# + peer-manager interop. `--validate` enables the §7a system/validate/* conformance handlers
# (OFF by default — dispatch-outbound is a standing dialer, never live in production).
# `--debug-open-grants` is the deprecated degenerate seed policy (accepted, ignored).
#
# Prints a single `LISTENING 127.0.0.1:PORT` line once the socket is bound (the S4 harness greps
# for it), then serves accepted connections on the single-threaded Task scheduler until killed.
#
# NOTE (S3 boundary): the peer machinery here — handshake, auth-before-resolve dispatch, seed
# grant, single-link root-cap check — is the S3 surface. Full validate-peer conformance (the
# core handlers system/{tree,capability,type,handler}, multi-link chain-walk, §7a validate
# handlers) is the S4 build-out; this entry point is the wiring S4 fills in.
using Sockets
using Base64

const HERE = @__DIR__
include(joinpath(HERE, "..", "src", "EntityCore.jl"))
using .EntityCore
using .EntityCore.Transport: serve_connection

function load_seed(name::AbstractString)::Vector{UInt8}
    home = get(ENV, "HOME", "/root")
    path = joinpath(home, ".entity", "peers", name, "keypair")
    isfile(path) || error("keypair not found: $path (provision it per the --name convention)")
    b64 = ""
    for line in eachline(path)
        startswith(line, "-----") && continue
        isempty(strip(line)) && continue
        b64 = strip(line); break
    end
    seed = base64decode(b64)
    length(seed) == 32 || error("keypair seed must be 32 bytes, got $(length(seed))")
    return seed
end

function main(args)
    port = 7777
    name = "conformance"
    validate = false
    open_grants = false
    i = 1
    while i <= length(args)
        a = args[i]
        if a == "--port"; port = parse(Int, args[i+1]); i += 2
        elseif a == "--name"; name = args[i+1]; i += 2
        elseif a == "--validate"; validate = true; i += 1
        elseif a == "--debug-open-grants"; open_grants = true; i += 1  # degenerate seed policy default→*
        else; i += 1
        end
    end

    peer = create_peer(load_seed(name); validate=validate, open_grants=open_grants)
    server = Sockets.listen(ip"127.0.0.1", port)
    bound = Int(getsockname(server)[2])
    println("LISTENING 127.0.0.1:$bound")
    flush(stdout)
    while true
        sock = try; accept(server); catch; break; end
        @async serve_connection(peer, sock)
    end
end

main(ARGS)
