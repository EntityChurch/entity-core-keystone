# Ed25519 signing over canonical-ECF bytes (§1.5 key_type 0x01), via SYSTEM libsodium `ccall`
# (profile [codec].ed25519_library; A-JULIA-003 — the native-audited-lib crypto tier, Elixir
# :crypto / Haskell crypton class, NOT the keystone C-ABI FFI-hybrid). RFC 8032 Ed25519 is
# deterministic: a fixed 32-byte seed + fixed message yields a fixed 64-byte signature, so the
# corpus vectors reproduce byte-exactly with no RNG. libsodium is image-provided; binding it by
# `ccall` keeps the floor peer self-contained + Pkg-fetch-free (container builds --network=none).
#
# Ed448 is NOT in libsodium (Ed25519 only) → the agility family is an opt-in hybrid-FFI
# sub-package over the C-ABI (A-JULIA-004), deferred; the Ed25519 floor is complete here.
module Sign

export ed25519_sign, ed25519_pubkey, ed25519_verify

const LIBSODIUM = "libsodium"

const _initialized = Ref(false)
function _ensure_init()
    if !_initialized[]
        rc = ccall((:sodium_init, LIBSODIUM), Cint, ())
        rc < 0 && error("sodium_init failed (rc=$rc)")   # 0 = ok, 1 = already inited
        _initialized[] = true
    end
    return nothing
end

"""(pk::32, sk::64) for a 32-byte Ed25519 seed."""
function _seed_keypair(seed::AbstractVector{UInt8})
    length(seed) == 32 || error("seed must be 32 bytes, got $(length(seed))")
    _ensure_init()
    pk = Vector{UInt8}(undef, 32)
    sk = Vector{UInt8}(undef, 64)
    rc = ccall((:crypto_sign_seed_keypair, LIBSODIUM), Cint,
               (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}), pk, sk, Vector{UInt8}(seed))
    rc == 0 || error("crypto_sign_seed_keypair failed (rc=$rc)")
    return pk, sk
end

"""Deterministic Ed25519 signature (64 bytes) over `msg` for a 32-byte `seed`."""
function ed25519_sign(seed::AbstractVector{UInt8}, msg::AbstractVector{UInt8})::Vector{UInt8}
    _, sk = _seed_keypair(seed)
    sig = Vector{UInt8}(undef, 64)
    siglen = Ref{UInt64}(0)
    m = Vector{UInt8}(msg)
    rc = ccall((:crypto_sign_detached, LIBSODIUM), Cint,
               (Ptr{UInt8}, Ptr{UInt64}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
               sig, siglen, m, length(m), sk)
    rc == 0 || error("crypto_sign_detached failed (rc=$rc)")
    return sig
end

"""The Ed25519 public key (32 bytes) for a 32-byte seed."""
function ed25519_pubkey(seed::AbstractVector{UInt8})::Vector{UInt8}
    pk, _ = _seed_keypair(seed)
    return pk
end

"""Verify a 64-byte signature against `msg` under a 32-byte public key."""
function ed25519_verify(pk::AbstractVector{UInt8}, sig::AbstractVector{UInt8}, msg::AbstractVector{UInt8})::Bool
    _ensure_init()
    (length(pk) == 32 && length(sig) == 64) || return false
    m = Vector{UInt8}(msg)
    rc = ccall((:crypto_sign_verify_detached, LIBSODIUM), Cint,
               (Ptr{UInt8}, Ptr{UInt8}, Culonglong, Ptr{UInt8}),
               Vector{UInt8}(sig), m, length(m), Vector{UInt8}(pk))
    return rc == 0
end

end # module Sign
