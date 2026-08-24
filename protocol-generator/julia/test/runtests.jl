#!/usr/bin/env julia
# entity-core-protocol-julia — S2 codec test suite (profile [testing], Test stdlib).
# Self-tests for the ranges/paths the corpus can't cover, the N1–N3 invariants, the
# A-JULIA-006/007/008 idiom traps, then the full 71-vector wire-conformance corpus.

using Test
using EntityCore

hx(v) = bytes2hex(encode(v))

@testset "entity-core-protocol-julia S2 codec" begin

    @testset "A-JULIA-008 fixed-width UInt64 head-form self-test [2^63, 2^64-1]" begin
        # The corpus int set tops out at 2^63-1 (i64::MAX). Pin the full u64 range — the exact
        # spot a signed-int decode would silently overflow (the classic fixed-width trap).
        @test hx(UInt64(0))                == "00"
        @test hx(9223372036854775807)      == "1b7fffffffffffffff"   # 2^63-1  (Int64 max)
        @test hx(UInt64(2)^63)             == "1b8000000000000000"   # 2^63
        @test hx(UInt64(2)^64 - 2)         == "1bfffffffffffffffe"   # 2^64-2
        @test hx(typemax(UInt64))          == "1bffffffffffffffff"   # 2^64-1
        # nint minimum: -2^64 == nint(2^64-1)
        @test hx(-(BigInt(2)^64))          == "3bffffffffffffffff"
        # round-trip via decode: the above must reconstruct to the same wire bytes
        for v in (UInt64(2)^63, UInt64(2)^64 - 2, typemax(UInt64))
            @test encode(decode(encode(v))) == encode(v)
        end
    end

    @testset "int minimal-encoding boundaries" begin
        @test hx(0) == "00"; @test hx(23) == "17"; @test hx(24) == "1818"
        @test hx(255) == "18ff"; @test hx(256) == "190100"; @test hx(65535) == "19ffff"
        @test hx(65536) == "1a00010000"; @test hx(4294967295) == "1affffffff"
        @test hx(4294967296) == "1b0000000100000000"
        @test hx(-1) == "20"; @test hx(-24) == "37"; @test hx(-25) == "3818"; @test hx(-256) == "38ff"
    end

    @testset "float ladder f16/f32/f64 (Rule 4/4a)" begin
        @test hx(0.0) == "f90000"; @test hx(-0.0) == "f98000"; @test hx(1.0) == "f93c00"
        @test hx(Inf) == "f97c00"; @test hx(-Inf) == "f9fc00"; @test hx(NaN) == "f97e00"
        @test hx(65504.0) == "f97bff"          # max normal f16
        @test hx(65503.0) == "fa477fdf00"      # must fall to f32
        @test hx(100000.0) == "fa47c35000"
        @test hx(1.1) == "fb3ff199999999999a"  # must fall to f64
    end

    @testset "N2 recursive major-type-6 tag rejection" begin
        @test_throws Exception decode(UInt8[0xc0, 0x00])                     # bare tag 0
        # tag nested inside a map value: {"data": tag0("x")} — must reject at depth
        @test_throws Exception decode(UInt8[0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0xc0, 0x61, 0x78])
        @test_throws Exception decode(UInt8[0xd9, 0xd9, 0xf7, 0xa0])         # tag 55799
    end

    @testset "N3 empty-map = 0xA0, empty-array = 0x80" begin
        @test encode(CborMap()) == UInt8[0xa0]
        @test encode(Any[]) == UInt8[0x80]
        @test encode("") == UInt8[0x60]
        @test encode(UInt8[]) == UInt8[0x40]
    end

    @testset "A-JULIA-006 multiple-dispatch major-type exclusivity" begin
        # A Vector{UInt8} is mt2; a String is mt3 — no value shimmers across the two branches.
        @test hx(UInt8[0x6b, 0x65, 0x79]) == "436b6579"     # bytes h'6b6579'  → mt2
        @test hx("key")                   == "636b6579"     # text  "key"      → mt3
        @test hx(true) == "f5"; @test hx(false) == "f4"; @test hx(nothing) == "f6"  # Bool≺Integer
    end

    @testset "A-JULIA-007 text length is BYTE length, not code-point count" begin
        s = "é"                                    # 1 code point, 2 UTF-8 bytes
        @test length(s) == 1 && ncodeunits(s) == 2
        @test hx(s) == "62c3a9"                    # mt3 len=2, not len=1
    end

    @testset "map-key canonical order (length-then-lex) + duplicate reject" begin
        @test hx(CborMap([("aa" => 2), ("z" => 1)])) == "a2617a0162616102"      # 'z' before 'aa'
        @test hx(CborMap([("b" => 2), ("a" => 1)]))   == "a2616101616202"        # 'a' before 'b'
        @test_throws Exception encode(CborMap([("a" => 1), ("a" => 2)]))         # Rule 5
    end

    @testset "N1 LEB128 varint single + multi byte" begin
        b = UInt8[]; encode_varint!(b, 128); @test b == UInt8[0x80, 0x01]
        b = UInt8[]; encode_varint!(b, 0);   @test b == UInt8[0x00]
        v, n = decode_varint(UInt8[0x80, 0x01], 1); @test v == 128 && n == 2
    end

    @testset "base58 + peer_id round trip (multi-byte key_type)" begin
        for c in (UInt8[0x00], UInt8[0x00, 0x00, 0x01, 0x02], Vector{UInt8}(codeunits("hello world")))
            @test base58decode(base58encode(c)) == c
        end
        dg = collect(UInt8, 0:31)
        pid = peerid_format(128, 1, dg)
        p = peerid_parse(pid)
        @test p.key_type == 128 && p.hash_type == 1 && p.digest == dg
    end

    @testset "Ed25519 (libsodium ccall) deterministic sign + verify" begin
        seed = zeros(UInt8, 32); msg = Vector{UInt8}(codeunits("hello entity"))
        sig = ed25519_sign(seed, msg); pk = ed25519_pubkey(seed)
        @test length(sig) == 64 && length(pk) == 32
        @test ed25519_verify(pk, sig, msg)
        @test !ed25519_verify(pk, sig, Vector{UInt8}(codeunits("tampered")))
        @test ed25519_sign(seed, msg) == sig            # determinism
    end

    @testset "wire-conformance corpus (71/71 byte-identical)" begin
        fixture = joinpath(@__DIR__, "..", "..", "shared", "test-vectors", "v0.8.0",
                           "conformance-vectors-v1.cbor")
        include("harness.jl")
        pass, fail, _, _ = run_conformance(fixture; verbose = true)
        @test fail == 0
        @test pass == 71
    end

end
