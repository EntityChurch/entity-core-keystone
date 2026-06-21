import Lake
open Lake DSL System

/-
  entity-core-protocol-lean — Lake build (S2).

  Two library targets, per the S1 layout decision (1a finding #4 — keep the
  SHIPPING peer mathlib-free, isolate proof deps):

    * `EntityCore`        (srcDir "src")    — the peer. Pure Lean codec/verdict
                                              + @[extern] crypto/transport shell.
                                              Init/Std only; NO mathlib.
    * `EntityCoreProofs`  (srcDir "proofs") — Track B. Built deliberately with
                                              `lake build EntityCoreProofs`; the
                                              build IS the proof check (a `sorry`
                                              or failed proof fails the build).
                                              Core-Lean tactics only so far —
                                              mathlib stays unpinned/unused until
                                              a proof genuinely needs it.

  Crypto is FFI-hybrid (S1 1a §4): a tiny C shim bridges Lean's ByteArray ABI to
  libentitycore_codec's C-ABI byte-pointer functions. The shim is compiled in via
  `extern_lib`; the external codec `.so` is linked through the exe's `moreLinkArgs`
  (mounted at /codec in-container; `ec_impl_info` records provenance, not the path).
-/

package «entity-core-protocol-lean» where
  -- Pure-core modules must stay kernel-reducible; never blanket-@[extern] them.
  leanOptions := #[]

-- The crypto FFI shim: ByteArray ↔ C-ABI (ec_sha256, ec_ed25519_sign, …).
target ec_ffi_shim.o pkg : FilePath := do
  let oFile := pkg.buildDir / "ec_ffi_shim.o"
  let srcJob ← inputTextFile <| pkg.dir / "ffi" / "ec_ffi_shim.c"
  let leanDir := (← getLeanIncludeDir).toString
  buildO oFile srcJob #["-I", leanDir, "-fPIC"] #[] "cc"

extern_lib libecffishim pkg := do
  let name := nameToStaticLib "ecffishim"
  let o ← ec_ffi_shim.o.fetch
  buildStaticLib (pkg.staticLibDir / name) #[o]

-- The TCP socket shim (S3 transport): blocking POSIX sockets + framed recv_exact.
target ec_socket_shim.o pkg : FilePath := do
  let oFile := pkg.buildDir / "ec_socket_shim.o"
  let srcJob ← inputTextFile <| pkg.dir / "ffi" / "ec_socket_shim.c"
  let leanDir := (← getLeanIncludeDir).toString
  buildO oFile srcJob #["-I", leanDir, "-fPIC"] #[] "cc"

extern_lib libecsocketshim pkg := do
  let name := nameToStaticLib "ecsocketshim"
  let o ← ec_socket_shim.o.fetch
  buildStaticLib (pkg.staticLibDir / name) #[o]

@[default_target]
lean_lib EntityCore where
  srcDir := "src"

-- Track B. Not a default target: `lake build EntityCoreProofs` checks the proofs.
lean_lib EntityCoreProofs where
  srcDir := "proofs"

-- The S2 conformance harness: loads the v0.8.0 corpus with our own decoder and
-- asserts the 69-vector Appendix-E gate. Links the external codec .so for the
-- Class-B crypto vectors (content_hash / signature).
@[default_target]
lean_exe conformance where
  root := `Conformance
  moreLinkArgs := #["-L/codec", "-lentitycore_codec"]

-- S3 pure verdict-core faithfulness selftest (§5.4 matcher + §5.6 attenuation).
-- Links the codec .so because Model.make computes content_hashes over the FFI.
@[default_target]
lean_exe selftest where
  root := `Selftest
  moreLinkArgs := #["-L/codec", "-lentitycore_codec"]

-- S3 peer host — the runnable validate-peer target (Transport + Peer + crypto).
@[default_target]
lean_exe host where
  root := `Host
  moreLinkArgs := #["-L/codec", "-lentitycore_codec"]
