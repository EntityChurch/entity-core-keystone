import Lake
open Lake DSL System

package cryptoffi

-- Compile the C shim to an object file, with Lean's headers on the include path.
target ffi_shim.o pkg : FilePath := do
  let oFile := pkg.buildDir / "ffi_shim.o"
  let srcJob ← inputTextFile <| pkg.dir / "ffi_shim.c"
  let leanDir := (← getLeanIncludeDir).toString
  buildO oFile srcJob #["-I", leanDir, "-fPIC"] #[] "cc"

-- Bundle the shim object as a static lib so the exe links it in.
extern_lib libffishim pkg := do
  let name := nameToStaticLib "ffishim"
  let o ← ffi_shim.o.fetch
  buildStaticLib (pkg.staticLibDir / name) #[o]

@[default_target]
lean_exe cryptoffi where
  root := `Main
  -- Link libentitycore_codec (mounted at /codec). Self-contained Rust cdylib.
  moreLinkArgs := #["-L/codec", "-lentitycore_codec"]
