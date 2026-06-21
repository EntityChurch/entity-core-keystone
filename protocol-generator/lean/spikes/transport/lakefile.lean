import Lake
open Lake DSL System

package transport

target socket_shim.o pkg : FilePath := do
  let oFile := pkg.buildDir / "socket_shim.o"
  let srcJob ← inputTextFile <| pkg.dir / "socket_shim.c"
  let leanDir := (← getLeanIncludeDir).toString
  buildO oFile srcJob #["-I", leanDir, "-fPIC"] #[] "cc"

extern_lib libsocketshim pkg := do
  let name := nameToStaticLib "socketshim"
  let o ← socket_shim.o.fetch
  buildStaticLib (pkg.staticLibDir / name) #[o]

@[default_target]
lean_exe transport where
  root := `Main
  -- sockets are libc; no external lib to link.
