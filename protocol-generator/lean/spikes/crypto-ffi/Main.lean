/-
  Lean S1/1c spike — CRYPTO FFI.

  Confirms we can link libentitycore_codec (C-ABI) and call into it from Lean:
    - SHA-256 of "abc" == the FIPS-180-4 known-answer (proves the byte boundary).
    - ec_impl_info() provenance string (proves we linked the intended library).
    - Ed25519 keygen+sign+verify round-trip (proves the signature boundary).

  These are the @[extern] bindings — opaque, axiomatic to the kernel (1a finding:
  extern functions don't reduce). This is the deliberate prove-the-protocol /
  trust-the-curve boundary the spec itself draws (V7 cites Ed25519, doesn't define it).
-/

@[extern "ec_lean_sha256"]
opaque sha256 (data : @& ByteArray) : ByteArray

@[extern "ec_lean_impl_info"]
opaque implInfo (u : Unit) : String

@[extern "ec_lean_ed25519_selftest"]
opaque ed25519Selftest (msg : @& ByteArray) : Bool

private def nyb (n : Nat) : Char := "0123456789abcdef".toList.getD n '?'

def hex (b : ByteArray) : String :=
  b.toList.foldl (fun s x => s ++ String.ofList [nyb (x.toNat / 16), nyb (x.toNat % 16)]) ""

def main : IO Unit := do
  IO.println s!"linked impl : {implInfo ()}"

  let h := sha256 ("abc".toUTF8)
  let got := hex h
  let want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  IO.println s!"sha256(abc) : {got}"
  IO.println s!"expected    : {want}"
  let shaOk := got == want
  IO.println s!"SHA-256 FFI : {if shaOk then "OK" else "MISMATCH"}"

  let edOk := ed25519Selftest ("hello entity core".toUTF8)
  IO.println s!"Ed25519 FFI : {if edOk then "keygen+sign+verify OK" else "FAILED"}"

  if shaOk && edOk then
    IO.println "crypto FFI spike: GREEN"
  else
    IO.Process.exit 1
