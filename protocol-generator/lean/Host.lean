/-
  Standalone peer host — the runnable target for S4 conformance. Boots one peer
  listener on a TCP port and blocks, so the entity-core-go `validate-peer` oracle
  can drive the live wire surface. Twin of the cohort hosts.

    --port N               listen port (default 7777; 0 = auto-assign)
    --debug-open-grants    select the degenerate `default → *` seed policy
                           (DEPRECATED v7.74 §6.9a; reachable grant-gated paths)
    --validate             register the §7a system/validate/* conformance handlers
                           (echo + dispatch-outbound), OFF by default
    --name NAME            load a persistent Ed25519 identity from the standard
                           on-disk location ~/.entity/peers/NAME/keypair (the
                           entity-core PEM keypair: base64 of a 32-byte seed
                           between BEGIN/END ENTITY PRIVATE KEY lines — the same
                           convention the Go entity-peer --name + peer-manager use).
                           Without --name a fresh per-boot keypair is minted.

  A single `LISTENING …` line on stdout signals readiness (run-s4 greps it).
-/
import EntityCore.Transport

/-- Decode standard-alphabet base64, ignoring whitespace, padding, and any other
non-alphabet characters (mirrors the cohort's `b64_decode`). Accumulates sextets
and emits a byte whenever ≥8 bits are buffered. -/
def b64Decode (s : String) : ByteArray := Id.run do
  let tbl (c : Char) : Int :=
    if c ≥ 'A' && c ≤ 'Z' then (c.toNat - 65 : Int)
    else if c ≥ 'a' && c ≤ 'z' then (c.toNat - 71 : Int)
    else if c ≥ '0' && c ≤ '9' then (c.toNat + 4 : Int)
    else if c = '+' then 62
    else if c = '/' then 63
    else -1
  let mut out := ByteArray.empty
  let mut acc : Nat := 0
  let mut bits : Nat := 0
  for c in s.data do
    let v := tbl c
    if v ≥ 0 then
      acc := (acc <<< 6) ||| v.toNat
      bits := bits + 6
      if bits ≥ 8 then
        bits := bits - 8
        out := out.push (UInt8.ofNat ((acc >>> bits) &&& 0xff))
  pure out

/-- Load the 32-byte Ed25519 seed from the standard on-disk keypair
(`~/.entity/peers/NAME/keypair`): a PEM whose body is base64(seed) between
BEGIN/END lines. HOME via `IO.getEnv`, default `/root`. Missing/malformed →
eprintln + exit 2 (matches the cohort `--name` contract). -/
def loadSeedFromName (name : String) : IO ByteArray := do
  let home := (← IO.getEnv "HOME").getD "/root"
  let path := s!"{home}/.entity/peers/{name}/keypair"
  let contents ← (IO.FS.readFile path).toBaseIO
  match contents with
  | .error e =>
      IO.eprintln s!"error: --name {name}: {e}"
      IO.Process.exit 2
  | .ok text =>
      -- strip PEM armor lines (those beginning with '-')
      let body := String.join (text.splitOn "\n" |>.filter (fun l =>
        !(l.length > 0 && l.get 0 = '-')))
      let seed := b64Decode body
      if seed.size ≠ 32 then
        IO.eprintln s!"error: --name {name}: expected a 32-byte seed, got {seed.size} bytes"
        IO.Process.exit 2
      pure seed

partial def parseArgs (args : List String) (port : Nat) (og v : Bool)
    (seed : Option ByteArray) : IO (Nat × Bool × Bool × Option ByteArray) := do
  match args with
  | [] => pure (port, og, v, seed)
  | "--port" :: n :: rest => parseArgs rest (n.toNat?.getD 7777) og v seed
  | "--name" :: n :: rest => do
      let s ← loadSeedFromName n
      parseArgs rest port og v (some s)
  | "--debug-open-grants" :: rest => do
      IO.eprintln "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a) — selects the degenerate `default -> *` seed policy."
      parseArgs rest port true v seed
  | "--validate" :: rest => parseArgs rest port og true seed
  | "-h" :: _ => do IO.println "usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]"; pure (port, og, v, seed)
  | "--help" :: _ => do IO.println "usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]"; pure (port, og, v, seed)
  | arg :: rest => do
      IO.eprintln s!"warning: ignoring unknown argument '{arg}'"; parseArgs rest port og v seed

def main (args : List String) : IO UInt32 := do
  let (port, openGrants, validate, seed) ← parseArgs args 7777 false false none
  let peer ← EntityCore.Peer.create openGrants validate seed
  let lfd ← EntityCore.Net.tcpListen (UInt16.ofNat port)
  if lfd == EntityCore.Net.badfd then
    IO.eprintln "error: listen failed"; return 1
  let bound ← EntityCore.Net.tcpBoundPort lfd
  IO.println s!"LISTENING 127.0.0.1:{bound} peer_id={peer.localPeer} open_grants={openGrants} validate={validate}"
  (← IO.getStdout).flush
  EntityCore.Transport.acceptLoop peer lfd
  return 0
