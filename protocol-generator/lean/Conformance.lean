/-
  S2 conformance harness — the 69-vector Appendix-E gate.

  Loads the locked v0.8.0 corpus with OUR OWN decoder (a green load is itself a
  decoder smoke test — the fixture is pure ECF), then for each vector:
    * encode_equal — re-produce the canonical bytes per category, compare bit-for-bit;
    * decode_reject — feed the bytes to the decoder, assert rejection.
  Class-B categories (content_hash / peer_id / signature) compose canonical
  encoding with the FFI crypto / Base58 surfaces. Exit 0 iff 69/69 pass.
-/
import EntityCore

open EntityCore (Value)
open EntityCore.Codec (encode decode)

-- ── hex / lookup helpers ─────────────────────────────────────────────────────

def nyb (n : Nat) : Char := "0123456789abcdef".toList.getD n '?'

def hex (b : ByteArray) : String :=
  b.toList.foldl (fun s x => s ++ String.ofList [nyb (x.toNat / 16), nyb (x.toNat % 16)]) ""

def mapLookup (kvs : List (Value × Value)) (key : String) : Option Value :=
  (kvs.find? (fun p => match p.1 with | .text s => s == key | _ => false)).map (·.2)

-- ── vector model ─────────────────────────────────────────────────────────────

structure Vec where
  id : String
  kind : String
  input : Option Value
  canonical : ByteArray

def category (id : String) : String := (id.splitOn ".").headD ""

def parseVector (v : Value) : Option Vec :=
  match v with
  | .map kvs =>
    match mapLookup kvs "id", mapLookup kvs "kind", mapLookup kvs "canonical" with
    | some (.text id), some (.text kind), some (.bytes canon) =>
        some { id, kind, input := mapLookup kvs "input", canonical := canon }
    | _, _, _ => none
  | _ => none

-- ── per-category producers ───────────────────────────────────────────────────

def produceContentHash (input : Value) : Except String ByteArray :=
  match input with
  | .map kvs =>
    match mapLookup kvs "type" with
    | some (.text typ) =>
        let dataV := (mapLookup kvs "data").getD .null
        let fmt := match mapLookup kvs "format_code" with | some (.uint n) => n.toNat | _ => 0
        .ok (EntityCore.ContentHash.contentHash fmt typ dataV)
    | _ => .error "content_hash: type missing/not text"
  | _ => .error "content_hash input not a map"

def producePeerId (input : Value) : Except String ByteArray :=
  match input with
  | .map kvs =>
    match mapLookup kvs "key_type", mapLookup kvs "hash_type", mapLookup kvs "digest" with
    | some (.uint kt), some (.uint ht), some (.bytes dg) =>
        .ok (encode (.text (EntityCore.PeerId.formatPeerId kt.toNat ht.toNat dg)))
    | _, _, _ => .error "peer_id: components missing"
  | _ => .error "peer_id input not a map"

def produceSignature (input : Value) : Except String ByteArray :=
  match input with
  | .map kvs =>
    match mapLookup kvs "seed", mapLookup kvs "entity" with
    | some (.bytes seed), some (.map ekvs) =>
        match mapLookup ekvs "type" with
        | some (.text typ) =>
            let dataV := (mapLookup ekvs "data").getD .null
            .ok (EntityCore.Signature.signEntity seed typ dataV)
        | _ => .error "signature: entity type missing/not text"
    | _, _ => .error "signature: seed/entity missing"
  | _ => .error "signature input not a map"

def produce (v : Vec) : Except String ByteArray :=
  match v.input with
  | none => .error "encode_equal vector has no input"
  | some input =>
    match category v.id with
    | "content_hash" => produceContentHash input
    | "peer_id" => producePeerId input
    | "signature" => produceSignature input
    | _ => .ok (encode input)

def runVector (v : Vec) : Except String Unit :=
  if v.kind == "decode_reject" then
    match decode v.canonical with
    | .error _ => .ok ()
    | .ok _ => .error "decoder ACCEPTED a decode_reject vector"
  else
    match produce v with
    | .error e => .error e
    | .ok bytes =>
        if bytes == v.canonical then .ok ()
        else .error s!"byte mismatch\n      want {hex v.canonical}\n      got  {hex bytes}"

-- ── main ─────────────────────────────────────────────────────────────────────

def main (args : List String) : IO UInt32 := do
  let path := args.headD "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
  let raw ← IO.FS.readBinFile path
  IO.println s!"corpus       : {path} ({raw.size} bytes)"
  IO.println s!"corpus sha256: {hex (EntityCore.Crypto.sha256 raw)}"
  IO.println s!"linked codec : {EntityCore.Crypto.implInfo ()}"
  match decode raw with
  | .error e =>
      IO.eprintln s!"corpus decode FAILED: {e.message}"
      pure 1
  | .ok (.array items) => do
      let mut pass := 0
      let mut fail := 0
      for it in items do
        match parseVector it with
        | none => IO.eprintln "  bad vector shape"; fail := fail + 1
        | some v =>
          match runVector v with
          | .ok () => pass := pass + 1
          | .error reason =>
              IO.eprintln s!"  FAIL {v.id}: {reason}"
              fail := fail + 1
      IO.println s!"\nvectors: {pass} pass · {fail} fail (of {items.length})"
      pure (if fail == 0 then 0 else 1)
  | .ok _ =>
      IO.eprintln "corpus root is not an array"
      pure 1
