/-
  Wire framing (§1.6) and the §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE builders.
  Frame := [4-byte BE length][CBOR payload]; the payload is a CBOR-encoded
  protocol envelope (§3.1). This module does payload↔envelope + the entity
  builders; the 4-byte header framing lives in the transport (Net) layer.
-/
import EntityCore.Model
import EntityCore.Codec

namespace EntityCore.Wire

open EntityCore (Value)
open EntityCore.Model

/-- §1.6 SHOULD bound — 16 MiB. -/
def maxFrame : Nat := 16 * 1024 * 1024

/-- CBOR payload of an envelope (no length header). -/
def payloadOfEnvelope (env : Envelope) : ByteArray :=
  EntityCore.Codec.encode (envelopeToCbor env)

/-- Parse a CBOR payload to an envelope (`none` on malformed bytes — §3.3 drop). -/
def envelopeOfPayload (payload : ByteArray) : Option Envelope :=
  match EntityCore.Codec.decode payload with
  | .ok v => envelopeOfCbor v
  | .error _ => none

-- ── builders ─────────────────────────────────────────────────────────────────

/-- system/protocol/error result entity (§3.3). -/
def errorResult (code : String) (message : Option String := none) : Entity :=
  make "system/protocol/error"
    (.map ((.text "code", .text code) ::
           (match message with | some m => [(.text "message", .text m)] | none => [])))

/-- Empty-params shape (§3.2): primitive/any whose data is the canonical empty map. -/
def emptyParams : Entity := make "primitive/any" (.map [])

/-- EXECUTE_RESPONSE builder (§3.3). -/
def makeResponse (requestId : String) (status : Nat) (result : Entity) : Entity :=
  make "system/protocol/execute/response"
    (.map [(.text "request_id", .text requestId),
           (.text "status", .uint (UInt64.ofNat status)),
           (.text "result", toCbor result)])

/-- EXECUTE builder (§3.2) — the §6.13(b) handler outbound seam. -/
def makeExecute (requestId uri operation : String) (params : Entity)
    (author capability : ByteArray) (resource : Option Value := none) : Entity :=
  make "system/protocol/execute"
    (.map ([(.text "request_id", .text requestId),
            (.text "uri", .text uri),
            (.text "operation", .text operation),
            (.text "params", toCbor params),
            (.text "author", .bytes author),
            (.text "capability", .bytes capability)]
           ++ (match resource with | some r => [(.text "resource", r)] | none => [])))

end EntityCore.Wire
