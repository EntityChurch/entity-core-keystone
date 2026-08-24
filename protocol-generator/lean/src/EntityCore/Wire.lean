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

/-- Recover ONLY the `request_id` from a frame the strict decoder rejected, so the
rejection can be delivered as a correlated `400 non_canonical_ecf` response (§6.3)
instead of silence or a closed connection.

The frame stays rejected. Nothing else is read out of it: no entity is built,
nothing is stored, and the offending tag is discarded rather than interpreted. The
envelope and entity-wrapper shapes are fixed maps with no legal tag position
(§6.3), so a frame whose only defect is a tag inside some entity's `data` still has
a structurally sound root -- exactly the case this recovers. -/
def salvageRequestId (payload : ByteArray) : Option String :=
  match EntityCore.Codec.decodeSalvage payload with
  | .error _ => none
  | .ok v =>
      match mapGet v "root" with
      | some r =>
          match mapGet r "data" with
          | some d => match mapGet d "request_id" with
                      | some (.text rid) => some rid
                      | _ => none
          | none => none
      | none => none

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
