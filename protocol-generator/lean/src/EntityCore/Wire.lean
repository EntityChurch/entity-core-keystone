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

/-- Parse a CBOR payload to an envelope (`none` on malformed bytes). Retained for
callers with no error channel; the reader loop uses `envelopeOfPayloadE`, because a
caller that discards the CAUSE cannot answer the code §4.11 assigns it. -/
def envelopeOfPayload (payload : ByteArray) : Option Envelope :=
  match EntityCore.Codec.decode payload with
  | .ok v => envelopeOfCbor v
  | .error _ => none

/-- §4.11's pre-admission refusal causes (0.8.2.25). The two framing arms arise
BELOW the decoder, where no CBOR was ever parsed and there is no `CodecError` to
carry them, so they live here alongside the decode causes and the whole
classification is one table. -/
inductive PreAdmission where
  /-- §4.10(a) / N14: the declared envelope exceeds the configured maximum. Reported
  BEFORE the body is buffered, so nothing is spent on it. -/
  | frameTooLarge
  /-- A length prefix declaring N bytes followed by fewer — §4.11's framing arm.
  DISTINCT from EOF: a clean close is not a refusal of anything and there is nobody
  left to answer. -/
  | frameTruncated
  /-- §6.3 / ENTITY-CBOR-ENCODING §5.4: a major-type-6 tag in a data-field position. -/
  | tagRejected
  /-- §1.8 / §5.2a resolution integrity — a hash claim that does not bind. -/
  | hashMismatch
  /-- Bytes that never become an Envelope. -/
  | malformed
  deriving Repr, Inhabited, BEq

/-- The (status, code) §4.11 assigns a pre-admission refusal's CAUSE (0.8.2.25).

"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
wire [MUST] — correlated by `request_id` where the id is available, and otherwise as
a best-effort coded frame carrying no correlation." §4.9(c)'s deliver-or-signal rule
is scoped to "every request the peer ADMITS" and therefore reaches none of these,
which is why §4.11 exists.

THE FRAME OBLIGATION BELONGS TO THE CLASS; THE CODE BELONGS TO THE CAUSE [MUST].

```
connect-auth proof-of-possession    401 authentication_failed  (the connect handler's)
envelope over the configured max     413 payload_too_large      (§4.10(a), N14)
resolution integrity (mis-keyed)     400 hash_mismatch          (§5.2a, §1.8)
framing / never becomes an Envelope  400 invalid_request        (§4.7, §4.11)
root neither EXECUTE nor RESPONSE    400 invalid_request        (§3.3, N12/N17 — in
                                                                 dispatch, not here)
```

The CBOR tag-policy arm keeps `non_canonical_ecf` and that is deliberate. §4.11 rules
that code non-conformant "on the framing arm" and gives its reason in the same
sentence: ENTITY-CBOR-ENCODING §5.4 "defines that code for CBOR tag-policy violations
specifically", which that document still MUSTs at decode time. §6.3 disjoins the two
by CAUSE — a tag in a DATA-FIELD position is the policy violation; bytes that never
become an Envelope are the framing arm — so there is no conflict of MUSTs to
reconcile, and this branch keeps the behaviour the `tag_reject` vectors were written
against. -/
def preAdmissionRefusal : PreAdmission → Nat × String
  | .frameTooLarge => (413, "payload_too_large")
  | .frameTruncated => (400, "invalid_request")
  | .tagRejected => (400, "non_canonical_ecf")
  | .hashMismatch => (400, "hash_mismatch")
  | .malformed => (400, "invalid_request")

/-- Parse a CBOR payload to an envelope, keeping the §4.11 CAUSE. -/
def envelopeOfPayloadE (payload : ByteArray) : Except PreAdmission Envelope :=
  match EntityCore.Codec.decode payload with
  | .error (.tagRejected _) => .error .tagRejected
  | .error _ => .error .malformed
  | .ok v =>
    match envelopeOfCborE v with
    | .ok e => .ok e
    | .error .hashMismatch => .error .hashMismatch
    | .error .malformed => .error .malformed

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

/-- EXECUTE builder (§3.2) — the §6.13(b) handler outbound seam.

`capability` is OPTIONAL because §1.4's PD-2 AMBIENT arm carries no credential at all:
the sub-dispatch is authorized by the executing handler's own grant and there is
nothing to name. An empty `ByteArray` would NOT do — that is a present field holding a
hash that resolves to nothing, which §5.2 reads as an unresolvable capability rather
than as its absence. -/
def makeExecute (requestId uri operation : String) (params : Entity)
    (author : ByteArray) (capability : Option ByteArray) (resource : Option Value := none) : Entity :=
  make "system/protocol/execute"
    (.map ([(.text "request_id", .text requestId),
            (.text "uri", .text uri),
            (.text "operation", .text operation),
            (.text "params", toCbor params),
            (.text "author", .bytes author)]
           ++ (match capability with | some c => [(.text "capability", .bytes c)] | none => [])
           ++ (match resource with | some r => [(.text "resource", r)] | none => [])))

end EntityCore.Wire
