--  Entity_Core.Protocol.Wire — §1.6 framing + the two message builders (L2).
--
--  Frame := [4-byte BE length][CBOR payload]; the payload is a CBOR-encoded
--  system/protocol/envelope (§3.1).
--
--  Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
--  authenticate are OPERATIONS on system/protocol/connect, not message types —
--  any other root type → the server returns no response (the connection-close
--  contract lives in the dispatcher).
--
--  §4.10 resource bound (substrate floor): the max inbound payload is checked on
--  the LENGTH PREFIX, BEFORE the body is buffered. An over-limit frame is a
--  protocol fault the reader surfaces as a Payload_Too_Large transport signal
--  (the dispatcher maps it to 413). Default 16 MiB.

with Ada.Exceptions;
with Interfaces;
with Entity_Core.Bytes;
with Entity_Core.Codec.Value;
with Entity_Core.Protocol.Entity;
with Entity_Core.Protocol.Envelope;
with GNAT.Sockets;

package Entity_Core.Protocol.Wire is

   use Entity_Core.Bytes;
   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Entity;

   --  §1.6 SHOULD bound — 16 MiB.
   Max_Frame : constant := 16 * 1024 * 1024;

   ---------------------------------------------------------------------------
   --  Frame read/write over a GNAT.Sockets socket.
   ---------------------------------------------------------------------------

   --  Read one length-prefixed frame; return its CBOR payload bytes. EOF sets
   --  At_Eof (a clean connection close at a frame boundary). An over-limit
   --  length prefix raises Errors.Payload_Too_Large (checked BEFORE buffering
   --  the body — §4.10). A truncated/short read raises Errors.<transport>.
   function Read_Frame
     (Socket : GNAT.Sockets.Socket_Type; At_Eof : out Boolean) return Byte_Array;

   --  Write Payload as a length-prefixed frame. The caller serializes
   --  concurrent writers on the same socket.
   procedure Write_Frame (Socket : GNAT.Sockets.Socket_Type; Payload : Byte_Array);

   --  Envelope <-> frame.
   function Envelope_Of_Frame (Payload : Byte_Array)
                               return Entity_Core.Protocol.Envelope.Protocol_Envelope;
   function Frame_Of_Envelope (E : Entity_Core.Protocol.Envelope.Protocol_Envelope)
                               return Byte_Array;

   --  §6.3 rejection reporting: recover ONLY the request_id from a frame the
   --  strict decoder rejected, so the rejection can be delivered as a correlated
   --  `400 non_canonical_ecf` response instead of silence. The frame stays
   --  rejected -- nothing else is read out of it. Returns "" when even the
   --  request_id is unrecoverable (an unattributable frame, where silence is the
   --  only option left). See Codec.Cbor.Decode_Salvage.
   function Salvage_Request_Id (Payload : Byte_Array) return String;

   ---------------------------------------------------------------------------
   --  §4.11 pre-admission refusal classification (0.8.2.25).
   --
   --  "A peer that refuses a frame pre-admission MUST put a coded
   --  EXECUTE_RESPONSE on the wire [MUST] -- correlated by request_id where the
   --  id is available, and otherwise as a best-effort coded frame carrying no
   --  correlation." §4.9(c)'s deliver-or-signal rule is scoped to "every request
   --  the peer ADMITS" and therefore reaches none of these, which is why §4.11
   --  exists.
   --
   --  "The frame obligation belongs to the class; the CODE belongs to the cause
   --  [MUST]" -- a single code for the class would answer an honest caller under
   --  the wrong reason and send them to the wrong layer:
   --
   --    connect-auth proof-of-possession      401 authentication_failed  (§4.6/§4.7 --
   --                                             the connect handler's, not here)
   --    envelope over the configured maximum  413 payload_too_large      (§4.10(a), N14)
   --    resolution integrity (mis-keyed inc.) 400 hash_mismatch          (§5.2a, §1.8)
   --    framing / never becomes an Envelope   400 invalid_request        (§4.7, §4.11)
   --    root is neither EXECUTE nor E_R       400 invalid_request        (§3.3, §4.11 --
   --                                             in Handlers.Dispatch, not here)
   --
   --  THE TAG ARM KEEPS non_canonical_ecf AND THAT IS DELIBERATE. §4.11 rules
   --  that code non-conformant "on the framing arm" and gives its reason in the
   --  same sentence: ENTITY-CBOR-ENCODING defines it for CBOR tag-policy
   --  violations specifically, which that document still MUSTs at decode time
   --  (§6.3). The two rows are disjoint by CAUSE rather than in conflict.
   --  Everything else this decoder calls non-canonical (a non-minimal head, an
   --  indefinite length, mis-ordered keys) is genuinely "non-canonical CBOR that
   --  never becomes an Envelope" and takes invalid_request.
   --
   --  THE CAUSE IS AN ENUM AND THE CLASSIFIER DISPATCHES ON EXCEPTION IDENTITY,
   --  not on Exception_Message. Ada has no exception inheritance, so identity IS
   --  the taxonomy; a message match would be one string edit away from silently
   --  re-collapsing two causes into one code.
   type Pre_Admission_Cause is
     (Cause_Oversize,        --  413 payload_too_large
      Cause_Hash_Mismatch,   --  400 hash_mismatch
      Cause_Tag_Policy,      --  400 non_canonical_ecf
      Cause_Framing);        --  400 invalid_request

   function Classify_Pre_Admission
     (X : Ada.Exceptions.Exception_Occurrence) return Pre_Admission_Cause;

   function Refusal_Status (C : Pre_Admission_Cause) return Interfaces.Unsigned_64;
   function Refusal_Code (C : Pre_Admission_Cause) return String;

   --  A FIXED TABLE, never the internal exception message: an exception message
   --  is a developer diagnostic and can name internal state. ASCII by discipline
   --  (a wire-visible string is ASCII-only; the §-style citations stay in
   --  comments).
   function Refusal_Message (C : Pre_Admission_Cause) return String;

   --  Whether a Read_Frame failure is a REFUSAL owed a coded frame at all. A
   --  closed or reset socket is not a refusal of anything and there is nobody
   --  left to answer; a clean EOF at a FRAME BOUNDARY is reported through
   --  Read_Frame's At_Eof rather than as an exception, so it never reaches here.
   function Is_Framing_Refusal
     (X : Ada.Exceptions.Exception_Occurrence) return Boolean;

   ---------------------------------------------------------------------------
   --  EXECUTE builder (§3.2).
   ---------------------------------------------------------------------------

   --  Build an EXECUTE entity. Author / Capability are 33-byte hashes (passed as
   --  Byte_Arrays; empty => omit the field). Resource is a cbor map
   --  {targets:[...]} or the null value to omit.
   function Make_Execute
     (Request_Id : String;
      Uri        : String;
      Operation  : String;
      Params     : Materialized_Entity;
      Author     : Byte_Array := Empty_Bytes;
      Capability : Byte_Array := Empty_Bytes;
      Resource   : Ecf_Value := Make_Null) return Materialized_Entity;

   ---------------------------------------------------------------------------
   --  EXECUTE_RESPONSE builder (§3.3).
   ---------------------------------------------------------------------------
   function Make_Response
     (Request_Id : String; Status : Interfaces.Unsigned_64; Result : Materialized_Entity)
      return Materialized_Entity;

   --  Error result + empty params + a resource-target map.
   function Error_Result (Code : String; Message : String := "") return Materialized_Entity;
   function Empty_Params return Materialized_Entity;
   function Resource_Target (Target : String) return Ecf_Value
     with Post => Kind (Resource_Target'Result) = K_Map;

   ---------------------------------------------------------------------------
   --  Response decode helpers (initiator side).
   ---------------------------------------------------------------------------
   function Response_Status (E : Entity_Core.Protocol.Envelope.Protocol_Envelope)
                             return Interfaces.Unsigned_64;
   function Response_Result (E : Entity_Core.Protocol.Envelope.Protocol_Envelope;
                             Found : out Boolean) return Materialized_Entity;

end Entity_Core.Protocol.Wire;
