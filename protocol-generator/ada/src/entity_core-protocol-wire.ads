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
