with Ada.Streams;
with Entity_Core.Codec.Cbor;
with Entity_Core.Protocol.Cbor_Util;
with Entity_Core.Errors;

package body Entity_Core.Protocol.Wire is

   use Entity_Core.Protocol.Cbor_Util;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_32;

   package Sock renames GNAT.Sockets;

   ---------------------------------------------------------------------------
   --  Low-level exact read/write helpers over a GNAT.Sockets socket. The wire
   --  octets are Stream_Element_Array; we convert at the boundary to/from the
   --  codec's Byte_Array (both are octet arrays).
   ---------------------------------------------------------------------------

   --  Read exactly N octets. Sets At_Eof on a clean close before any byte of
   --  this read; raises Truncated_Input on a partial frame (peer vanished
   --  mid-frame). N may be 0 (returns empty).
   procedure Read_Exact
     (Socket : Sock.Socket_Type;
      N      : Natural;
      Buf    : out Byte_Array;
      At_Eof : out Boolean)
   is
      Got   : Natural := 0;
   begin
      At_Eof := False;
      if N = 0 then
         return;
      end if;
      while Got < N loop
         declare
            Chunk : Ada.Streams.Stream_Element_Array
                      (1 .. Ada.Streams.Stream_Element_Offset (N - Got));
            Last  : Ada.Streams.Stream_Element_Offset;
         begin
            Sock.Receive_Socket (Socket, Chunk, Last);
            if Last < Chunk'First then
               --  Peer closed.
               if Got = 0 then
                  At_Eof := True;
                  return;
               else
                  raise Entity_Core.Errors.Truncated_Input with "frame truncated";
               end if;
            end if;
            for I in Chunk'First .. Last loop
               Got := Got + 1;
               Buf (Buf'First + Got - 1) := Octet (Chunk (I));
            end loop;
         end;
      end loop;
   end Read_Exact;

   ----------------
   -- Read_Frame --
   ----------------
   function Read_Frame
     (Socket : Sock.Socket_Type; At_Eof : out Boolean) return Byte_Array
   is
      Hdr : Byte_Array (1 .. 4);
      Len : Interfaces.Unsigned_32;
   begin
      Read_Exact (Socket, 4, Hdr, At_Eof);
      if At_Eof then
         return Empty_Bytes;
      end if;
      Len := Interfaces.Shift_Left (Interfaces.Unsigned_32 (Hdr (1)), 24)
           or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Hdr (2)), 16)
           or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Hdr (3)), 8)
           or Interfaces.Unsigned_32 (Hdr (4));
      --  §4.10: reject an over-limit frame on the LENGTH PREFIX, before
      --  buffering the body.
      if Len > Interfaces.Unsigned_32 (Max_Frame) then
         raise Entity_Core.Errors.Payload_Too_Large
           with "frame length" & Interfaces.Unsigned_32'Image (Len) & " exceeds max";
      end if;
      declare
         Payload : Byte_Array (1 .. Natural (Len));
      begin
         Read_Exact (Socket, Natural (Len), Payload, At_Eof);
         if At_Eof then
            raise Entity_Core.Errors.Truncated_Input with "eof after length prefix";
         end if;
         return Payload;
      end;
   end Read_Frame;

   -----------------
   -- Write_Frame --
   -----------------
   procedure Write_Frame (Socket : Sock.Socket_Type; Payload : Byte_Array) is
      Len : constant Interfaces.Unsigned_32 := Interfaces.Unsigned_32 (Payload'Length);
      Hdr : constant Byte_Array (1 .. 4) :=
        (1 => Octet (Interfaces.Shift_Right (Len, 24) and 16#FF#),
         2 => Octet (Interfaces.Shift_Right (Len, 16) and 16#FF#),
         3 => Octet (Interfaces.Shift_Right (Len, 8) and 16#FF#),
         4 => Octet (Len and 16#FF#));

      procedure Send_All (Data : Byte_Array) is
         Buf  : Ada.Streams.Stream_Element_Array
                  (1 .. Ada.Streams.Stream_Element_Offset (Data'Length));
         Last : Ada.Streams.Stream_Element_Offset;
         From : Ada.Streams.Stream_Element_Offset := 1;
      begin
         for I in Data'Range loop
            Buf (Ada.Streams.Stream_Element_Offset (I - Data'First + 1)) :=
              Ada.Streams.Stream_Element (Data (I));
         end loop;
         while From <= Buf'Last loop
            Sock.Send_Socket (Socket, Buf (From .. Buf'Last), Last);
            exit when Last < From;   --  short/closed write
            From := Last + 1;
         end loop;
      end Send_All;
   begin
      Send_All (Hdr);
      Send_All (Payload);
   end Write_Frame;

   -----------------------
   -- Envelope_Of_Frame --
   -----------------------
   function Envelope_Of_Frame (Payload : Byte_Array)
                               return Entity_Core.Protocol.Envelope.Protocol_Envelope is
      V : constant Ecf_Value := Entity_Core.Codec.Cbor.Decode (Payload);
   begin
      if Kind (V) /= K_Map then
         raise Entity_Core.Errors.Non_Canonical_Ecf with "frame: not a map";
      end if;
      return Entity_Core.Protocol.Envelope.Of_Cbor (V);
   end Envelope_Of_Frame;

   -----------------------
   -- Frame_Of_Envelope --
   -----------------------
   function Frame_Of_Envelope (E : Entity_Core.Protocol.Envelope.Protocol_Envelope)
                               return Byte_Array is
   begin
      return Entity_Core.Codec.Cbor.Encode (Entity_Core.Protocol.Envelope.To_Cbor (E));
   end Frame_Of_Envelope;

   ------------------
   -- Make_Execute --
   ------------------
   function Make_Execute
     (Request_Id : String;
      Uri        : String;
      Operation  : String;
      Params     : Materialized_Entity;
      Author     : Byte_Array := Empty_Bytes;
      Capability : Byte_Array := Empty_Bytes;
      Resource   : Ecf_Value := Make_Null) return Materialized_Entity
   is
      --  Build the kv list incrementally (Author/Capability/Resource optional).
      Base : constant Kv_List :=
        ((Key => K ("request_id"), Value => Make_Text (Request_Id)),
         (Key => K ("uri"),        Value => Make_Text (Uri)),
         (Key => K ("operation"),  Value => Make_Text (Operation)),
         (Key => K ("params"),     Value => To_Cbor (Params)));
      Has_Author : constant Boolean := Author'Length > 0;
      Has_Cap    : constant Boolean := Capability'Length > 0;
      Has_Res    : constant Boolean := Kind (Resource) = K_Map;
      Extra      : constant Natural :=
        (if Has_Author then 1 else 0) + (if Has_Cap then 1 else 0)
        + (if Has_Res then 1 else 0);
      All_Kv     : Kv_List (1 .. Base'Length + Extra);
      Idx        : Positive := 1;
   begin
      for B of Base loop
         All_Kv (Idx) := B;
         Idx := Idx + 1;
      end loop;
      if Has_Author then
         All_Kv (Idx) := (Key => K ("author"), Value => Make_Bytes (Author));
         Idx := Idx + 1;
      end if;
      if Has_Cap then
         All_Kv (Idx) := (Key => K ("capability"), Value => Make_Bytes (Capability));
         Idx := Idx + 1;
      end if;
      if Has_Res then
         All_Kv (Idx) := (Key => K ("resource"), Value => Resource);
         Idx := Idx + 1;
      end if;
      return Make ("system/protocol/execute", Map_Of (All_Kv));
   end Make_Execute;

   -------------------
   -- Make_Response --
   -------------------
   function Make_Response
     (Request_Id : String; Status : Interfaces.Unsigned_64; Result : Materialized_Entity)
      return Materialized_Entity is
   begin
      return Make ("system/protocol/execute/response",
        Map_Of (((Key => K ("request_id"), Value => Make_Text (Request_Id)),
                 (Key => K ("status"),     Value => Make_Uint (Status)),
                 (Key => K ("result"),     Value => To_Cbor (Result)))));
   end Make_Response;

   ------------------
   -- Error_Result --
   ------------------
   function Error_Result (Code : String; Message : String := "") return Materialized_Entity is
   begin
      if Message = "" then
         return Make ("system/protocol/error",
           Map_Of ((1 => (Key => K ("code"), Value => Make_Text (Code)))));
      end if;
      return Make ("system/protocol/error",
        Map_Of (((Key => K ("code"),    Value => Make_Text (Code)),
                 (Key => K ("message"), Value => Make_Text (Message)))));
   end Error_Result;

   ------------------
   -- Empty_Params --
   ------------------
   function Empty_Params return Materialized_Entity is
   begin
      return Make ("primitive/any", Empty_Map);
   end Empty_Params;

   ---------------------
   -- Resource_Target --
   ---------------------
   function Resource_Target (Target : String) return Ecf_Value is
      One : constant Value_Vector (1 .. 1) := (1 => Make_Text (Target));
   begin
      return Map_Of ((1 => (Key => K ("targets"), Value => Make_Array (One))));
   end Resource_Target;

   ---------------------
   -- Response_Status --
   ---------------------
   function Response_Status (E : Entity_Core.Protocol.Envelope.Protocol_Envelope)
                             return Interfaces.Unsigned_64 is
      Found : Boolean;
   begin
      return Uint_Field (Data (E.Root), "status", Found);
   end Response_Status;

   ---------------------
   -- Response_Result --
   ---------------------
   function Response_Result (E : Entity_Core.Protocol.Envelope.Protocol_Envelope;
                             Found : out Boolean) return Materialized_Entity is
      Result_V : constant Ecf_Value := Field (Data (E.Root), "result", Found);
   begin
      if Found and then Kind (Result_V) = K_Map and then Has (Result_V, "type") then
         return Of_Cbor (Result_V);
      end if;
      Found := False;
      return Make ("primitive/any", Empty_Map);
   end Response_Result;

end Entity_Core.Protocol.Wire;
