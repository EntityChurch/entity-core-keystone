with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;
with Interfaces;
with Entity_Core.Errors;

package body Entity_Core.Codec.Cbor is

   --  ECF floats legitimately include the IEEE specials (NaN / +/-Inf / -0.0).
   --  Ada's validity model would flag these as "invalid" the instant they are
   --  produced via Unchecked_Conversion / returned, raising Constraint_Error on
   --  canonical wire bytes. Turn compiler-inserted validity checks OFF for this
   --  body — float specials are first-class here, not corruption.
   pragma Validity_Checks (Off);
   pragma Suppress (Validity_Check);

   use Interfaces;

   subtype U64 is Interfaces.Unsigned_64;
   subtype U32 is Interfaces.Unsigned_32;
   subtype U16 is Interfaces.Unsigned_16;

   --  Exact IEEE bit re-interpretation (no value conversion).
   function F64_To_Bits is new Ada.Unchecked_Conversion (Long_Float, U64);
   function Bits_To_F64 is new Ada.Unchecked_Conversion (U64, Long_Float);
   function F32_To_Bits is new Ada.Unchecked_Conversion (Float, U32);
   function Bits_To_F32 is new Ada.Unchecked_Conversion (U32, Float);

   ---------------------------------------------------------------------------
   --  Big-endian emit helpers
   ---------------------------------------------------------------------------
   procedure Add_BE (Buf : in out Byte_Vector; V : U64; N_Bytes : Natural) is
   begin
      for I in reverse 0 .. N_Bytes - 1 loop
         Buf.Append (Octet (Shift_Right (V, I * 8) and 16#FF#));
      end loop;
   end Add_BE;

   --  Emit a CBOR head: major type (0..7) + minimal-length unsigned argument.
   procedure Add_Head (Buf : in out Byte_Vector; Major : U64; Arg : U64) is
      MT : constant Octet := Octet (Shift_Left (Major, 5));
   begin
      if Arg < 24 then
         Buf.Append (MT or Octet (Arg));
      elsif Arg < 256 then
         Buf.Append (MT or 24);
         Add_BE (Buf, Arg, 1);
      elsif Arg < 65536 then
         Buf.Append (MT or 25);
         Add_BE (Buf, Arg, 2);
      elsif Arg < 16#1_0000_0000# then
         Buf.Append (MT or 26);
         Add_BE (Buf, Arg, 4);
      else
         Buf.Append (MT or 27);
         Add_BE (Buf, Arg, 8);
      end if;
   end Add_Head;

   ---------------------------------------------------------------------------
   --  half-precision (float16) helpers
   ---------------------------------------------------------------------------
   --  Exact float16 -> f64 expansion, computed directly in IEEE-754 f64 BIT
   --  space so that infinities and -0.0 round-trip bit-exactly (the encoder's
   --  f16-viability test depends on this).
   function Half_To_Double (H : U16) return Long_Float is
      Sign : constant U64 := U64 (Shift_Right (H, 15) and 1);
      Exp  : constant U16 := Shift_Right (H, 10) and 16#1F#;
      Mant : constant U16 := H and 16#3FF#;
      SBit : constant U64 := Shift_Left (Sign, 63);
   begin
      if Exp = 0 then
         if Mant = 0 then
            --  +/-0.0
            return Bits_To_F64 (SBit);
         end if;
         --  subnormal half: value = mant * 2^-24. Normalise into an f64.
         declare
            M : U64 := U64 (Mant);
            E : Integer := -24;
         begin
            --  shift M up to a 53-bit (implicit-1) significand: top bit at 2^52.
            while (M and 16#10_0000_0000_0000#) = 0 loop
               M := Shift_Left (M, 1);
               E := E - 1;
            end loop;
            M := M and 16#F_FFFF_FFFF_FFFF#;  -- drop the implicit leading 1
            declare
               F64_Exp : constant U64 := U64 (E + 24 + 52 + 1023 - 53 + 1);
            begin
               return Bits_To_F64 (SBit or Shift_Left (F64_Exp, 52) or M);
            end;
         end;
      elsif Exp = 16#1F# then
         if Mant = 0 then
            --  +/-inf
            return Bits_To_F64 (SBit or 16#7FF0_0000_0000_0000#);
         end if;
         --  NaN (canonical quiet)
         return Bits_To_F64 (16#7FF8_0000_0000_0000#);
      else
         --  normal half: f64_exp = half_exp - 15 + 1023; mantissa zero-extended.
         declare
            F64_Exp : constant U64 := U64 (Integer (Exp) - 15 + 1023);
            F64_Man : constant U64 := Shift_Left (U64 (Mant), 42);
         begin
            return Bits_To_F64 (SBit or Shift_Left (F64_Exp, 52) or F64_Man);
         end;
      end if;
   end Half_To_Double;

   --  Round-to-nearest-even f64 -> float16 bits. The encoder only EMITS the
   --  result when it round-trips bit-exactly through Half_To_Double (for
   --  finite values), so an imperfect subnormal rounding can never produce
   --  wrong canonical bytes; it just falls back to f32/f64.
   function Double_To_Half_Bits (X : Long_Float) return U16 is
      Bits : constant U64 := F64_To_Bits (X);
      Sign : constant U16 := U16 (Shift_Right (Bits, 63) and 1);
      SBit : constant U16 := Shift_Left (Sign, 15);
      Exp  : constant U16 := U16 (Shift_Right (Bits, 52) and 16#7FF#);
      Mant : constant U64 := Bits and 16#F_FFFF_FFFF_FFFF#;
   begin
      if Exp = 16#7FF# then
         if Mant = 0 then
            return SBit or 16#7C00#;
         else
            return 16#7E00#;
         end if;
      end if;
      declare
         E : constant Integer := Integer (Exp) - 1023;
      begin
         if E > 15 then
            return SBit or 16#7C00#;
         elsif E >= -14 then
            --  normal half: top 10 of 52 mantissa bits, round half-to-even.
            declare
               Drop     : constant Natural := 42;
               M        : U64 := Shift_Right (Mant, Drop);
               Rem_Bits : constant U64 := Mant and (Shift_Left (U64 (1), Drop) - 1);
               Halfway  : constant U64 := Shift_Left (U64 (1), Drop - 1);
               Round_Up : constant Boolean :=
                 Rem_Bits > Halfway
                 or else (Rem_Bits = Halfway and then (M and 1) = 1);
               Half_Exp : Integer := E + 15;
            begin
               if Round_Up then
                  M := M + 1;
               end if;
               if M = 1024 then
                  Half_Exp := Half_Exp + 1;
                  M := 0;
               end if;
               if Half_Exp >= 16#1F# then
                  return SBit or 16#7C00#;
               end if;
               return SBit
                 or Shift_Left (U16 (Half_Exp), 10)
                 or U16 (M and 16#3FF#);
            end;
         elsif E < -25 then
            return SBit;  -- underflow -> +/-0
         else
            --  subnormal half: value = m * 2^-24.
            declare
               Full     : constant U64 := Shift_Left (U64 (1), 52) or Mant;
               Shift_N  : constant Natural := 28 - E;
               M        : U64 := Shift_Right (Full, Shift_N);
               Rem_Bits : constant U64 := Full and (Shift_Left (U64 (1), Shift_N) - 1);
               Halfway  : constant U64 := Shift_Left (U64 (1), Shift_N - 1);
               Round_Up : constant Boolean :=
                 Rem_Bits > Halfway
                 or else (Rem_Bits = Halfway and then (M and 1) = 1);
            begin
               if Round_Up then
                  M := M + 1;
               end if;
               if M >= 1024 then
                  return SBit or Shift_Left (U16 (1), 10);
               end if;
               return SBit or U16 (M and 16#3FF#);
            end;
         end if;
      end;
   end Double_To_Half_Bits;

   --  Is X a NaN? (X /= X is true only for NaN.)
   function Is_NaN (X : Long_Float) return Boolean is (X /= X);

   ---------------------------------------------------------------------------
   --  float encode (shortest-preserving ladder; specials per Rule 4a)
   ---------------------------------------------------------------------------
   procedure Encode_Float (Buf : in out Byte_Vector; X : Long_Float) is
   begin
      if Is_NaN (X) then
         --  canonical NaN: f9 7e00
         Buf.Append (16#F9#);
         Add_BE (Buf, 16#7E00#, 2);
         return;
      end if;

      declare
         X_Bits : constant U64 := F64_To_Bits (X);
         H      : constant U16 := Double_To_Half_Bits (X);
      begin
         --  Try f16: emit only if it round-trips bit-exactly through the f64.
         --  +/-0.0 (sign-preserving, Rule 4a -0.0 -> f9 8000) and +/-inf are
         --  caught here, because Half_To_Double now expands them bit-exactly.
         if F64_To_Bits (Half_To_Double (H)) = X_Bits then
            Buf.Append (16#F9#);
            Add_BE (Buf, U64 (H), 2);
            return;
         end if;

         --  Try f32: emit only if it round-trips bit-exactly.
         declare
            S32 : constant U32 := F32_To_Bits (Float (X));
         begin
            if F64_To_Bits (Long_Float (Bits_To_F32 (S32))) = X_Bits then
               Buf.Append (16#FA#);
               Add_BE (Buf, U64 (S32), 4);
               return;
            end if;
         end;

         --  Fall back to f64.
         Buf.Append (16#FB#);
         Add_BE (Buf, X_Bits, 8);
      end;
   end Encode_Float;

   ---------------------------------------------------------------------------
   --  map-key canonical ordering: encode each key, sort by encoded-key bytes
   --  (length-first then bytewise-lex), reject duplicates (Rule 5).
   ---------------------------------------------------------------------------
   --  Compare two encoded-key byte arrays: length first, then bytewise.
   function Key_Less (A, B : Byte_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return A'Length < B'Length;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return A (A'First + I) < B (B'First + I);
         end if;
      end loop;
      return False;  -- equal
   end Key_Less;

   function Key_Equal (A, B : Byte_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Key_Equal;

   ---------------------------------------------------------------------------
   --  Encode_Into
   ---------------------------------------------------------------------------
   procedure Encode_Into (Buf : in out Byte_Vector; V : Ecf_Value) is
   begin
      case Kind (V) is
         when K_Uint =>
            Add_Head (Buf, 0, As_Uint (V));

         when K_Nint =>
            Add_Head (Buf, 1, As_Nint (V));

         when K_Bytes =>
            declare
               B : constant Byte_Array := As_Bytes (V);
            begin
               Add_Head (Buf, 2, U64 (B'Length));
               Buf.Append (B);
            end;

         when K_Text =>
            declare
               S   : constant String := As_Text (V);
               Tmp : Byte_Array (1 .. S'Length);
            begin
               for I in S'Range loop
                  Tmp (Tmp'First + (I - S'First)) := Octet (Character'Pos (S (I)));
               end loop;
               Add_Head (Buf, 3, U64 (S'Length));
               Buf.Append (Tmp);
            end;

         when K_Array =>
            Add_Head (Buf, 4, U64 (Array_Length (V)));
            for I in 1 .. Array_Length (V) loop
               Encode_Into (Buf, Array_Element (V, I));
            end loop;

         when K_Map =>
            declare
               N : constant Natural := Map_Length (V);
               type Key_Buf is access Byte_Array;
               type Slot is record
                  Key_Bytes : Key_Buf;
                  Idx       : Positive;
               end record;
               Slots : array (1 .. N) of Slot;
            begin
               --  Encode each key into its own buffer.
               for I in 1 .. N loop
                  declare
                     KV  : Byte_Vector;
                  begin
                     Encode_Into (KV, Map_Pair (V, I).Key);
                     Slots (I) := (Key_Bytes => new Byte_Array'(KV.To_Array),
                                   Idx       => I);
                     KV.Clear;
                  end;
               end loop;

               --  Insertion sort by encoded-key (N is tiny in practice).
               for I in 2 .. N loop
                  declare
                     Cur : constant Slot := Slots (I);
                     J   : Integer := I - 1;
                  begin
                     while J >= 1
                       and then Key_Less (Cur.Key_Bytes.all, Slots (J).Key_Bytes.all)
                     loop
                        Slots (J + 1) := Slots (J);
                        J := J - 1;
                     end loop;
                     Slots (J + 1) := Cur;
                  end;
               end loop;

               --  Reject duplicate keys (adjacent after sort).
               for I in 2 .. N loop
                  if Key_Equal (Slots (I - 1).Key_Bytes.all, Slots (I).Key_Bytes.all) then
                     raise Entity_Core.Errors.Duplicate_Key with "duplicate map key";
                  end if;
               end loop;

               Add_Head (Buf, 5, U64 (N));
               for I in 1 .. N loop
                  Buf.Append (Slots (I).Key_Bytes.all);
                  Encode_Into (Buf, Map_Pair (V, Slots (I).Idx).Value);
               end loop;

               --  Free key buffers.
               declare
                  procedure Free_KB is new
                    Ada.Unchecked_Deallocation (Byte_Array, Key_Buf);
               begin
                  for I in 1 .. N loop
                     Free_KB (Slots (I).Key_Bytes);
                  end loop;
               end;
            end;

         when K_Bool =>
            Buf.Append (if As_Bool (V) then 16#F5# else 16#F4#);

         when K_Null =>
            Buf.Append (16#F6#);

         when K_Float =>
            Encode_Float (Buf, As_Float (V));
      end case;
   end Encode_Into;

   ------------
   -- Encode --
   ------------
   function Encode (V : Ecf_Value) return Byte_Array is
      Buf : Byte_Vector;
   begin
      Encode_Into (Buf, V);
      return R : constant Byte_Array := Buf.To_Array do
         Buf.Clear;
      end return;
   end Encode;

   ------------
   -- Decode --
   ------------
   --  The decoder is a set of nested subprograms over the input slice S, with a
   --  mutable cursor Pos (next 1-based byte index). Nesting closes over S/Pos so
   --  no access-to-local is needed (which the accessibility rules would reject).
   function Decode (S : Byte_Array) return Ecf_Value is
      Pos : Positive := S'First;

      procedure Need (K : Natural) is
      begin
         if Pos + K - 1 > S'Last then
            raise Entity_Core.Errors.Truncated_Input with "truncated input";
         end if;
      end Need;

      function Read_Byte return Octet is
      begin
         Need (1);
         return R : constant Octet := S (Pos) do
            Pos := Pos + 1;
         end return;
      end Read_Byte;

      function Read_BE (K : Natural) return U64 is
         V : U64 := 0;
      begin
         Need (K);
         for I in 1 .. K loop
            V := Shift_Left (V, 8) or U64 (S (Pos));
            Pos := Pos + 1;
         end loop;
         return V;
      end Read_BE;

      function Read_Arg (AI : Octet) return U64 is
      begin
         if AI < 24 then
            return U64 (AI);
         end if;
         case AI is
            when 24 => return Read_BE (1);
            when 25 => return Read_BE (2);
            when 26 => return Read_BE (4);
            when 27 => return Read_BE (8);
            when others =>
               --  28..31 = indefinite / reserved: non-canonical.
               raise Entity_Core.Errors.Non_Canonical_Ecf
                 with "indefinite/reserved length argument";
         end case;
      end Read_Arg;

      function Read_Item return Ecf_Value is
         IB    : constant Octet := Read_Byte;
         Major : constant Octet := Shift_Right (IB, 5) and 7;
         AI    : constant Octet := IB and 16#1F#;
      begin
         case Major is
            when 0 =>
               return Make_Uint (Read_Arg (AI));

            when 1 =>
               return Make_Nint (Read_Arg (AI));

            when 2 =>
               declare
                  Len : constant Natural := Natural (Read_Arg (AI));
               begin
                  Need (Len);
                  declare
                     B : constant Byte_Array := S (Pos .. Pos + Len - 1);
                  begin
                     Pos := Pos + Len;
                     return Make_Bytes (B);
                  end;
               end;

            when 3 =>
               declare
                  Len : constant Natural := Natural (Read_Arg (AI));
               begin
                  Need (Len);
                  declare
                     Txt : String (1 .. Len);
                  begin
                     for I in 1 .. Len loop
                        Txt (I) := Character'Val (S (Pos));
                        Pos := Pos + 1;
                     end loop;
                     return Make_Text (Txt);
                  end;
               end;

            when 4 =>
               declare
                  Len   : constant Natural := Natural (Read_Arg (AI));
                  Items : Value_Vector (1 .. Len);
               begin
                  for I in 1 .. Len loop
                     Items (I) := Read_Item;
                  end loop;
                  return Make_Array (Items);
               end;

            when 5 =>
               declare
                  Len   : constant Natural := Natural (Read_Arg (AI));
                  Pairs : Pair_Vector (1 .. Len);
               begin
                  for I in 1 .. Len loop
                     declare
                        K   : constant Ecf_Value := Read_Item;
                        Val : constant Ecf_Value := Read_Item;
                     begin
                        Pairs (I) := (Key => K, Value => Val);
                     end;
                  end loop;
                  return Make_Map (Pairs);
               end;

            when 6 =>
               --  N2: any CBOR tag (major type 6), at any nesting depth, rejected.
               raise Entity_Core.Errors.Tag_Rejected with "CBOR tag rejected (N2)";

            when 7 =>
               case AI is
                  when 20 => return Make_Bool (False);
                  when 21 => return Make_Bool (True);
                  when 22 => return Make_Null;
                  when 25 => return Make_Float (Half_To_Double (U16 (Read_BE (2))));
                  when 26 => return Make_Float (Long_Float (Bits_To_F32 (U32 (Read_BE (4)))));
                  when 27 => return Make_Float (Bits_To_F64 (Read_BE (8)));
                  when others =>
                     raise Entity_Core.Errors.Non_Canonical_Ecf
                       with "unsupported simple value";
               end case;

            when others =>
               raise Entity_Core.Errors.Non_Canonical_Ecf with "bad major type";
         end case;
      end Read_Item;

   begin
      if S'Length = 0 then
         raise Entity_Core.Errors.Truncated_Input with "empty input";
      end if;
      return V : constant Ecf_Value := Read_Item do
         if Pos /= S'Last + 1 then
            raise Entity_Core.Errors.Trailing_Bytes with "trailing bytes";
         end if;
      end return;
   end Decode;

end Entity_Core.Codec.Cbor;
