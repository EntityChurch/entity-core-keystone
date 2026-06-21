--  run_tests — hand-rolled unit/self-test runner (no AUnit; profile [testing]).
--
--  Covers the codec primitives and the conformance invariants N1-N4 with
--  explicit assertions, plus the uncovered-range probes a green corpus does NOT
--  exercise (full uint64, -2**64, float ladder boundaries, crypto KATs). Each
--  check prints PASS/FAIL; a non-zero exit status if any fails.

with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;
with Interfaces;           use Interfaces;

with Entity_Core.Bytes;           use Entity_Core.Bytes;
with Entity_Core.Codec.Value;     use Entity_Core.Codec.Value;
with Entity_Core.Codec.Cbor;
with Entity_Core.Codec.Varint;
with Entity_Core.Codec.Base58;
with Entity_Core.Codec.Peer_Id;
with Entity_Core.Codec.Hash;
with Entity_Core.Crypto;
with Entity_Core.Errors;

procedure Run_Tests is

   package Cbor renames Entity_Core.Codec.Cbor;

   Passed : Natural := 0;
   Failed : Natural := 0;
   Threw  : Boolean;  -- shared flag for exception-expecting checks

   procedure Check (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Passed := Passed + 1;
      else
         Failed := Failed + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   function Hex_Eq (V : Ecf_Value; Want_Hex : String) return Boolean is
      Got  : constant Byte_Array := Cbor.Encode (V);
      Want : constant Byte_Array := From_Hex (Want_Hex);
   begin
      if Got'Length /= Want'Length then
         return False;
      end if;
      for I in 0 .. Got'Length - 1 loop
         if Got (Got'First + I) /= Want (Want'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Hex_Eq;

   function Bytes_Eq (A : Byte_Array; Hex : String) return Boolean is
      Want : constant Byte_Array := From_Hex (Hex);
   begin
      if A'Length /= Want'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= Want (Want'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Bytes_Eq;

begin
   Put_Line ("-- int minimal-form boundaries --");
   Check ("uint 0",      Hex_Eq (Make_Uint (0), "00"));
   Check ("uint 23",     Hex_Eq (Make_Uint (23), "17"));
   Check ("uint 24",     Hex_Eq (Make_Uint (24), "1818"));
   Check ("uint 1000",   Hex_Eq (Make_Uint (1000), "1903e8"));
   Check ("uint i64max", Hex_Eq (Make_Uint (9223372036854775807), "1b7fffffffffffffff"));
   Check ("nint -1",     Hex_Eq (Make_Nint (0), "20"));
   Check ("nint -25",    Hex_Eq (Make_Nint (24), "3818"));

   Put_Line ("-- uncovered uint64 / -2**64 range (no unsigned trap) --");
   --  The corpus int set tops out at 2**63-1. Pin the full u64 range.
   Check ("uint 2**64-1", Hex_Eq (Make_Uint (16#FFFF_FFFF_FFFF_FFFF#), "1bffffffffffffffff"));
   Check ("uint 2**63",   Hex_Eq (Make_Uint (16#8000_0000_0000_0000#), "1b8000000000000000"));
   Check ("nint -2**64",  Hex_Eq (Make_Nint (16#FFFF_FFFF_FFFF_FFFF#), "3bffffffffffffffff"));

   Put_Line ("-- float ladder f16/f32/f64 + specials (Rule 4 / 4a) --");
   Check ("1.0 -> f16",   Hex_Eq (Make_Float (1.0), "f93c00"));
   Check ("1.5 -> f16",   Hex_Eq (Make_Float (1.5), "f93e00"));
   Check ("-0.0 -> f16",  Hex_Eq (Make_Float (-0.0), "f98000"));
   Check ("65504 -> f16", Hex_Eq (Make_Float (65504.0), "f97bff"));
   Check ("65503 -> f32", Hex_Eq (Make_Float (65503.0), "fa477fdf00"));
   Check ("1.1 -> f64",   Hex_Eq (Make_Float (1.1), "fb3ff199999999999a"));

   Put_Line ("-- N3: empty map = 0xA0; empty array = 0x80 --");
   declare
      Empty_Pairs : Pair_Vector (1 .. 0);
      Empty_Items : Value_Vector (1 .. 0);
   begin
      Check ("empty map A0",   Hex_Eq (Make_Map (Empty_Pairs), "a0"));
      Check ("empty array 80", Hex_Eq (Make_Array (Empty_Items), "80"));
   end;

   Put_Line ("-- map-key canonical ordering (length-then-lex) --");
   declare
      --  {"aa":2, "z":1} -> z before aa (length first): a2 617a 01 626161 02
      P : constant Pair_Vector :=
        ((Key => Make_Text ("aa"), Value => Make_Uint (2)),
         (Key => Make_Text ("z"),  Value => Make_Uint (1)));
   begin
      Check ("len-first sort", Hex_Eq (Make_Map (P), "a2617a0162616102"));
   end;

   Put_Line ("-- Rule 5: duplicate keys rejected --");
   Threw := False;
   begin
      declare
         Dup : constant Pair_Vector :=
           ((Key => Make_Text ("a"), Value => Make_Uint (1)),
            (Key => Make_Text ("a"), Value => Make_Uint (2)));
         Discard : constant Byte_Array := Cbor.Encode (Make_Map (Dup));
      begin
         pragma Unreferenced (Discard);
         null;
      end;
   exception
      when Entity_Core.Errors.Duplicate_Key =>
         Threw := True;
   end;
   Check ("dup-key reject", Threw);

   Put_Line ("-- N2: recursive major-type-6 tag rejection --");
   Threw := False;
   begin
      --  bare tag 0 over uint 0: c0 00
      declare
         Discard : constant Ecf_Value := Cbor.Decode (From_Hex ("c000"));
      begin
         pragma Unreferenced (Discard);
         null;
      end;
   exception
      when Entity_Core.Errors.Tag_Rejected =>
         Threw := True;
   end;
   Check ("bare tag reject", Threw);

   Threw := False;
   begin
      --  {"data": tag0("x")}: a1 64 64617461 c0 61 78
      declare
         Discard : constant Ecf_Value :=
           Cbor.Decode (From_Hex ("a16464617461c06178"));
      begin
         pragma Unreferenced (Discard);
         null;
      end;
   exception
      when Entity_Core.Errors.Tag_Rejected =>
         Threw := True;
   end;
   Check ("nested tag reject", Threw);

   Put_Line ("-- N1: LEB128 varint multi-byte (128 -> 80 01) --");
   declare
      V : Byte_Vector;
   begin
      Entity_Core.Codec.Varint.Encode (V, 128);
      Check ("varint 128", Bytes_Eq (V.To_Array, "8001"));
      V.Clear;
      Entity_Core.Codec.Varint.Encode (V, 0);
      Check ("varint 0", Bytes_Eq (V.To_Array, "00"));
      V.Clear;
      Entity_Core.Codec.Varint.Encode (V, 16#FFFF_FFFF_FFFF_FFFF#);
      declare
         VV    : Unsigned_64;
         C     : Positive;
      begin
         Entity_Core.Codec.Varint.Decode (V.To_Array, 1, VV, C);
         Check ("varint u64max roundtrip", VV = 16#FFFF_FFFF_FFFF_FFFF#);
      end;
      V.Clear;
   end;

   Put_Line ("-- base58 round-trip (leading-zero preservation) --");
   declare
      B : constant Byte_Array := (1 => 0, 2 => 0, 3 => 1, 4 => 2);
      S : constant String := Entity_Core.Codec.Base58.Encode (B);
      D : constant Byte_Array := Entity_Core.Codec.Base58.Decode (S);
   begin
      Check ("base58 leading-zero rt", Bytes_Eq (D, "00000102"));
   end;

   Put_Line ("-- peer_id: §1.5 canonical Ed25519 form (kt=1, ht=0, raw pubkey) --");
   declare
      --  A-ADA-001: derive from raw pubkey -> key_type=1, hash_type=0.
      PK : constant Byte_Array (1 .. 32) := (others => 16#11#);
      Pid : constant String := Entity_Core.Codec.Peer_Id.From_Ed25519_Public (PK);
      P : constant Entity_Core.Codec.Peer_Id.Components :=
        Entity_Core.Codec.Peer_Id.Parse (Pid);
   begin
      Check ("peer_id kt=1", P.Key_Type = 1);
      Check ("peer_id ht=0", P.Hash_Type = 0);
      Check ("peer_id digest=raw-pubkey",
             P.Digest_Length = 32
             and then (for all I in 1 .. 32 => P.Digest (I) = 16#11#));
   end;

   Put_Line ("-- peer_id: multi-byte key_type (128) round-trip (N1) --");
   declare
      Dig : Byte_Array (1 .. 32);
   begin
      for I in Dig'Range loop
         Dig (I) := Octet (I - 1);
      end loop;
      declare
         S : constant String := Entity_Core.Codec.Peer_Id.Format (128, 1, Dig);
         P : constant Entity_Core.Codec.Peer_Id.Components :=
           Entity_Core.Codec.Peer_Id.Parse (S);
      begin
         Check ("peer_id multibyte kt", P.Key_Type = 128 and then P.Hash_Type = 1);
      end;
   end;

   Put_Line ("-- crypto: Ed25519 RFC-8032 TEST-1 (all-zero seed) pubkey --");
   declare
      Seed : constant Entity_Core.Crypto.Seed_Bytes := (others => 0);
      PK   : constant Byte_Array := Entity_Core.Crypto.Public_Of_Seed (Seed);
   begin
      --  RFC 8032 §7.1 TEST 1 public key.
      Check ("ed25519 pubkey KAT",
             Bytes_Eq (PK,
               "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"));
   end;

   Put_Line ("-- crypto: SHA-256 KAT (empty + 'abc') --");
   declare
      Empty_Msg : constant Byte_Array (1 .. 0) := Empty_Bytes;
      Abc       : constant Byte_Array := (Octet (Character'Pos ('a')),
                                          Octet (Character'Pos ('b')),
                                          Octet (Character'Pos ('c')));
   begin
      Check ("sha256 empty",
             Bytes_Eq (Entity_Core.Crypto.Sha256 (Empty_Msg),
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
      Check ("sha256 abc",
             Bytes_Eq (Entity_Core.Crypto.Sha256 (Abc),
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
   end;

   Put_Line ("-- crypto: deterministic Ed25519 sign + verify + tamper-reject --");
   declare
      Seed : constant Entity_Core.Crypto.Seed_Bytes := (others => 0);
      Msg  : constant Byte_Array := (Octet (Character'Pos ('h')),
                                     Octet (Character'Pos ('i')));
      Bad  : constant Byte_Array := (Octet (Character'Pos ('y')),
                                     Octet (Character'Pos ('o')));
      Sig  : constant Byte_Array := Entity_Core.Crypto.Sign (Seed, Msg);
      Sig2 : constant Byte_Array := Entity_Core.Crypto.Sign (Seed, Msg);
      PK   : constant Byte_Array := Entity_Core.Crypto.Public_Of_Seed (Seed);
   begin
      Check ("sign deterministic", Sig = Sig2);
      Check ("verify ok", Entity_Core.Crypto.Verify (PK, Sig, Msg));
      Check ("verify tamper-reject", not Entity_Core.Crypto.Verify (PK, Sig, Bad));
   end;

   Put_Line ("-- content_hash empty-entity floor (N3 boundary) --");
   declare
      Empty_Pairs : Pair_Vector (1 .. 0);
      CH : constant Byte_Array :=
        Entity_Core.Codec.Hash.Content_Hash (0, "system/empty", Make_Map (Empty_Pairs));
   begin
      Check ("content_hash.1 floor",
             Bytes_Eq (CH,
               "005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b"));
   end;

   New_Line;
   Put_Line ("== self-tests:" & Natural'Image (Passed) & " passed,"
             & Natural'Image (Failed) & " failed ==");

   if Failed > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Ada.Command_Line.Set_Exit_Status (0);
   end if;
end Run_Tests;
