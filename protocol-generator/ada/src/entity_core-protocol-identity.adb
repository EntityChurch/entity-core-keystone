with Entity_Core.Codec.Peer_Id;
with Entity_Core.Codec.Value;
with Entity_Core.Protocol.Cbor_Util;

package body Entity_Core.Protocol.Identity is

   use Entity_Core.Codec.Value;
   use Entity_Core.Protocol.Cbor_Util;

   -----------------------------
   -- Peer_Entity_Of_Public --
   -----------------------------
   function Peer_Entity_Of_Public
     (Public : Entity_Core.Crypto.Public_Bytes) return Materialized_Entity is
   begin
      return Make ("system/peer",
        Map_Of (((Key => K ("public_key"), Value => Make_Bytes (Public)),
                 (Key => K ("key_type"),   Value => Make_Text ("ed25519")))));
   end Peer_Entity_Of_Public;

   ------------------------
   -- Peer_Id_Of_Public --
   ------------------------
   function Peer_Id_Of_Public (Public : Entity_Core.Crypto.Public_Bytes) return String is
   begin
      return Entity_Core.Codec.Peer_Id.From_Ed25519_Public (Public);
   end Peer_Id_Of_Public;

   ------------------
   -- Seed_Of_Byte --
   ------------------
   function Seed_Of_Byte (B : Octet) return Entity_Core.Crypto.Seed_Bytes is
   begin
      return (others => B);
   end Seed_Of_Byte;

   -------------
   -- Of_Seed --
   -------------
   function Of_Seed (Seed : Entity_Core.Crypto.Seed_Bytes) return Peer_Identity is
      Pub  : constant Entity_Core.Crypto.Public_Bytes :=
        Entity_Core.Crypto.Public_Of_Seed (Seed);
      Peer : constant Materialized_Entity := Peer_Entity_Of_Public (Pub);
      Pid  : constant String := Peer_Id_Of_Public (Pub);
   begin
      return Id : Peer_Identity do
         Id.Seed := Seed;
         Id.Pub  := Pub;
         Id.Id_Len := Pid'Length;
         Id.Id_Buf (1 .. Pid'Length) := Pid;
         Id.Peer := Peer;
         Id.Id_Hash := Hash (Peer);
      end return;
   end Of_Seed;

   ----------------
   -- Public_Key --
   ----------------
   function Public_Key (Id : Peer_Identity) return Entity_Core.Crypto.Public_Bytes is
     (Id.Pub);

   -------------
   -- Peer_Id --
   -------------
   function Peer_Id (Id : Peer_Identity) return String is
     (Id.Id_Buf (1 .. Id.Id_Len));

   -----------------
   -- Peer_Entity --
   -----------------
   function Peer_Entity (Id : Peer_Identity) return Materialized_Entity is (Id.Peer);

   -------------------
   -- Identity_Hash --
   -------------------
   function Identity_Hash (Id : Peer_Identity) return Content_Hash is (Id.Id_Hash);

   ----------
   -- Sign --
   ----------
   function Sign (Id : Peer_Identity; Target : Materialized_Entity)
                  return Materialized_Entity is
      Sig : constant Entity_Core.Crypto.Signature_Bytes :=
        Entity_Core.Crypto.Sign (Id.Seed, Hash (Target));
   begin
      return Make ("system/signature",
        Map_Of (((Key => K ("target"),    Value => Make_Bytes (Hash (Target))),
                 (Key => K ("signer"),    Value => Make_Bytes (Id.Id_Hash)),
                 (Key => K ("algorithm"), Value => Make_Text ("ed25519")),
                 (Key => K ("signature"), Value => Make_Bytes (Sig)))));
   end Sign;

   ----------------------
   -- Verify_Signature --
   ----------------------
   function Verify_Signature
     (Signature   : Materialized_Entity;
      Signer_Peer : Materialized_Entity) return Boolean is
      Target_Found, Sig_Found, Pub_Found : Boolean;
      Target : constant Byte_Array := Byte_Field (Signature, "target", Target_Found);
      Sig    : constant Byte_Array := Byte_Field (Signature, "signature", Sig_Found);
      Pub    : constant Byte_Array := Byte_Field (Signer_Peer, "public_key", Pub_Found);
   begin
      if not (Target_Found and then Sig_Found and then Pub_Found) then
         return False;
      end if;
      if Sig'Length /= Entity_Core.Crypto.Signature_Length
        or else Pub'Length /= Entity_Core.Crypto.Public_Length
      then
         return False;
      end if;
      return Entity_Core.Crypto.Verify
        (Public_Key => Entity_Core.Crypto.Public_Bytes (Pub),
         Signature  => Entity_Core.Crypto.Signature_Bytes (Sig),
         Message    => Target);
   end Verify_Signature;

end Entity_Core.Protocol.Identity;
