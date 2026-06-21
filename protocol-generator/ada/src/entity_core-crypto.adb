with Interfaces.C;
with System;
with Entity_Core.Errors;

package body Entity_Core.Crypto is

   use type Interfaces.C.int;

   ---------------------------------------------------------------------------
   --  libsodium C bindings (pragma Import, Convention => C). Buffers are
   --  passed by System.Address (the C ABI for `unsigned char *`); lengths are
   --  unsigned long long. Passing addresses (rather than element 'Access)
   --  keeps the binding simple and avoids aliased-element accessibility rules.
   ---------------------------------------------------------------------------

   function sodium_init return Interfaces.C.int
     with Import, Convention => C, External_Name => "sodium_init";

   function crypto_hash_sha256
     (Out_Hash : System.Address;
      In_Msg   : System.Address;
      In_Len   : Interfaces.C.unsigned_long_long) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_hash_sha256";

   function crypto_sign_seed_keypair
     (PK   : System.Address;
      SK   : System.Address;
      Seed : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_seed_keypair";

   function crypto_sign_detached
     (Sig     : System.Address;
      Sig_Len : System.Address;   -- may be NULL (System.Null_Address)
      Msg     : System.Address;
      Msg_Len : Interfaces.C.unsigned_long_long;
      SK      : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_detached";

   function crypto_sign_verify_detached
     (Sig     : System.Address;
      Msg     : System.Address;
      Msg_Len : Interfaces.C.unsigned_long_long;
      PK      : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_verify_detached";

   --  Initialise libsodium once at elaboration (see the package-end block).
   Init_RC : constant Interfaces.C.int := sodium_init;

   --  Address of the first element of a (possibly empty) Byte_Array. For an
   --  empty array libsodium is called with length 0 and does not dereference,
   --  so any non-null address is fine; we use the array object's own address.
   function Addr (B : Byte_Array) return System.Address is (B'Address);

   ------------
   -- Sha256 --
   ------------
   function Sha256 (Message : Byte_Array) return Sha256_Digest is
      Digest : Sha256_Digest := (others => 0);
      RC     : Interfaces.C.int;
   begin
      RC := crypto_hash_sha256
              (Digest'Address, Addr (Message),
               Interfaces.C.unsigned_long_long (Message'Length));
      if RC /= 0 then
         raise Entity_Core.Errors.Crypto_Error with "crypto_hash_sha256 failed";
      end if;
      return Digest;
   end Sha256;

   --------------------
   -- Public_Of_Seed --
   --------------------
   function Public_Of_Seed (Seed : Seed_Bytes) return Public_Bytes is
      PK : Public_Bytes := (others => 0);
      SK : Byte_Array (1 .. Secret_Length) := (others => 0);
   begin
      if crypto_sign_seed_keypair (PK'Address, SK'Address, Seed'Address) /= 0 then
         raise Entity_Core.Errors.Bad_Seed with "crypto_sign_seed_keypair failed";
      end if;
      return PK;
   end Public_Of_Seed;

   ----------
   -- Sign --
   ----------
   function Sign (Seed : Seed_Bytes; Message : Byte_Array) return Signature_Bytes is
      PK  : Public_Bytes := (others => 0);
      SK  : Byte_Array (1 .. Secret_Length) := (others => 0);
      Sig : Signature_Bytes := (others => 0);
   begin
      if crypto_sign_seed_keypair (PK'Address, SK'Address, Seed'Address) /= 0 then
         raise Entity_Core.Errors.Bad_Seed with "seed keypair failed";
      end if;
      if crypto_sign_detached
           (Sig'Address, System.Null_Address,
            Addr (Message),
            Interfaces.C.unsigned_long_long (Message'Length),
            SK'Address) /= 0
      then
         raise Entity_Core.Errors.Crypto_Error with "crypto_sign_detached failed";
      end if;
      return Sig;
   end Sign;

   ------------
   -- Verify --
   ------------
   function Verify
     (Public_Key : Public_Bytes;
      Signature  : Signature_Bytes;
      Message    : Byte_Array) return Boolean
   is
   begin
      return crypto_sign_verify_detached
               (Signature'Address, Addr (Message),
                Interfaces.C.unsigned_long_long (Message'Length),
                Public_Key'Address) = 0;
   end Verify;

begin
   if Init_RC < 0 then
      raise Entity_Core.Errors.Crypto_Error with "sodium_init failed";
   end if;
end Entity_Core.Crypto;
