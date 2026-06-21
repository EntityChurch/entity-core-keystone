--  Entity_Core.Crypto — libsodium binding (Ed25519 + SHA-256) via Interfaces.C.
--
--  Profile [codec]: crypto is sourced from libsodium over Ada's strong C
--  interop (Interfaces.C / pragma Import, Convention => C). The §9.1 core floor
--  needs only Ed25519 + SHA-256, both provided by libsodium:
--    crypto_sign_seed_keypair  (seed -> keypair; raw 32-byte pubkey directly)
--    crypto_sign_detached      (deterministic RFC-8032 Ed25519 signature)
--    crypto_sign_verify_detached
--    crypto_hash_sha256
--
--  Ada advantage over the Java peer: crypto_sign_seed_keypair returns the raw
--  32-byte public key directly — NO point-extraction step (contrast the JDK
--  EdEC point-encoding wrinkle). The raw pubkey the §1.5 identity-multihash
--  peer_id needs is in hand immediately.
--
--  Ed448 / SHA-384 (v7.67 agility higher bar) are NOT in libsodium and are
--  DEFERRED (A-ADA-002); the core floor is unaffected.

with Entity_Core.Bytes;

package Entity_Core.Crypto is

   use Entity_Core.Bytes;

   Seed_Length       : constant := 32;
   Public_Length     : constant := 32;
   Secret_Length     : constant := 64;   -- libsodium sk = seed(32) || pubkey(32)
   Signature_Length  : constant := 64;
   Sha256_Length     : constant := 32;

   subtype Seed_Bytes      is Byte_Array (1 .. Seed_Length);
   subtype Public_Bytes    is Byte_Array (1 .. Public_Length);
   subtype Signature_Bytes is Byte_Array (1 .. Signature_Length);
   subtype Sha256_Digest   is Byte_Array (1 .. Sha256_Length);

   --  SHA-256 of an arbitrary message.
   function Sha256 (Message : Byte_Array) return Sha256_Digest
     with Post => Sha256'Result'Length = Sha256_Length;

   --  Derive the raw 32-byte Ed25519 public key for a 32-byte seed.
   function Public_Of_Seed (Seed : Seed_Bytes) return Public_Bytes
     with Post => Public_Of_Seed'Result'Length = Public_Length;

   --  Deterministic Ed25519 signature (64 bytes) over Message for the seed.
   function Sign (Seed : Seed_Bytes; Message : Byte_Array) return Signature_Bytes
     with Post => Sign'Result'Length = Signature_Length;

   --  Verify a 64-byte detached signature against Message under a 32-byte
   --  public key. Returns True iff valid.
   function Verify
     (Public_Key : Public_Bytes;
      Signature  : Signature_Bytes;
      Message    : Byte_Array) return Boolean;

end Entity_Core.Crypto;
