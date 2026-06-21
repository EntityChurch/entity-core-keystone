--  Entity_Core.Protocol.Identity — a peer's identity (L1).
--
--  An Ed25519 seed and everything derived from it (§1.5, §3.5, §7.3):
--    Public_Key   = Ed25519 public key of seed                 (32 bytes)
--    Peer_Id      = §1.5 canonical-form (identity-multihash; A-ADA-001 — the
--                   digest IS the raw public key, key_type 16#01#, hash_type
--                   16#00#; NOT the stale §7.4 SHA-256 form)
--    Peer_Entity  = system/peer {public_key, key_type}         (§3.5; v7.65 —
--                   NO peer_id field in the hashable basis)
--    Identity_Hash = content_hash(Peer_Entity)                 (33 bytes)
--
--  Signing is over the full 33-byte content_hash (format byte + digest, §7.3),
--  so a signature is bound to the hash format. libsodium returns the raw 32-byte
--  pubkey directly (no point extraction — the Ada advantage over the JDK EdEC
--  wrinkle the Java peer flagged), so the §1.5 peer_id is in hand immediately.

with Entity_Core.Bytes;
with Entity_Core.Crypto;
with Entity_Core.Protocol.Entity;

package Entity_Core.Protocol.Identity is

   use Entity_Core.Bytes;

   type Peer_Identity is private;

   --  Construct an identity from a 32-byte Ed25519 seed.
   function Of_Seed (Seed : Entity_Core.Crypto.Seed_Bytes) return Peer_Identity;

   --  A seed of 32 repeated bytes (deterministic test identities, --seed N).
   function Seed_Of_Byte (B : Octet) return Entity_Core.Crypto.Seed_Bytes;

   function Public_Key (Id : Peer_Identity) return Entity_Core.Crypto.Public_Bytes;
   function Peer_Id (Id : Peer_Identity) return String;
   function Peer_Entity (Id : Peer_Identity) return Entity_Core.Protocol.Entity.Materialized_Entity;
   function Identity_Hash (Id : Peer_Identity) return Entity_Core.Protocol.Entity.Content_Hash;

   --  The system/peer entity for a raw public key (v7.65: no peer_id field).
   function Peer_Entity_Of_Public
     (Public : Entity_Core.Crypto.Public_Bytes)
      return Entity_Core.Protocol.Entity.Materialized_Entity;

   --  The §1.5 canonical identity-multihash peer_id for a raw Ed25519 pubkey.
   function Peer_Id_Of_Public (Public : Entity_Core.Crypto.Public_Bytes) return String;

   --  Sign a target entity's content_hash, producing a system/signature entity
   --  (§3.5): target = the signed entity's hash, signer = our identity hash.
   function Sign (Id : Peer_Identity;
                  Target : Entity_Core.Protocol.Entity.Materialized_Entity)
                  return Entity_Core.Protocol.Entity.Materialized_Entity;

   --  Verify a system/signature entity against the signer's system/peer entity.
   --  Reads public_key from the peer entity; the §5.2 signer-hash binding is the
   --  caller's responsibility.
   function Verify_Signature
     (Signature   : Entity_Core.Protocol.Entity.Materialized_Entity;
      Signer_Peer : Entity_Core.Protocol.Entity.Materialized_Entity) return Boolean;

private

   use Entity_Core.Protocol.Entity;

   --  A Base58 identity-multihash peer_id is ~47 chars; 64 is a safe upper
   --  bound. Stored as a fixed buffer + length so the record stays a plain
   --  value type (no access discipline on copy).
   Max_Peer_Id : constant := 64;

   type Peer_Identity is record
      Seed       : Entity_Core.Crypto.Seed_Bytes := (others => 0);
      Pub        : Entity_Core.Crypto.Public_Bytes := (others => 0);
      Id_Buf     : String (1 .. Max_Peer_Id) := (others => ' ');
      Id_Len     : Natural := 0;
      Peer       : Materialized_Entity;
      Id_Hash    : Content_Hash := (others => 0);
   end record;

end Entity_Core.Protocol.Identity;
