-- | Seed-policy selection (the keystone §6.9a bootstrap convention).
--
-- V7 §6.9a pins the invariant (a peer establishes operable owner authority at
-- init + derives authenticate-time grants from a declared identity → capability
-- seed policy). The cross-peer file format + CLI convention are keystone's
-- (@protocol-generator/shared/seed-policy/@). This module is the Haskell builder
-- shape: a 'SeedPolicy' value the host/builder supplies to 'EntityCore.Peer.createPeer'.
--
-- The S3 floor mirrors the cohort (C#/TS/OCaml): the in-code builders
-- ('standardPolicy' = the conformant default = @default@ → §4.4 discovery floor;
-- 'SeedPolicyDebugOpen' = the degenerate @default → *@, the retired
-- @--debug-open-grants@). @with_seed_policy_from_file@ (JSON parse of the shared
-- schema) is the next increment (S4/S5), not the floor — recorded as A-HS-011.
module EntityCore.SeedPolicy
  ( SeedPolicy (..)
  , defaultPolicy
  , standardPolicy
  ) where

-- | The seed policy a peer boots with. @SeedPolicyStandard@ is the conformant
-- default (@default@ → the §4.4 discovery floor); @SeedPolicyDebugOpen@ selects
-- the degenerate @default → *@ (deprecated v7.74, removed v7.75) — routed through
-- the real §6.9a mechanism, not a hardcoded fork.
data SeedPolicy
  = SeedPolicyStandard
  | SeedPolicyDebugOpen
  deriving (Eq, Show)

-- | The conformant default.
defaultPolicy :: SeedPolicy
defaultPolicy = SeedPolicyStandard

-- | Alias for the conformant default (matches the cross-peer @SeedPolicy.standard()@).
standardPolicy :: SeedPolicy
standardPolicy = SeedPolicyStandard
