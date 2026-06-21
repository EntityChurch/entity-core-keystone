{-# LANGUAGE OverloadedStrings #-}

-- | Core type floor (V7 §9.5) — the render-from-model registry (A-HS-009 resolved
-- at S4).
--
-- Design (cross-peer ruling): peers render @system/type/*@ from an in-code model
-- through the native S2 codec, NOT by ingesting fixture bytes — the entity's
-- content_hash is computed by our own encoder over the model, then byte-diffed
-- against the canonical type-registry vectors (the S8 drift target). A core peer
-- publishes exactly the §9.5 floor — the 53 core + operational + type-system
-- bootstrap types; extension vocabularies (compute\/*, content\/*, …) are NOT
-- published by a core peer (refined G4 \/ F17). The oracle's @type_system@
-- category matches the 53 floor as a hard FAIL gate and WARNs (matched-if-present)
-- on the non-floor types it also probes.
--
-- Omit-empty: an absent\/false\/zero field drops the key, so the rendered ECF map
-- is byte-identical to the Go reference encoder. The codec sorts map keys
-- canonically (length-then-lex), so field declaration order is irrelevant to the
-- bytes — only the present key\/value set matters.
--
-- Faithful port of the cross-blessed C#\/TS\/OCaml\/Zig registry (byte-identical
-- to the Go oracle vectors).
module EntityCore.TypeDefs
  ( coreTypes
  , coreTypeCount
  , publish
    -- * Render-from-model internals (exported for the S4 byte-diff test)
  , FSpec (..)
  , TypeDef (..)
  , fref
  , opt
  , sized
  , farray
  , fmapOf
  , funion
  , typeDefData
  , allTypes
  ) where

import Data.Text (Text)

import EntityCore.Codec.Value (Value (..))
import EntityCore.Model (Entity, makeEntity)
import EntityCore.Store (Store, bind)

-- ── FSpec — a field spec inside a TypeDef (system/type/field-spec shape) ──────
--
-- Exactly one structural carrier is set: a type_ref, an array_of, a map_of, or a
-- union_of. Rendered omit-empty into the field-spec ECF map.

data FSpec = FSpec
  { fsTypeRef  :: Maybe Text
  , fsOptional :: Bool
  , fsArrayOf  :: Maybe FSpec
  , fsMapOf    :: Maybe FSpec
  , fsUnionOf  :: Maybe [FSpec]
  , fsKeyType  :: Maybe Text
  , fsByteSize :: Maybe Word
  }

emptyFSpec :: FSpec
emptyFSpec = FSpec Nothing False Nothing Nothing Nothing Nothing Nothing

-- | @type_ref@ to a named type.
fref :: Text -> FSpec
fref t = emptyFSpec { fsTypeRef = Just t }

-- | Mark a field-spec optional.
opt :: FSpec -> FSpec
opt s = s { fsOptional = True }

-- | Add a @byte_size@ carrier.
sized :: Word -> FSpec -> FSpec
sized n s = s { fsByteSize = Just n }

-- | @array_of@ the given element spec.
farray :: FSpec -> FSpec
farray elemSpec = emptyFSpec { fsArrayOf = Just elemSpec }

-- | @map_of@ the given value spec, with an optional @key_type@.
fmapOf :: Maybe Text -> FSpec -> FSpec
fmapOf keyT valSpec = emptyFSpec { fsMapOf = Just valSpec, fsKeyType = keyT }

-- | @union_of@ the given variant specs.
funion :: [FSpec] -> FSpec
funion vs = emptyFSpec { fsUnionOf = Just vs }

-- | Render a field-spec to its ECF data map (omit-empty).
fspecData :: FSpec -> Value
fspecData s =
  VMap $ concat
    [ kv "type_ref" VText (fsTypeRef s)
    , [ (VText "optional", VBool True) | fsOptional s ]
    , kv "array_of" fspecData (fsArrayOf s)
    , kv "map_of" fspecData (fsMapOf s)
    , case fsUnionOf s of
        Just vs -> [ (VText "union_of", VArray (map fspecData vs)) ]
        Nothing -> []
    , kv "key_type" VText (fsKeyType s)
    , kv "byte_size" (VUInt . fromIntegral) (fsByteSize s)
    ]
  where
    kv :: Text -> (a -> Value) -> Maybe a -> [(Value, Value)]
    kv k f = maybe [] (\x -> [(VText k, f x)])

-- ── TypeDef — a core type definition (system/type entity data) ────────────────

data TypeDef = TypeDef
  { tdName    :: Text
  , tdExtends :: Maybe Text
  , tdFields  :: [(Text, FSpec)]
  , tdLayout  :: [Text]
  }

def :: Text -> TypeDef
def n = TypeDef n Nothing [] []

-- These builders are used infix (@td \`withFields\` fields@) so the @TypeDef@ is
-- the LEFT operand — hence @td@ comes first.
withExtends :: TypeDef -> Text -> TypeDef
withExtends td e = td { tdExtends = Just e }

withFields :: TypeDef -> [(Text, FSpec)] -> TypeDef
withFields td fs = td { tdFields = fs }

withLayout :: TypeDef -> [Text] -> TypeDef
withLayout td ls = td { tdLayout = ls }

-- | Render the @system/type@ data map (omit-empty). Field declaration order is
-- preserved within the @fields@ sub-map; the codec re-sorts keys canonically.
typeDefData :: TypeDef -> Value
typeDefData td =
  VMap $ concat
    [ [ (VText "name", VText (tdName td)) ]
    , maybe [] (\e -> [(VText "extends", VText e)]) (tdExtends td)
    , [ (VText "fields", VMap [ (VText k, fspecData s) | (k, s) <- tdFields td ])
      | not (null (tdFields td)) ]
    , [ (VText "layout", VArray (map VText (tdLayout td)))
      | not (null (tdLayout td)) ]
    ]

typeDefEntity :: TypeDef -> Entity
typeDefEntity td = makeEntity "system/type" (typeDefData td)

-- ── reused nested specs ───────────────────────────────────────────────────────

spString, spAny, spHash, spCoreEntity, spTreePath, spGrantEntry, spMultiGranter :: FSpec
spString       = fref "primitive/string"
spAny          = fref "primitive/any"
spHash         = fref "system/hash"
spCoreEntity   = fref "core/entity"
spTreePath     = fref "system/tree/path"
spGrantEntry   = fref "system/capability/grant-entry"
spMultiGranter = fref "system/capability/multi-granter"

spFieldSpec, spOpSpec, spListingEntry, spType, spTypeName :: FSpec
spFieldSpec    = fref "system/type/field-spec"
spOpSpec       = fref "system/handler/operation-spec"
spListingEntry = fref "system/tree/listing-entry"
spType         = fref "system/type"
spTypeName     = fref "system/type/name"

-- ── the 53 core type definitions ──────────────────────────────────────────────

allTypes :: [TypeDef]
allTypes =
  [ -- primitives (8)
    def "primitive/any"
  , def "primitive/bool"
  , def "primitive/bytes"
  , def "primitive/float"
  , def "primitive/int"
  , def "primitive/null"
  , def "primitive/string"
  , def "primitive/uint"

    -- structural roots + envelopes (5)
  , def "entity" `withFields`
      [ ("type", fref "primitive/string")
      , ("data", fref "primitive/any")
      ]
  , def "core/entity" `withFields`
      [ ("type", fref "primitive/string")
      , ("data", fref "primitive/any")
      , ("content_hash", fref "system/hash")
      ]
  , def "core/envelope" `withFields`
      [ ("root", fref "core/entity")
      , ("included", opt (fmapOf (Just "system/hash") spCoreEntity))
      ]
  , def "system/envelope" `withExtends` "core/envelope"
  , def "system/protocol/envelope" `withExtends` "core/envelope"

    -- identity / hash / signature (4)
  , (def "system/hash" `withExtends` "primitive/bytes") `withFields`
      [ ("format_code", sized 1 (fref "primitive/uint"))
      , ("digest", fref "primitive/bytes")
      ] `withLayout` ["format_code", "digest"]
  , def "system/peer" `withFields`
      [ ("key_type", fref "primitive/string")
      , ("peer_id", fref "system/peer-id")
      , ("public_key", fref "primitive/bytes")
      ]
  , def "system/peer-id" `withExtends` "primitive/string"
  , def "system/signature" `withFields`
      [ ("algorithm", fref "primitive/string")
      , ("signature", fref "primitive/bytes")
      , ("signer", fref "system/hash")
      , ("target", fref "system/hash")
      ]

    -- protocol surface (6)
  , def "system/protocol/connect/authenticate" `withFields`
      [ ("key_type", fref "primitive/string")
      , ("nonce", fref "primitive/bytes")
      , ("peer_id", fref "system/peer-id")
      , ("public_key", fref "primitive/bytes")
      ]
  , def "system/protocol/connect/hello" `withFields`
      [ ("protocols", farray spString)
      , ("nonce", fref "primitive/bytes")
      , ("peer_id", fref "system/peer-id")
      , ("timestamp", fref "primitive/uint")
      , ("compression", opt (farray spString))
      , ("encryption", opt (farray spString))
      , ("hash_formats", opt (farray spString))
      , ("key_types", opt (farray spString))
      ]
  , def "system/protocol/error" `withFields`
      [ ("code", fref "primitive/string")
      , ("message", opt (fref "primitive/string"))
      , ("rejected_marker", opt (fref "system/hash"))
      ]
  , def "system/protocol/execute" `withFields`
      [ ("operation", fref "primitive/string")
      , ("params", fref "core/entity")
      , ("request_id", fref "primitive/string")
      , ("uri", fref "system/tree/path")
      , ("author", opt (fref "system/hash"))
      , ("bounds", opt (fref "system/bounds"))
      , ("capability", opt (fref "system/hash"))
      , ("deliver_to", opt (fref "system/delivery-spec"))
      , ("deliver_token", opt (fref "system/hash"))
      , ("durability_request", opt (fref "system/durability-request"))
      , ("resource", opt (fref "system/protocol/resource-target"))
      ]
  , def "system/protocol/execute/response" `withFields`
      [ ("request_id", fref "primitive/string")
      , ("result", fref "core/entity")
      , ("status", fref "primitive/uint")
      , ("durability", opt (fref "system/durability-result"))
      ]
  , def "system/protocol/resource-target" `withFields`
      [ ("targets", farray spTreePath)
      , ("exclude", opt (farray spTreePath))
      ]

    -- capability (12)
  , def "system/capability/grant" `withFields`
      [ ("token", fref "system/hash") ]
  , def "system/capability/grant-entry" `withFields`
      [ ("handlers", fref "system/capability/path-scope")
      , ("operations", fref "system/capability/id-scope")
      , ("resources", fref "system/capability/path-scope")
      , ("allowances", opt (fmapOf Nothing spAny))
      , ("constraints", opt (fmapOf Nothing spAny))
      , ("peers", opt (fref "system/capability/id-scope"))
      ]
  , def "system/capability/id-scope" `withFields`
      [ ("include", farray spString)
      , ("exclude", opt (farray spString))
      ]
  , def "system/capability/path-scope" `withFields`
      [ ("include", farray spTreePath)
      , ("exclude", opt (farray spTreePath))
      ]
  , def "system/capability/request" `withFields`
      [ ("grants", farray spGrantEntry)
      , ("ttl_ms", opt (fref "primitive/uint"))
      ]
  , def "system/capability/revocation" `withFields`
      [ ("token", fref "system/hash")
      , ("revoked_at", fref "primitive/uint")
      , ("reason", opt (fref "primitive/string"))
      ]
  , def "system/capability/revoke-request" `withFields`
      [ ("token", fref "system/hash")
      , ("reason", opt (fref "primitive/string"))
      ]
  , def "system/capability/delegate-request" `withFields`
      [ ("grants", farray spGrantEntry)
      , ("parent", fref "system/hash")
      , ("ttl_ms", opt (fref "primitive/uint"))
      ]
  , def "system/capability/delegation-caveats" `withFields`
      [ ("max_delegation_depth", opt (fref "primitive/uint"))
      , ("max_delegation_ttl", opt (fref "primitive/uint"))
      , ("no_delegation", opt (fref "primitive/bool"))
      ]
  , def "system/capability/policy-entry" `withFields`
      [ ("grants", farray spGrantEntry)
      , ("peer_pattern", fref "primitive/string")
      , ("notes", opt (fref "primitive/string"))
      , ("ttl_ms", opt (fref "primitive/uint"))
      ]
  , def "system/capability/token" `withFields`
      [ ("created_at", fref "primitive/uint")
      , ("grantee", fref "system/hash")
      , ("granter", funion [spHash, spMultiGranter])
      , ("grants", farray spGrantEntry)
      , ("delegation_caveats", opt (fref "system/capability/delegation-caveats"))
      , ("expires_at", opt (fref "primitive/uint"))
      , ("not_before", opt (fref "primitive/uint"))
      , ("parent", opt (fref "system/hash"))
      , ("resource_limits", opt (fref "system/resource-limits"))
      ]
  , def "system/capability/multi-granter" `withFields`
      [ ("signers", farray spHash)
      , ("threshold", fref "primitive/uint")
      ]

    -- handler machinery (6)
  , def "system/handler" `withFields`
      [ ("interface", fref "system/tree/path")
      , ("expression_path", opt (fref "system/tree/path"))
      , ("internal_scope", opt (farray spGrantEntry))
      , ("max_scope", opt (farray spGrantEntry))
      ]
  , def "system/handler/interface" `withFields`
      [ ("name", fref "primitive/string")
      , ("operations", fmapOf Nothing spOpSpec)
      , ("pattern", fref "system/tree/path")
      ]
  , (def "system/handler/manifest" `withExtends` "system/handler/interface") `withFields`
      [ ("name", fref "primitive/string")
      , ("operations", fmapOf Nothing spOpSpec)
      , ("pattern", fref "system/tree/path")
      , ("expression_path", opt (fref "system/tree/path"))
      , ("internal_scope", opt (farray spGrantEntry))
      , ("max_scope", opt (farray spGrantEntry))
      ]
  , def "system/handler/operation-spec" `withFields`
      [ ("input_type", opt (fref "system/type/name"))
      , ("output_type", opt (fref "system/type/name"))
      ]
  , def "system/handler/register-request" `withFields`
      [ ("manifest", fref "system/handler/manifest")
      , ("requested_scope", opt (farray spGrantEntry))
      , ("types", opt (fmapOf Nothing spType))
      ]
  , def "system/handler/register-result" `withFields`
      [ ("grant", fref "system/capability/token")
      , ("pattern", fref "system/tree/path")
      ]

    -- tree (5)
  , def "system/tree/get-request" `withFields`
      [ ("limit", opt (fref "primitive/uint"))
      , ("mode", opt (fref "primitive/string"))
      , ("offset", opt (fref "primitive/uint"))
      , ("tree_id", opt (fref "primitive/string"))
      ]
  , def "system/tree/put-request" `withFields`
      [ ("entity", opt (fref "core/entity"))
      , ("expected_hash", opt (fref "system/hash"))
      , ("tree_id", opt (fref "primitive/string"))
      ]
  , def "system/tree/listing" `withFields`
      [ ("count", fref "primitive/uint")
      , ("entries", fmapOf Nothing spListingEntry)
      , ("offset", fref "primitive/uint")
      , ("path", fref "system/tree/path")
      , ("next_page", opt (fref "system/hash"))
      ]
  , def "system/tree/listing-entry" `withFields`
      [ ("has_children", fref "primitive/bool")
      , ("hash", opt (fref "system/hash"))
      ]
  , def "system/tree/path" `withExtends` "primitive/string"

    -- type-system bootstrap (3)
  , def "system/type" `withFields`
      [ ("name", fref "system/type/name")
      , ("extends", opt (fref "system/type/name"))
      , ("fields", opt (fmapOf Nothing spFieldSpec))
      , ("layout", opt (farray spString))
      , ("type_args", opt (fmapOf Nothing spTypeName))
      , ("type_params", opt (farray spString))
      ]
  , def "system/type/field-spec" `withFields`
      [ ("type_ref", opt (fref "system/type/name"))
      , ("optional", opt (fref "primitive/bool"))
      , ("array_of", opt (fref "system/type/field-spec"))
      , ("map_of", opt (fref "system/type/field-spec"))
      , ("union_of", opt (farray spFieldSpec))
      , ("key_type", opt (fref "system/type/name"))
      , ("byte_size", opt (fref "primitive/uint"))
      , ("type_param", opt (fref "primitive/string"))
      , ("type_args", opt (fmapOf Nothing spTypeName))
      , ("default", opt (fref "primitive/any"))
      , ("constraints", opt (farray spCoreEntity))
      ]
  , def "system/type/name" `withExtends` "primitive/string"

    -- operational (4)
  , def "system/bounds" `withFields`
      [ ("budget", opt (fref "primitive/uint"))
      , ("cascade_depth", opt (fref "primitive/uint"))
      , ("chain_id", opt (fref "primitive/string"))
      , ("parent_chain_id", opt (fref "primitive/string"))
      , ("ttl", opt (fref "primitive/uint"))
      , ("visited", opt (farray spTreePath))
      ]
  , def "system/resource-limits" `withFields`
      [ ("max_budget", opt (fref "primitive/uint"))
      , ("max_ttl", opt (fref "primitive/uint"))
      , ("max_visited_length", opt (fref "primitive/uint"))
      ]
  , def "system/delivery-spec" `withFields`
      [ ("operation", fref "primitive/string")
      , ("uri", fref "system/tree/path")
      ]
  , def "system/deletion-marker"
  ]

-- | The number of core types published (53).
coreTypeCount :: Int
coreTypeCount = length allTypes

-- | The rendered @system/type@ entities for all core types, keyed by name.
coreTypes :: [(Text, Entity)]
coreTypes = [ (tdName td, typeDefEntity td) | td <- allTypes ]

-- | Publish every core type at @\/{peer}\/system\/type\/{name}@ (content-addressed
-- in the store too, via 'bind').
publish :: Store -> Text -> IO ()
publish store localPeer =
  mapM_ (\(name, e) -> bind store ("/" <> localPeer <> "/system/type/" <> name) e) coreTypes
