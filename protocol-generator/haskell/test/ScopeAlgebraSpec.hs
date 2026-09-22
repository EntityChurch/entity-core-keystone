{-# LANGUAGE OverloadedStrings #-}

-- | The §5 scope algebra and the §4.11 pre-admission table — the rules landed for
-- spec 0.8.2.24 / 0.8.2.25, in the direction the conformance oracle cannot reach.
--
-- Every group here exists because the pinned check set is SILENT about it: the
-- §6.3 path check and the §3.3 effective-targets ladder moved this peer from
-- violating three landed MUSTs to conformant without moving a single severity, so
-- the only thing standing between the code and a silent regression is this file.
--
-- == The shape of each group
--
-- A predicate group carries at least one ACCEPT assertion and one DENY assertion
-- PER DIMENSION. The accept case is the one that validates the FIXTURE — a
-- predicate built over a mis-shaped grant denies everything, and a deny-only group
-- is then indistinguishable from one asserting @False == False@. The per-dimension
-- denies are what separate "the predicate checks the dimension I care about" from
-- "the predicate denies".
module ScopeAlgebraSpec (spec) where

import Data.Text (Text)
import Test.Hspec

import EntityCore.Capability
  ( checkPathPermission
  , effectiveTargets
  , grantSubset
  , matchesPattern
  , parseGrant
  )
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.Model (Entity (..), Envelope (..), envelopeOfCbor, makeEntity)
import EntityCore.Wire (FramingRefusal (..), preAdmissionRefusal)

-- A stand-in local peer_id. Only its SHAPE matters here (it must not look like a
-- path segment that a pattern could match by accident); nothing derives a key.
local :: Text
local = "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"

scope :: [Text] -> [Text] -> Value
scope incl excl =
  VMap
    ( [(VText "include", VArray (map VText incl))]
        ++ [(VText "exclude", VArray (map VText excl)) | not (null excl)]
    )

-- | A one-grant capability token over the four dimensions, as a real entity — the
-- same shape 'checkPathPermission' reads off the wire.
tokenOf :: [(Text, Value)] -> Entity
tokenOf dims = makeEntity "system/capability/token" (VMap [(VText "grants", VArray [VMap (map (\(k, v) -> (VText k, v)) dims)])])

-- | The grant the §6.3 groups below narrow from: @system/tree@ may @get@ under
-- @system/type/*@, and nothing else.
narrowToken :: Entity
narrowToken =
  tokenOf
    [ ("handlers", scope ["system/tree"] [])
    , ("resources", scope ["system/type/*"] [])
    , ("operations", scope ["get"] [])
    ]

-- | An EXECUTE carrying a @resource@ map verbatim.
execWithResource :: Value -> Entity
execWithResource r =
  makeEntity
    "system/protocol/execute"
    (VMap [(VText "operation", VText "get"), (VText "uri", VText "system/tree"), (VText "resource", r)])

-- | A well-formed envelope CBOR value whose single `included` entry is filed under
-- @key@. Passing the entry's own content_hash is the control; passing anything else
-- is the §5.2a forgery.
envelopeWithIncludedKey :: Value -> Value
envelopeWithIncludedKey key =
  let root = makeEntity "primitive/any" (VMap [])
      e = makeEntity "primitive/any" (VMap [(VText "x", VUInt 1)])
      wire x = VMap [(VText "type", VText (entType x)), (VText "data", entData x), (VText "content_hash", VBytes (entHash x))]
   in VMap [(VText "root", wire root), (VText "included", VMap [(key, wire e)])]

-- | The content_hash the entry in 'envelopeWithIncludedKey' is owed.
correctIncludedKey :: Value
correctIncludedKey = VBytes (entHash (makeEntity "primitive/any" (VMap [(VText "x", VUInt 1)])))

spec :: Spec
spec = do
  -- ── §5.2 effective targets (0.8.2.20/.21, N11) ─────────────────────────────
  describe "effectiveTargets — the caller's own exclude, applied first (§5.2, 0.8.2.20)" $ do
    it "ACCEPT: a target no exclude covers survives, in the caller's OWN spelling" $
      -- Not canonicalized: 0.8.2.21 is explicit that effective_targets yields RAW
      -- survivors, and the value flows on to a store lookup that canonicalizes for
      -- itself. A canonicalized survivor here would still resolve, so only an
      -- equality assertion on the spelling can catch it.
      effectiveTargets local (execWithResource (VMap [(VText "targets", VArray [VText "system/type/qA"])]))
        `shouldBe` (["system/type/qA"], True)

    it "DENY: a target the caller's own exclude covers is removed before anything looks at it" $
      effectiveTargets
        local
        ( execWithResource
            ( VMap
                [ (VText "targets", VArray [VText "system/type/qA", VText "system/type/qB"])
                , (VText "exclude", VArray [VText "system/type/qB"])
                ]
            )
        )
        `shouldBe` (["system/type/qA"], True)

    it "THE TWO EMPTIES ARE DISTINCT: absent resource is (mempty, False)" $
      -- N11's non-lossy projection [MUST]. A function returning only a list cannot
      -- satisfy it: collapsing `[qA] exclude [qA]` to `[]` deletes the
      -- discriminator before any handler can read it, and `get`'s refusal arm
      -- becomes dead code only a WIRE drive could detect.
      effectiveTargets local (makeEntity "system/protocol/execute" (VMap [(VText "operation", VText "get")]))
        `shouldBe` ([], False)

    it "THE TWO EMPTIES ARE DISTINCT: self-excluded resource is ([], True)" $
      effectiveTargets
        local
        ( execWithResource
            ( VMap
                [ (VText "targets", VArray [VText "system/type/qA"])
                , (VText "exclude", VArray [VText "system/type/qA"])
                ]
            )
        )
        `shouldBe` ([], True)

    it "a PRESENT-but-non-array `targets` reads as PRESENT-and-empty, never as absent" $
      -- Reading it as absent answers it with the ABSENT case, which for `get` is
      -- the whole root listing — WIDER than the request, which is the answer §3.3
      -- forbids. This is the one row the two vanguard peers disagreed on.
      effectiveTargets local (execWithResource (VMap [(VText "targets", VText "not-an-array")]))
        `shouldBe` ([], True)

    it "the caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4)" $
      -- `../nope` canonicalizes to the sentinel, matchesPattern then answers False,
      -- and the target simply SURVIVES. §5.4 rules the caller arm separately from
      -- the grant arm, where the same value is fail-CLOSED. Inherited from the
      -- primitives, and asserted here because the asymmetry is the whole point.
      effectiveTargets
        local
        ( execWithResource
            ( VMap
                [ (VText "targets", VArray [VText "system/type/qA"])
                , (VText "exclude", VArray [VText "../nope"])
                ]
            )
        )
        `shouldBe` (["system/type/qA"], True)

  -- ── §6.3 check_path_permission ──────────────────────────────────────────────
  describe "checkPathPermission — §6.3's handler-level path check" $ do
    it "ACCEPT: a path inside every dimension of the grant is authorized" $
      -- THE FIXTURE-VALIDATING CASE. Without it the three denies below would all
      -- pass against a token whose grants parsed EMPTY, which denies everything.
      checkPathPermission local "get" "system/type/qA" narrowToken "system/tree"
        `shouldBe` True

    it "DENY (resources): a path outside the grant's resource scope" $
      checkPathPermission local "get" "system/other/qA" narrowToken "system/tree"
        `shouldBe` False

    it "DENY (operations): the right path under an operation the grant does not name" $
      checkPathPermission local "put" "system/type/qA" narrowToken "system/tree"
        `shouldBe` False

    it "DENY (handlers): the right path named by a handler the grant does not name" $
      checkPathPermission local "get" "system/type/qA" narrowToken "system/other"
        `shouldBe` False

    it "an absolute local path is accepted identically to its peer-relative spelling" $
      -- The handler hands this function an already-canonicalized path. canonicalize
      -- is idempotent on absolute input, so both spellings must land on the same
      -- verdict; a second canonicalization pass that mangled the absolute form
      -- would deny every real call.
      checkPathPermission local "get" ("/" <> local <> "/system/type/qA") narrowToken "system/tree"
        `shouldBe` True

    it "DENY: an empty `resources.include` is a legal grant shape that denies every path" $
      -- §5.2's note: a handler that touches no tree paths. `any` over an empty
      -- include list is False, which is what that note says it should be.
      checkPathPermission
        local
        "get"
        "system/type/qA"
        (tokenOf [("handlers", scope ["*"] []), ("resources", scope [] []), ("operations", scope ["*"] [])])
        "system/tree"
        `shouldBe` False

    it "DENY: a malformed path canonicalizes to the sentinel and matches no grant" $
      checkPathPermission
        local
        "get"
        "../escape"
        (tokenOf [("handlers", scope ["*"] []), ("resources", scope ["*"] []), ("operations", scope ["*"] [])])
        "system/tree"
        `shouldBe` False

    it "DENY: a grant exclude covering the subject denies it" $
      -- There is no caller-exclude set at this call site — the subject is a single
      -- concrete path and the caller's exclusions were applied in DERIVING it — so
      -- every grant exclude covering the subject denies.
      checkPathPermission
        local
        "get"
        "system/type/qB"
        (tokenOf
           [ ("handlers", scope ["system/tree"] [])
           , ("resources", scope ["system/type/*"] ["system/type/qB"])
           , ("operations", scope ["get"] [])
           ])
        "system/tree"
        `shouldBe` False

  -- ── §5.4 sentinel, SCOPED to path-scope (0.8.2.24, N2/N3) ──────────────────
  describe "the §5.4 unmatchable-exclude sentinel reaches path-scope ONLY (0.8.2.24)" $ do
    it "PATH-SCOPE: an unmatchable `resources` exclude denies the dimension (0.8.2.21)" $
      checkPathPermission
        local
        "get"
        "system/type/qA"
        (tokenOf
           [ ("handlers", scope ["system/tree"] [])
           , ("resources", scope ["system/type/*"] ["../nope"])
           , ("operations", scope ["get"] [])
           ])
        "system/tree"
        `shouldBe` False

    it "ID-SCOPE: an `operations` exclude that path-canonicalizes to the sentinel does NOT deny" $
      -- THE 0.8.2.24 REGRESSION THIS GUARDS. `*/apply` is an ordinary namespaced
      -- operation name and a literal matching nothing under the id-scope grammar.
      -- Asked outside the type dispatch, it was run through the §5.4 path
      -- transforms purely to classify it, canonicalized to the sentinel, and
      -- DENIED EVERY OPERATION — over-denial, invisible on any well-formed grant.
      -- §5.4: "It does NOT reach `operations` or `peers` [MUST]".
      checkPathPermission
        local
        "get"
        "system/type/qA"
        (tokenOf
           [ ("handlers", scope ["system/tree"] [])
           , ("resources", scope ["system/type/*"] [])
           , ("operations", scope ["get"] ["*/apply"])
           ])
        "system/tree"
        `shouldBe` True

    it "ID-SCOPE: the exclude still EXCLUDES what it literally names" $
      -- The companion to the row above: scoping the sentinel off the id dimension
      -- must not make id excludes inert. Without this, "does not deny" and "is
      -- never read" are the same observation.
      checkPathPermission
        local
        "get"
        "system/type/qA"
        (tokenOf
           [ ("handlers", scope ["system/tree"] [])
           , ("resources", scope ["system/type/*"] [])
           , ("operations", scope ["*"] ["get"])
           ])
        "system/tree"
        `shouldBe` False

  -- ── §3.6 / F50: scope_subset is typed by scope kind ────────────────────────
  describe "grantSubset routes each dimension through its OWN matcher (F50, 0.8.2.16)" $ do
    let sub incl = parseGrant (VMap [(VText "operations", scope incl []), (VText "handlers", scope ["*"] []), (VText "resources", scope ["*"] [])])
        parentAll = parseGrant (VMap [(VText "operations", scope ["*"] []), (VText "handlers", scope ["*"] []), (VText "resources", scope ["*"] [])])

    it "ID-SCOPE: a child `operations` include of `/tree/get` IS covered by a parent `*`" $
      -- The formalization differential: 2 of 64 include pairs diverged, FAIL-CLOSED,
      -- and a 16-pair control alphabet reported ZERO — which is why every hand-tried
      -- example missed it. Under the path matcher `/tree/get` canonicalizes to
      -- ["tree","get"] and the parent `*` to [local,"*"], which do not match; under
      -- the id matcher a bare `*` covers every identifier, which is what §3.6 says.
      grantSubset local local local (sub ["/tree/get"]) parentAll `shouldBe` True

    it "ID-SCOPE: a child `operations` include of `*/apply` IS covered by a parent `*`" $
      -- The second half of the formalization's divergence, and the one that also
      -- exercises RULE B from the subset side: `*/apply` PATH-canonicalizes to the
      -- §5.4 sentinel, which matches nothing in either operand, so under the path
      -- matcher a bare parent `*` could not cover it.
      grantSubset local local local (sub ["*/apply"]) parentAll `shouldBe` True

    it "ID-SCOPE still ATTENUATES: a child operation outside a narrow parent is refused" $
      -- The accept rows above would also pass against a `scopeSubset` that answered
      -- True unconditionally. This is the row that says it is still a subset check.
      grantSubset
        local
        local
        local
        (sub ["put"])
        (parseGrant (VMap [(VText "operations", scope ["get"] []), (VText "handlers", scope ["*"] []), (VText "resources", scope ["*"] [])]))
        `shouldBe` False

    it "PATH-SCOPE is unchanged: a child `resources` include outside the parent is refused" $
      grantSubset
        local
        local
        local
        (parseGrant (VMap [(VText "operations", scope ["*"] []), (VText "handlers", scope ["*"] []), (VText "resources", scope ["system/other/*"] [])]))
        (parseGrant (VMap [(VText "operations", scope ["*"] []), (VText "handlers", scope ["*"] []), (VText "resources", scope ["system/type/*"] [])]))
        `shouldBe` False

  -- ── §5.2a / §4.11: the code belongs to the CAUSE ───────────────────────────
  describe "pre-admission refusal codes follow the CAUSE (§4.11/§5.2a, 0.8.2.24/.25)" $ do
    it "a mis-keyed `included` entry answers 400 hash_mismatch at the wire boundary" $
      -- §5.2a: "A peer that refuses at the decode boundary MUST answer 400
      -- hash_mismatch [MUST] ... 400 non_canonical_ecf is NOT conformant here".
      -- The entry's encoding is CANONICAL; what is false is the claim the key makes.
      -- Asserted END TO END — decode through to the code the caller sees — because
      -- the constructor alone would not catch a classifier that then routed it to
      -- the wrong code.
      either
        (preAdmissionRefusal . Right)
        (const (0 :: Int, "decoded" :: Text))
        (envelopeOfCbor (envelopeWithIncludedKey (VBytes "not-this-entitys-content-hash")))
        `shouldBe` (400, "hash_mismatch")

    it "a correctly-keyed `included` entry still decodes (THE FIXTURE CONTROL)" $
      -- Without this the row above would pass against an envelope builder that
      -- produced garbage, which fails to decode for reasons unrelated to the key.
      either
        (const ("refused" :: String))
        (\(Envelope _ incl) -> "decoded " ++ show (length incl))
        (envelopeOfCbor (envelopeWithIncludedKey correctIncludedKey))
        `shouldBe` "decoded 1"

    it "a tampered `content_hash` on an entity is the same CAUSE and the same code (§1.8)" $
      -- §1.8 entity fidelity, one level in from the mis-keyed entry: the encoding
      -- is canonical, no tag, and the false thing is the hash claim. This answered
      -- non_canonical_ecf too.
      either
        (preAdmissionRefusal . Right)
        (const (0 :: Int, "decoded" :: Text))
        ( envelopeOfCbor
            ( VMap
                [ (VText "root", VMap [(VText "type", VText "primitive/any"), (VText "data", VMap []), (VText "content_hash", VBytes "tampered-not-the-real-digest")])
                ]
            )
        )
        `shouldBe` (400, "hash_mismatch")

    it "§4.11's table: each CAUSE selects its own status and code" $
      -- "The frame obligation belongs to the class; the CODE belongs to the cause
      -- [MUST]" — a single code for the whole class answers an honest caller under
      -- the wrong reason and sends them to the wrong layer.
      map
        preAdmissionRefusal
        [ Left FrameTooLarge
        , Left FrameTruncated
        , Right (HashMismatch "")
        , Right (TagRejected "")
        , Right (Truncated "")
        , Right (Unsupported "")
        ]
        `shouldBe` [ (413, "payload_too_large")
                   , (400, "invalid_request")
                   , (400, "hash_mismatch")
                   , (400, "non_canonical_ecf") -- ENTITY-CBOR-ENCODING §5.4 keeps this arm
                   , (400, "invalid_request")
                   , (400, "invalid_request")
                   ]

  -- ── §5.4 matcher sanity (the primitive the two groups above rest on) ───────
  describe "matchesPattern refuses the sentinel in EITHER operand (0.8.2.20)" $ do
    it "sentinel as the VALUE never matches a bare `*`" $
      matchesPattern "/never-match" "*" `shouldBe` False
    it "sentinel as the PATTERN never matches — NOT EVEN ITSELF" $
      -- THE PATTERN-SIDE CASE THAT IS ACTUALLY LOAD-BEARING, and the first draft of
      -- this row was not it. Asserting the sentinel pattern against a REAL path
      -- passes with the guard REMOVED — the sentinel falls to the literal-equality
      -- arm and misses anyway — so that row was an inert control, green in both
      -- directions. It was the PLANT that said so, not a reading. Sentinel against
      -- sentinel is the input the equality arm answers True for, which is exactly
      -- the "in EITHER operand" half of §5.4: a grant exclude of `../x` and a
      -- target that both canonicalize to the sentinel must NOT be a match.
      matchesPattern "/never-match" "/never-match" `shouldBe` False
    it "a bare `*` still matches a real path (the control)" $
      matchesPattern ("/" <> local <> "/system/type/qA") "*" `shouldBe` True
