{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

-- | Canonical ECF (Entity Canonical Form) CBOR encode / decode.
--
-- This is the hand-rolled canonical layer (A-005, 8th confirmation): a faithful
-- ECF codec OWNS the canonical guarantees regardless of any CBOR library —
--
--   * map keys sorted by ENCODED length then lexicographically over the encoded
--     key bytes (ENTITY-CBOR-ENCODING §2.2 Rule 2);
--   * minimal integer head form (Rule 1) — and full 'Word64' / -2^64 range,
--     NOT clamped to 'Int64';
--   * shortest-form float ladder (Rule 4 / Rule 4a, in "EntityCore.Codec.Float");
--   * definite lengths only (Rule 3); indefinite-length heads rejected on decode;
--   * recursive major-type-6 (tag) rejection on decode (§6.3 Option B) — N2;
--   * empty map = single byte @0xA0@ (N3), empty array = @0x80@.
--
-- == Laziness discipline (A-HS-002 — THE Haskell-specific watch-item)
--
-- The encoder accumulates output in a strict 'BS.ByteString' (NOT lazy
-- 'BL.ByteString' — lazy chunks would defer + leak). 'encode' builds a
-- 'BSB.Builder' and immediately forces it to a strict 'BS.ByteString' with
-- @BL.toStrict@; the result is bang-bound so no builder thunk escapes. The
-- map-key sort materialises @(encodedKeyBytes, encodedValueBytes)@ pairs
-- strictly before sorting — the sort key is the FORCED encoded bytes, never a
-- lazy thunk, so ordering is deterministic and no thunk chain survives the
-- fold. The decoder threads its cursor as a strict 'BS.ByteString' slice and
-- bang-binds each step; @decodeFully@ forces the decoded 'Value' (it is built
-- from strict-field constructors) so no thunk retains the input buffer.
module EntityCore.Codec.CBOR
  ( encode
  , decode
  , decodeAllowTags
  , encodeKey
  ) where

import Control.Monad (when)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BL
import Data.List (sortBy)
import Data.Ord (comparing)
import qualified Data.Text.Encoding as TE
import Data.Word (Word16, Word32, Word64, Word8)

import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Float (decodeFloat16, decodeFloat32, decodeFloat64, encodeFloatShortest)
import EntityCore.Codec.Value (Value (..))

-- ─────────────────────────────────────────────────────────────────────────────
-- Encode (total, pure; canonical by construction)
-- ─────────────────────────────────────────────────────────────────────────────

-- | Canonically ECF-encode a 'Value' to a strict 'BS.ByteString'. Total — the
-- model can only represent canonical-encodable shapes, so encode never fails.
encode :: Value -> BS.ByteString
encode v =
  let !out = BL.toStrict (BSB.toLazyByteString (buildValue v))
   in out

buildValue :: Value -> BSB.Builder
buildValue = \case
  VUInt n -> buildHead 0 (fromIntegral n)
  VNInt arg -> buildHead 1 (fromIntegral arg)
  VBytes bs -> buildHead 2 (fromIntegral (BS.length bs)) <> BSB.byteString bs
  VText t ->
    let !enc = TE.encodeUtf8 t -- UTF-8 BYTE length, not Text code-point length
     in buildHead 3 (fromIntegral (BS.length enc)) <> BSB.byteString enc
  VArray xs ->
    buildHead 4 (fromIntegral (length xs)) <> mconcat (map buildValue xs)
  VMap kvs -> buildMap kvs
  VFloat d -> BSB.byteString (encodeFloatShortest d)
  VBool b -> BSB.word8 (if b then 0xf5 else 0xf4)
  VNull -> BSB.word8 0xf6

-- | Encode a single value to its standalone canonical bytes (used as the map-key
-- sort key + by content_hash callers).
encodeKey :: Value -> BS.ByteString
encodeKey = encode

-- | Build a CBOR head: major type in the top 3 bits, then the minimal-length
-- argument (Rule 1). Carries the full 64-bit argument range.
buildHead :: Word8 -> Word64 -> BSB.Builder
buildHead major arg
  | arg < 24 = BSB.word8 (mt .|. fromIntegral arg)
  | arg <= 0xff = BSB.word8 (mt .|. 24) <> BSB.word8 (fromIntegral arg)
  | arg <= 0xffff = BSB.word8 (mt .|. 25) <> BSB.word16BE (fromIntegral arg)
  | arg <= 0xffffffff = BSB.word8 (mt .|. 26) <> BSB.word32BE (fromIntegral arg)
  | otherwise = BSB.word8 (mt .|. 27) <> BSB.word64BE arg
  where
    !mt = major `shiftL` 5

-- | Encode a map: sort entries by (encoded-key-length, encoded-key-bytes), then
-- emit head + each key/value. The sort key is the FORCED encoded key bytes
-- (A-HS-002): the @(kBytes, vBytes)@ pairs are bang-materialised before the
-- sort so ordering never depends on an unforced thunk.
buildMap :: [(Value, Value)] -> BSB.Builder
buildMap kvs =
  let !encoded = map (\(k, v) -> let !kb = encode k; !vb = encode v in (kb, vb)) kvs
      !sorted = sortBy (comparing (\(kb, _) -> (BS.length kb, kb))) encoded
   in buildHead 5 (fromIntegral (length sorted))
        <> mconcat (map (\(kb, vb) -> BSB.byteString kb <> BSB.byteString vb) sorted)

-- ─────────────────────────────────────────────────────────────────────────────
-- Decode (total Either; canonical-form enforcing; recursive tag rejection N2)
-- ─────────────────────────────────────────────────────────────────────────────

-- | Decode a single top-level 'Value' from strict bytes, rejecting any
-- major-type-6 tag at any nesting depth (N2), indefinite-length heads, simple
-- values other than false/true/null, non-minimal int heads, non-shortest
-- floats, out-of-order or duplicate map keys, and trailing bytes.
decode :: BS.ByteString -> Either CodecError Value
decode = decodeWith True

-- | Like 'decode' but does NOT reject tags — used only by the file-marker /
-- relaxed surfaces (not on the wire). Kept narrow; the protocol path uses
-- 'decode'.
decodeAllowTags :: BS.ByteString -> Either CodecError Value
decodeAllowTags = decodeWith False

decodeWith :: Bool -> BS.ByteString -> Either CodecError Value
decodeWith rejectTags bs = do
  (!v, !rest) <- decodeItem rejectTags bs
  if BS.null rest
    then Right v
    else Left (TrailingBytes ("decode: " ++ show (BS.length rest) ++ " trailing byte(s)"))

-- | Decode one item, returning it and the remaining bytes. Cursor is a strict
-- slice; each step is bang-bound.
decodeItem :: Bool -> BS.ByteString -> Either CodecError (Value, BS.ByteString)
decodeItem rejectTags bs = case BS.uncons bs of
  Nothing -> Left (Truncated "decode: empty input")
  Just (!ib, !rest) ->
    let !major = ib `shiftR` 5
        !ai = ib .&. 0x1f
     in case major of
          0 -> do (!arg, !r) <- readArg ai rest; Right (VUInt arg, r)
          1 -> do (!arg, !r) <- readArg ai rest; Right (VNInt arg, r)
          2 -> do
            (!len, !r) <- readArg ai rest
            (!payload, !r') <- takeN (fromIntegral len) r
            Right (VBytes payload, r')
          3 -> do
            (!len, !r) <- readArg ai rest
            (!payload, !r') <- takeN (fromIntegral len) r
            case TE.decodeUtf8' payload of
              Left _ -> Left (NonCanonicalEcf "text: invalid UTF-8")
              Right !t -> Right (VText t, r')
          4 -> do
            (!len, !r) <- readArg ai rest
            decodeArray rejectTags (fromIntegral len) r
          5 -> do
            (!len, !r) <- readArg ai rest
            decodeMap rejectTags (fromIntegral len) r
          6 ->
            if rejectTags
              then Left (TagRejected ("tag major-type-6 (ai=" ++ show ai ++ ") on the wire"))
              else Left (TagRejected "tag rejected (allow-tags path is not wired for protocol use)")
          7 -> decodeSimpleOrFloat ai rest
          _ -> Left (NonCanonicalEcf "decode: impossible major type")

-- | Read a head argument per the additional-info value, enforcing MINIMAL
-- encoding (Rule 1): a 1/2/4/8-byte argument that would fit in a shorter form
-- is non-canonical. Rejects indefinite (31) and reserved (28..30).
readArg :: Word8 -> BS.ByteString -> Either CodecError (Word64, BS.ByteString)
readArg ai bs
  | ai < 24 = Right (fromIntegral ai, bs)
  | ai == 24 = do
      (!w, !r) <- takeN 1 bs
      let !v = fromIntegral (BS.head w)
      if v < 24 then Left (NonCanonicalEcf "int: non-minimal 1-byte arg") else Right (v, r)
  | ai == 25 = do
      (!w, !r) <- takeN 2 bs
      let !v = beWord w
      if v <= 0xff then Left (NonCanonicalEcf "int: non-minimal 2-byte arg") else Right (v, r)
  | ai == 26 = do
      (!w, !r) <- takeN 4 bs
      let !v = beWord w
      if v <= 0xffff then Left (NonCanonicalEcf "int: non-minimal 4-byte arg") else Right (v, r)
  | ai == 27 = do
      (!w, !r) <- takeN 8 bs
      let !v = beWord w
      if v <= 0xffffffff then Left (NonCanonicalEcf "int: non-minimal 8-byte arg") else Right (v, r)
  | ai == 31 = Left (NonCanonicalEcf "indefinite-length head forbidden in ECF")
  | otherwise = Left (NonCanonicalEcf ("reserved additional-info " ++ show ai))

-- | Big-endian fold of up to 8 bytes into a 'Word64'.
beWord :: BS.ByteString -> Word64
beWord = BS.foldl' (\ !acc b -> (acc `shiftL` 8) .|. fromIntegral b) 0

-- | Split off exactly @n@ bytes or fail with 'Truncated'.
takeN :: Int -> BS.ByteString -> Either CodecError (BS.ByteString, BS.ByteString)
takeN n bs
  | n < 0 = Left (NonCanonicalEcf "negative length")
  | BS.length bs < n = Left (Truncated ("need " ++ show n ++ " bytes, have " ++ show (BS.length bs)))
  | otherwise = Right (BS.splitAt n bs)

decodeArray :: Bool -> Int -> BS.ByteString -> Either CodecError (Value, BS.ByteString)
decodeArray rejectTags = go []
  where
    go acc 0 r = Right (VArray (reverse acc), r)
    go acc k r = do
      (!v, !r') <- decodeItem rejectTags r
      go (v : acc) (k - 1) r'

-- | Decode a map of @n@ entries, enforcing canonical key order
-- (length-then-lex over encoded key bytes) AND duplicate-key rejection (N3
-- neighborhood). The previous key's encoded bytes thread through so each new
-- key is checked to be strictly greater.
decodeMap :: Bool -> Int -> BS.ByteString -> Either CodecError (Value, BS.ByteString)
decodeMap rejectTags total = go [] Nothing total
  where
    go acc _ 0 r = Right (VMap (reverse acc), r)
    go acc prevKey k r = do
      (!key, !r1) <- decodeItem rejectTags r
      (!val, !r2) <- decodeItem rejectTags r1
      let !kb = encode key
      case prevKey of
        Nothing -> pure ()
        Just !pb -> when (keyOrder pb kb /= LT) $
          if pb == kb
            then Left (DuplicateKey "map: duplicate key")
            else Left (NonCanonicalEcf "map: keys not in canonical order")
      go ((key, val) : acc) (Just kb) (k - 1) r2

-- | Canonical key order: by encoded length, then lexicographic over bytes.
keyOrder :: BS.ByteString -> BS.ByteString -> Ordering
keyOrder a b = compare (BS.length a) (BS.length b) <> compare a b

-- | Decode a major-type-7 head: false/true/null, or a float (f16/f32/f64).
-- Rejects @undefined@ (0xf7) and any simple value not in ECF, and enforces
-- shortest-float (a value that would fit in a narrower width is non-canonical).
decodeSimpleOrFloat :: Word8 -> BS.ByteString -> Either CodecError (Value, BS.ByteString)
decodeSimpleOrFloat ai rest = case ai of
  20 -> Right (VBool False, rest)
  21 -> Right (VBool True, rest)
  22 -> Right (VNull, rest)
  23 -> Left (Unsupported "undefined (0xf7) not used in ECF")
  25 -> do
    (!w, !r) <- takeN 2 rest
    Right (VFloat (decodeFloat16 (fromIntegral (beWord w) :: Word16)), r)
  26 -> do
    (!w, !r) <- takeN 4 rest
    let !d = decodeFloat32 (fromIntegral (beWord w) :: Word32)
    if encodeFloatShortest d == BS.cons 0xfa w
      then Right (VFloat d, r)
      else Left (NonCanonicalEcf "float32 not shortest")
  27 -> do
    (!w, !r) <- takeN 8 rest
    let !d = decodeFloat64 (beWord w)
    if encodeFloatShortest d == BS.cons 0xfb w
      then Right (VFloat d, r)
      else Left (NonCanonicalEcf "float64 not shortest")
  24 -> Left (Unsupported "simple value with 1-byte arg not in ECF")
  _ -> Left (Unsupported ("simple value ai=" ++ show ai ++ " not in ECF"))
