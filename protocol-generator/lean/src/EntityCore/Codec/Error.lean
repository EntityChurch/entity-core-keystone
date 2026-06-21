/- Codec error model. The pure codec returns `Except CodecError`; no exceptions,
no IO (the totality that makes the encoder a proof target). -/
namespace EntityCore

inductive CodecError where
  | truncated (msg : String)
  | nonCanonical (msg : String)      -- 400 non_canonical_ecf neighbourhood
  | tagRejected (msg : String)       -- §6.3 Option B
  | duplicateKey (msg : String)
  | unsupported (msg : String)
  | badUtf8 (msg : String)
  | trailing (msg : String)
  deriving Repr, Inhabited, BEq

def CodecError.message : CodecError → String
  | .truncated m | .nonCanonical m | .tagRejected m | .duplicateKey m
  | .unsupported m | .badUtf8 m | .trailing m => m

end EntityCore
