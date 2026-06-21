/- Public codec surface. `EntityCore.Codec.encode : Value → ByteArray` and
`EntityCore.Codec.decode : ByteArray → Except CodecError Value`. The encoder is a
total pure function (the T2/T3 proof surface); the decoder is `partial` (Track A). -/
import EntityCore.Codec.Value
import EntityCore.Codec.Error
import EntityCore.Codec.Float
import EntityCore.Codec.Varint
import EntityCore.Codec.CBOR
