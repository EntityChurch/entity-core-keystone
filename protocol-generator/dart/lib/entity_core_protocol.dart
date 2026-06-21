/// entity_core_protocol — a native pure-Dart peer of the Entity Core Protocol
/// (V7 Layers 0-4). The S2 codec surface: a hand-rolled canonical ECF (CBOR)
/// codec, content_hash, peer-id, and Ed25519 signatures.
///
/// The codec is byte-identical to the wire-conformance corpus. See
/// protocol-generator/dart/status/ for the conformance report.
library;

export 'src/errors.dart';
export 'src/codec/ecf_value.dart';
export 'src/codec/ecf.dart';
export 'src/codec/varint.dart';
export 'src/codec/base58.dart';
export 'src/crypto/ed.dart';
export 'src/crypto/content_hash.dart';
export 'src/crypto/peer_id.dart';
