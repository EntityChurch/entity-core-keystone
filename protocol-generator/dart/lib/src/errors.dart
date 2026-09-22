/// The Dart-3 sealed-class error model for the Entity Core Protocol peer.
///
/// Codec and protocol decode failures are VALUES, not thrown exceptions: a
/// sealed [EntityError] hierarchy matched EXHAUSTIVELY by a `switch` EXPRESSION
/// (the analyzer reports a non-exhaustive switch over a sealed type — the
/// static-rigor analogue of Kotlin's sealed `when`, OCaml's `result`, C++'s
/// `std::expected`). See profile.toml [error_model] + A-DART-004.
///
/// Exceptions ([StateError]/[ArgumentError]) stay reserved for truly
/// unrecoverable programmer errors and are caught at the per-connection task
/// boundary (S3) — NEVER on the protocol flow path.
library;

/// Root of the protocol/codec error hierarchy. A value, not a thrown exception.
sealed class EntityError {
  const EntityError(this.message);

  /// A human-readable detail for diagnostics (never on the wire).
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

// ── codec errors (S2) ────────────────────────────────────────────────────────

/// Failures of the canonical ECF codec (ENTITY-CBOR-ENCODING).
sealed class CodecError extends EntityError {
  const CodecError(super.message);
}

/// The bytes are not canonical ECF (e.g. non-minimal head, reserved/indefinite
/// argument, bad major type, trailing bytes, depth limit). Wire status 400.
final class NonCanonicalEcf extends CodecError {
  const NonCanonicalEcf(super.message);
}

/// The input ran off the end of the buffer mid-item.
final class TruncatedInput extends CodecError {
  const TruncatedInput(super.message);
}

/// A CBOR major-type-6 tag was seen on decode (rejected at any depth — N2).
final class TagRejected extends CodecError {
  const TagRejected(super.message);
}

/// A duplicate key was seen in a canonical map.
final class DuplicateKey extends CodecError {
  const DuplicateKey(super.message);
}

/// An integer head form used a non-minimal argument encoding.
final class NonMinimalInt extends CodecError {
  const NonMinimalInt(super.message);
}

/// A float used a non-shortest (non-canonical) encoding.
final class NonCanonicalFloat extends CodecError {
  const NonCanonicalFloat(super.message);
}

// ── crypto errors (S2) ───────────────────────────────────────────────────────

/// Crypto-layer failures (seed shape, unsupported curve/hash).
sealed class CryptoError extends EntityError {
  const CryptoError(super.message);
}

/// A signing seed was the wrong length for the curve.
final class BadSeed extends CryptoError {
  const BadSeed(super.message);
}

/// An unsupported key_type was requested.
final class UnsupportedKeyType extends CryptoError {
  const UnsupportedKeyType(super.message);
}

/// An unsupported content_hash format code was requested on the verify side.
final class UnsupportedContentHashFormat extends CryptoError {
  const UnsupportedContentHashFormat(super.message);
}

// ── protocol errors (S3 — declared now so the hierarchy is complete) ──────────

/// Protocol-status failures mapped to wire status codes at the dispatcher.
sealed class ProtocolError extends EntityError {
  const ProtocolError(super.message);
}

/// §5.2a — 401: author absent / unresolvable on a non-connect EXECUTE path.
final class AuthenticationFailed extends ProtocolError {
  const AuthenticationFailed(super.message);
}

/// §5.2a — 403: capability absent (author present + signed).
final class AuthorizationDenied extends ProtocolError {
  const AuthorizationDenied(super.message);
}

/// §4.10a — 413: payload over the declared bound.
final class PayloadTooLarge extends ProtocolError {
  const PayloadTooLarge(super.message);
}

/// §4.10b — 400: delegation chain over the declared depth bound.
final class ChainDepthExceeded extends ProtocolError {
  const ChainDepthExceeded(super.message);
}

/// A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
/// `content_hash` is not `content_hash({type, data})`, or an `included` entry whose
/// MAP KEY does not bind to the entity filed under it.
///
/// §5.2a pins this arm: "A peer that refuses at the decode boundary MUST answer
/// `400 hash_mismatch` [MUST]" (mood corrected 0.8.2.24), and in the same breath
/// "`400 non_canonical_ecf` is NOT conformant here [MUST]". That code is
/// ENTITY-CBOR-ENCODING §6.3's, for a CBOR tag-policy violation, and a mis-keyed
/// `included` entry carries NO TAG: its encoding is canonical, what is false is the
/// claim the KEY makes, and the remedy `non_canonical_ecf` selects (re-encode) sends
/// an honest caller to the wrong layer. This peer answered `non_canonical_ecf` for
/// every decode-boundary refusal until 0.8.2.24 — measured on the wire, arc-probe
/// B1/B2.
///
/// A MEMBER OF THE SEALED [ProtocolError] TREE rather than the `ArgumentError` these
/// sites used to throw: §4.11's classifier dispatches on the TYPE, and an
/// `ArgumentError` carrying a distinguishing MESSAGE would put the code one string
/// edit away from silently re-collapsing two causes into one.
final class HashMismatch extends ProtocolError {
  const HashMismatch(super.message);
}

/// Transport-layer failures (S3).
sealed class TransportError extends EntityError {
  const TransportError(super.message);
}

/// A generic transport failure (connection reset, etc.).
final class TransportFailed extends TransportError {
  const TransportFailed(super.message);
}

/// A Dart-3 sealed-class `Result` over the [EntityError] error channel.
///
/// The codec public surface returns an [EcfResult]; callers match with an
/// exhaustive `switch` over [Ok]/[Err] (the compiler enforces coverage).
sealed class EcfResult<T> {
  const EcfResult();

  /// True for [Ok].
  bool get isOk => this is Ok<T>;

  /// The value if [Ok], else null. Prefer an exhaustive `switch` over this.
  T? get valueOrNull => switch (this) {
        Ok<T>(:final value) => value,
        Err<T>() => null,
      };

  /// The error if [Err], else null.
  EntityError? get errorOrNull => switch (this) {
        Ok<T>() => null,
        Err<T>(:final error) => error,
      };

  /// Unwrap the [Ok] value or throw a [StateError] (internal-callers-only path,
  /// for code that treats a failure here as a bug).
  T unwrap() => switch (this) {
        Ok<T>(:final value) => value,
        Err<T>(:final error) => throw StateError('EcfResult.unwrap on Err: $error'),
      };
}

/// The success arm of [EcfResult].
final class Ok<T> extends EcfResult<T> {
  const Ok(this.value);
  final T value;
}

/// The failure arm of [EcfResult], carrying a sealed [EntityError].
final class Err<T> extends EcfResult<T> {
  const Err(this.error);
  final EntityError error;
}

/// Internal sentinel exception used to unwind the recursive codec hot path; the
/// public surface catches it and translates it to an [Err]. The throw NEVER
/// escapes the codec (mirrors the Kotlin EcfException seam). Not exported.
final class EcfException implements Exception {
  const EcfException(this.error);
  final EntityError error;
  @override
  String toString() => 'EcfException($error)';
}

/// A decode-boundary refusal, carrying the [EntityError] that CAUSED it.
///
/// §4.11 (0.8.2.25) assigns the status and code by CAUSE, so the cause has to
/// survive the throw. The frame path used to collapse every codec failure into one
/// untyped transport exception, which is exactly the erasure that made
/// `non_canonical_ecf` the answer to five different questions.
final class DecodeRefusal implements Exception {
  const DecodeRefusal(this.cause);
  final EntityError cause;
  @override
  String toString() => 'DecodeRefusal($cause)';
}
