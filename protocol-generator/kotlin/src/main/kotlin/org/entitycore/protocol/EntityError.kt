package org.entitycore.protocol

/**
 * The protocol/codec error hierarchy — a SEALED CLASS matched EXHAUSTIVELY by `when`
 * (the compiler enforces exhaustiveness over a sealed type, so a new error variant
 * forces every dispatch site to handle it). This is the Kotlin-native recoverable-error
 * seam and the PRIMARY axis on which this peer diverges from the Java peer (Java chose
 * checked exceptions; Kotlin has none — the sealed `EntityError` value *is* the
 * compiler-enforced handling mechanism). See profile.toml [error_model].
 *
 * Errors are carried as VALUES on the recoverable path (via [EcfResult]); exceptions
 * stay reserved for truly unrecoverable programmer errors, the Kotlin convention.
 */
sealed class EntityError {
    abstract val message: String

    /** Codec-layer failures (ECF encode/decode). */
    sealed class CodecError : EntityError() {
        /** Input is not canonical ECF (e.g. trailing bytes, bad major type, non-minimal). */
        data class NonCanonicalEcf(override val message: String) : CodecError()

        /** Input ran off the end of the buffer. */
        data class TruncatedInput(override val message: String) : CodecError()

        /** A CBOR tag (major type 6) was found — forbidden in ECF (§6.3, invariant N2). */
        data class TagRejected(override val message: String) : CodecError()

        /** A duplicate map key was found on decode (non-canonical). */
        data class DuplicateKey(override val message: String) : CodecError()
    }

    /** Crypto-layer failures. */
    sealed class CryptoError : EntityError() {
        data class BadSeed(override val message: String) : CryptoError()
        data class UnsupportedKeyType(override val message: String) : CryptoError()
        data class UnsupportedContentHashFormat(override val message: String) : CryptoError()
        data class SignFailed(override val message: String) : CryptoError()
    }
}

/**
 * The Kotlin-idiomatic recoverable-result seam: `sealed class EcfResult<out T>` with
 * [Ok] / [Err]. Codec/protocol operations return this rather than throwing; callers
 * match exhaustively with `when` (compiler-checked). The static-rigor analogue of
 * OCaml's `result`, Zig's error union, and Java's checked exceptions — reached via
 * Kotlin's own mechanism.
 */
sealed class EcfResult<out T> {
    data class Ok<out T>(val value: T) : EcfResult<T>()
    data class Err(val error: EntityError) : EcfResult<Nothing>()

    /** Unwrap the value, or throw — for test code / unrecoverable callers only. */
    fun getOrThrow(): T = when (this) {
        is Ok -> value
        is Err -> throw EcfException(error)
    }

    inline fun <R> map(transform: (T) -> R): EcfResult<R> = when (this) {
        is Ok -> Ok(transform(value))
        is Err -> this
    }
}

/** Thin exception wrapper used only when an [EcfResult.Err] must cross an
 *  exception boundary (test harness / unrecoverable caller). Not the primary seam. */
class EcfException(val error: EntityError) : RuntimeException(error.message)
