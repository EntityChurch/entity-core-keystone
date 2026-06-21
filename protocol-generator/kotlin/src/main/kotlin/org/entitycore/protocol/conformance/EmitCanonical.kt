package org.entitycore.protocol.conformance

import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import org.entitycore.protocol.crypto.ContentHash
import org.entitycore.protocol.crypto.Curve
import org.entitycore.protocol.crypto.Ed
import org.entitycore.protocol.crypto.PeerId
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path

/**
 * Per-impl emission producer per GUIDE-CONFORMANCE §3.1 — the cross-impl diff artifact.
 *
 *   emission = {
 *     impl, impl_version, corpus_version, spec_version,
 *     encode_results: { id -> bstr },
 *     decode_results: { id -> bool },
 *     decode_codes:   { id -> tstr },
 *     errors:         { id -> tstr },
 *   }
 *
 * This is the Kotlin analogue of Go's `wire-conformance emit-canonical`. tools/oracle-diff.sh
 * builds Go's emit-go.cbor independently and byte-compares it with our emit-kotlin.cbor
 * to confirm the two impls converge on the wire (the task's "run against the oracle" step).
 *
 * Usage:  emit-canonical <corpus.cbor> <out.cbor>
 *
 * NOTE: the field-key order in the emitted map does not matter — the canonical encoder
 * re-sorts keys (length-then-lex), so emit-go and emit-kotlin sort to the same shape.
 */
object EmitCanonical {
    private const val CORPUS_VERSION = "v1"
    private const val SPEC_VERSION = "1.5"
    // Identity fields are metadata only (NOT codec output). They can be overridden via
    // env so an emission can be produced under the Go oracle's identity (core-go /
    // go-oracle) to make the cross-impl emission byte-IDENTICAL — isolating the codec
    // payload (encode_results/decode_results) as the thing actually under test.
    private val IMPL_NAME = System.getenv("EMIT_IMPL")?.takeIf { it.isNotEmpty() } ?: "core-kotlin"
    private val IMPL_VERSION = System.getenv("EMIT_IMPL_VERSION")?.takeIf { it.isNotEmpty() } ?: "0.1.0"

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size != 2) {
            System.err.println("usage: emit-canonical <corpus.cbor> <out.cbor>")
            kotlin.system.exitProcess(2)
        }
        val corpus = Files.readAllBytes(Path.of(args[0]))
        val out = emit(corpus)
        Files.write(Path.of(args[1]), out)
        println("emit-canonical: wrote ${args[1]} (${out.size} bytes)")
    }

    /** Build the emission CBOR from a loaded corpus. */
    fun emit(corpus: ByteArray): ByteArray {
        val arr = (CanonicalCbor.decode(corpus) as EcfResult.Ok).value as EcfValue.Arr

        val encodeResults = ArrayList<EcfValue.Entry>()
        val decodeResults = ArrayList<EcfValue.Entry>()
        val decodeCodes = ArrayList<EcfValue.Entry>()
        val errors = ArrayList<EcfValue.Entry>()

        for (v in arr.items) {
            val vm = v as? EcfValue.MapVal ?: continue
            val kind = (vm["kind"] as? EcfValue.Text)?.value ?: continue
            val id = (vm["id"] as? EcfValue.Text)?.value ?: continue
            when (kind) {
                "encode_equal" -> try {
                    val b = produce(id, vm["input"]!!)
                    encodeResults.add(EcfValue.Entry(EcfValue.Text(id), EcfValue.Bytes(b)))
                } catch (e: Exception) {
                    errors.add(EcfValue.Entry(EcfValue.Text(id), EcfValue.Text(e.message ?: e.toString())))
                }
                "decode_reject" -> {
                    val wire = (vm["canonical"] as EcfValue.Bytes).octets()
                    val rejected = CanonicalCbor.decode(wire) is EcfResult.Err
                    decodeResults.add(EcfValue.Entry(EcfValue.Text(id),
                        if (rejected) EcfValue.Bool.TRUE else EcfValue.Bool.FALSE))
                    if (rejected) {
                        decodeCodes.add(EcfValue.Entry(EcfValue.Text(id), EcfValue.Text("non_canonical_ecf")))
                    }
                }
            }
        }

        val emission = EcfValue.MapVal.of(
            "impl", EcfValue.Text(IMPL_NAME),
            "impl_version", EcfValue.Text(IMPL_VERSION),
            "corpus_version", EcfValue.Text(CORPUS_VERSION),
            "spec_version", EcfValue.Text(SPEC_VERSION),
            "encode_results", EcfValue.MapVal(encodeResults),
            "decode_results", EcfValue.MapVal(decodeResults),
            "decode_codes", EcfValue.MapVal(decodeCodes),
            "errors", EcfValue.MapVal(errors),
        )
        return CanonicalCbor.encodeOrThrow(emission)
    }

    private fun produce(id: String, input: EcfValue): ByteArray {
        val dot = id.indexOf('.')
        val cat = if (dot >= 0) id.substring(0, dot) else id
        return when (cat) {
            "content_hash" -> {
                val m = input as EcfValue.MapVal
                val code = (m["format_code"] as? EcfValue.IntVal)?.value?.toInt() ?: 0
                ContentHash.compute(EcfValue.MapVal.of("type", m["type"]!!, "data", m["data"]!!), code)
            }
            "peer_id" -> {
                val m = input as EcfValue.MapVal
                val kt = (m["key_type"] as EcfValue.IntVal).value.toInt()
                val ht = (m["hash_type"] as EcfValue.IntVal).value.toInt()
                val digest = (m["digest"] as EcfValue.Bytes).octets()
                CanonicalCbor.encodeOrThrow(EcfValue.Text(PeerId.format(kt, ht, digest)))
            }
            "signature" -> {
                val m = input as EcfValue.MapVal
                val seed = (m["seed"] as EcfValue.Bytes).octets()
                val entity = m["entity"] as EcfValue.MapVal
                val ecf = CanonicalCbor.encodeOrThrow(
                    EcfValue.MapVal.of("type", entity["type"]!!, "data", entity["data"]!!))
                Ed.sign(seed, ecf, Curve.ED25519)
            }
            else -> CanonicalCbor.encodeOrThrow(input)
        }
    }
}
