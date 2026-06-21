package org.entitycore.protocol.conformance

import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import org.entitycore.protocol.crypto.ContentHash
import org.entitycore.protocol.crypto.Curve
import org.entitycore.protocol.crypto.Ed
import org.entitycore.protocol.crypto.PeerId
import java.nio.file.Files
import java.nio.file.Path

/**
 * ECF wire-conformance harness (the codec gate).
 *
 * The normative fixture `conformance-vectors-v1.cbor` is itself a canonical-ECF-encoded
 * array of vector maps, each carrying its own cross-blessed `canonical` bytes (the Go
 * `wire-conformance` oracle's build-fixture/emit-canonical output, 3-way Go × Rust ×
 * Python byte-locked). The harness decodes the fixture with THIS peer's OWN decoder (a
 * decoder bug is itself a conformance failure per ENTITY-CBOR-ENCODING.md §E.3), runs
 * each vector through the codec, and byte-compares against the embedded `canonical`.
 * Byte-identity to the fixture == oracle PASS. (Same self-contained mechanism the
 * C#/TS/OCaml/Elixir/Zig/CL/Java peers used; the Go binary is the fixture PRODUCER, not
 * a runtime checker.) An independent diff against a freshly built Go `emit-canonical`
 * emission is run by tools/oracle-diff.sh.
 *
 * Dispatch by `id` prefix:
 *  - content_hash → varint(format_code) ‖ SHA-2(ECF({type,data}))
 *  - peer_id      → the Base58 string wrapped as a CBOR text string
 *  - signature    → Ed25519_sign(seed, ECF({type,data}))
 *  - everything else (float/int/map_keys/length/primitive/nested/envelope) → ECF encode(input)
 *  - decode_reject → the decoder MUST reject the canonical wire bytes
 */
object ConformanceHarness {

    data class Result(val pass: Int, val fail: Int, val total: Int, val failures: List<String>)

    /** Resolve the fixture path: env `ECF_FIXTURE` or the vendored default. */
    fun defaultFixture(): Path {
        val env = System.getenv("ECF_FIXTURE")
        if (!env.isNullOrEmpty()) return Path.of(env)
        return Path.of("../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor")
    }

    fun run(fixture: Path): Result {
        val octets = Files.readAllBytes(fixture)
        val decoded = (CanonicalCbor.decode(octets) as? EcfResult.Ok)?.value
            ?: error("fixture failed to decode with our own decoder")
        val arr = decoded as? EcfValue.Arr ?: error("fixture top-level is not an array")

        var pass = 0
        var fail = 0
        var total = 0
        val failures = ArrayList<String>()

        for (v in arr.items) {
            val vm = v as? EcfValue.MapVal ?: continue // meta / non-vector
            val kind = text(vm["kind"]) ?: continue    // meta entry without a kind
            val id = text(vm["id"]) ?: "?"
            total++
            var ok: Boolean
            var detail: String? = null
            try {
                when (kind) {
                    "decode_reject" -> {
                        val wire = bytes(vm["canonical"])
                        ok = rejects(wire)
                        if (!ok) detail = "decoder ACCEPTED a reject vector"
                    }
                    "encode_equal" -> {
                        val want = bytes(vm["canonical"])
                        val got = produce(id, vm["input"]!!)
                        ok = got.contentEquals(want)
                        if (!ok) detail = "want=${hex(want)} got=${hex(got)}"
                    }
                    else -> { total--; continue }
                }
            } catch (e: Exception) {
                ok = false
                detail = "raised: $e"
            }
            if (ok) pass++ else { fail++; failures.add("FAIL $id: $detail") }
        }
        return Result(pass, fail, total, failures)
    }

    private fun produce(id: String, input: EcfValue): ByteArray = when (category(id)) {
        "content_hash" -> {
            val m = input as EcfValue.MapVal
            val code = (m["format_code"] as? EcfValue.IntVal)?.value?.toInt() ?: 0
            val entity = EcfValue.MapVal.of("type", m["type"]!!, "data", m["data"]!!)
            ContentHash.compute(entity, code)
        }
        "peer_id" -> {
            val m = input as EcfValue.MapVal
            val kt = (m["key_type"] as EcfValue.IntVal).value.toInt()
            val ht = (m["hash_type"] as EcfValue.IntVal).value.toInt()
            val digest = bytes(m["digest"])
            val peerId = PeerId.format(kt, ht, digest)
            // canonical = the peer_id string encoded as a CBOR text string
            CanonicalCbor.encodeOrThrow(EcfValue.Text(peerId))
        }
        "signature" -> {
            val m = input as EcfValue.MapVal
            val seed = bytes(m["seed"])
            val entity = m["entity"] as EcfValue.MapVal
            val hashed = EcfValue.MapVal.of("type", entity["type"]!!, "data", entity["data"]!!)
            val ecf = CanonicalCbor.encodeOrThrow(hashed)
            Ed.sign(seed, ecf, Curve.ED25519)
        }
        else -> CanonicalCbor.encodeOrThrow(input)
    }

    private fun rejects(wire: ByteArray): Boolean =
        CanonicalCbor.decode(wire) is EcfResult.Err

    private fun category(id: String): String {
        val dot = id.indexOf('.')
        return if (dot >= 0) id.substring(0, dot) else id
    }

    private fun text(v: EcfValue?): String? = (v as? EcfValue.Text)?.value

    private fun bytes(v: EcfValue?): ByteArray =
        (v as? EcfValue.Bytes)?.octets() ?: error("expected bytes, got $v")

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
}
