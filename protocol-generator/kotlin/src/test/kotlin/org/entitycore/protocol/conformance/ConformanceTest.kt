package org.entitycore.protocol.conformance

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The ECF conformance gate as a kotlin.test test (JUnit 5 platform). Decodes the
 * vendored fixture with our own decoder, runs every vector, byte-compares against the
 * embedded cross-blessed `canonical` bytes. All vectors MUST pass.
 */
class ConformanceTest {
    @Test
    fun allVectorsByteIdentical() {
        val result = ConformanceHarness.run(ConformanceHarness.defaultFixture())
        println("ECF conformance: ${result.pass}/${result.total} PASS (${result.fail} fail)")
        result.failures.forEach { println("  $it") }
        assertTrue(result.total >= 69, "expected >= 69 testable vectors, got ${result.total}")
        assertEquals(0, result.fail, "byte-identity failures:\n" + result.failures.joinToString("\n"))
        assertEquals(result.total, result.pass)
    }
}
