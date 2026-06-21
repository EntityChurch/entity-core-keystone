package org.entitycore.protocol.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Drives the ECF wire-conformance corpus and asserts 0 FAIL (the S2 phase gate). */
final class ConformanceTest {

    @Test
    void ecfCorpusByteIdentical() throws Exception {
        ConformanceHarness.Result r = ConformanceHarness.run(ConformanceHarness.defaultFixture());
        System.out.printf("== ECF conformance: %d/%d PASS, %d FAIL ==%n",
                r.pass(), r.total(), r.fail());
        for (String f : r.failures()) {
            System.out.println("  " + f);
        }
        assertTrue(r.total() >= 69, "expected at least 69 testable vectors, got " + r.total());
        assertEquals(0, r.fail(), "wire-conformance must be all-PASS");
    }
}
