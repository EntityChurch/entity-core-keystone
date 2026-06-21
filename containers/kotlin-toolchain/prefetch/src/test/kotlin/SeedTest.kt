package prefetch

import kotlin.test.Test
import kotlin.test.assertEquals

// Trivial kotlin.test test on the JUnit-5 platform so the test-runtime providers
// resolve into the image caches at BUILD time (they resolve lazily at test execution,
// not at dependency resolution — the surefire/gradle lesson noted in the Containerfile).
class SeedTest {
    @Test
    fun seedIs42() {
        assertEquals(42, seed())
    }
}
