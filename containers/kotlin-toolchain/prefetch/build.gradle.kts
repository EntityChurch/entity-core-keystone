// Prefetch seed build — see settings.gradle.kts. Resolves the EXACT pinned deps
// into the image gradle caches so the real peer build runs `--offline`.
//
// The Kotlin Gradle plugin is applied via the plugins block; the toolchain image's
// `gradle` resolves the kotlin-gradle-plugin (1.9.25) from the Gradle Plugin Portal
// at build time, seeding it into the cache too. A trivial kotlin.test test is
// compiled + run so the kotlin compiler artifacts AND the JUnit-5 test-runtime
// providers (which resolve lazily at test-EXECUTION time, not at resolution time)
// land in the caches.

plugins {
    kotlin("jvm") version "1.9.25"
}

repositories {
    mavenCentral()
    gradlePluginPortal()
}

// Dedicated configuration to force the opt-in BouncyCastle jar into the cache.
// Declared BEFORE the dependencies block that references it.
val bouncyCastle by configurations.creating

dependencies {
    // Runtime deps the real peer ships / depends on.
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.25")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // Test path: kotlin.test on the JUnit 5 platform.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:1.9.25")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")

    // OPT-IN agility cross-check / fallback ONLY (the core build is BouncyCastle-free).
    // Pre-fetched so an opt-in agility cross-check can run offline. Marked into its own
    // configuration so `resolveBouncyCastle` can force-seed it.
    "bouncyCastle"("org.bouncycastle:bcprov-jdk18on:1.80")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}

// Explicitly seed the opt-in BouncyCastle agility cross-check jar (called by the
// Containerfile's `gradle -q resolveBouncyCastle`).
tasks.register("resolveBouncyCastle") {
    doLast {
        bouncyCastle.resolve().forEach { println("seeded: ${it.name}") }
    }
}
