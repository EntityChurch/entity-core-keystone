// Prefetch seed project for the kotlin-toolchain image.
//
// Purpose: at container BUILD time (network available) `gradle build test` against
// this project populates the image's GRADLE_USER_HOME (/root/.gradle) caches with
// EXACTLY the pinned dependency versions the entity-core-protocol-kotlin peer uses,
// so the dev loop then runs `gradle --offline` under a sealed network (--network=none).
//
// Pins MUST match protocol-generator/kotlin/profile.toml [deps]:
//   * org.jetbrains.kotlin:kotlin-stdlib            1.9.25  (runtime)
//   * org.jetbrains.kotlinx:kotlinx-coroutines-core 1.8.1   (runtime)
//   * org.jetbrains.kotlin:kotlin-test-junit5       1.9.25  (test)
//   * org.junit.jupiter:junit-jupiter               5.11.4  (test platform backend)
//   * org.bouncycastle:bcprov-jdk18on               1.80    (OPT-IN agility cross-check)
//
// This is the build-recipe fixture, NOT the peer's real settings/build (authored
// under protocol-generator/kotlin/).
rootProject.name = "entity-core-protocol-kotlin-prefetch"
