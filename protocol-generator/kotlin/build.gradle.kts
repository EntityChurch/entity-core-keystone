// entity-core-protocol-kotlin — build script (Gradle Kotlin DSL).
//
// Per protocol-generator/kotlin/profile.toml:
//   * Kotlin 1.9.25 / JVM target 21 / language+api version 1.9
//   * runtime dep: kotlinx-coroutines-core 1.8.1 (the one non-stdlib runtime dep)
//   * test:        kotlin-test on the JUnit 5 platform (junit-jupiter 5.11.4)
// CORE crypto (Ed25519 + SHA-256) is JDK SunEC/SunMessageDigest — zero dep. CBOR +
// base58 + LEB128 varint are hand-rolled in src/main/kotlin/.../codec.
//
// Reproducible/offline: built in the kotlin-toolchain image with `gradle --offline
// --no-daemon`; deps pre-seeded into the image caches at container build time.

plugins {
    kotlin("jvm") version "1.9.25"
    application
    // S5 packaging — vanilla Gradle publish path (no third-party publish plugin, to keep the
    // supply chain minimal per the profile [publishing].publish_plugin). maven-publish builds
    // the POM + publication; signing GPG-signs the artifacts (Maven Central requires signed
    // artifacts). NEITHER is run by the pipeline — `/entity-rosetta` never publishes
    // (lifecycle §Publishing); these configure a `gradle publish` an OPERATOR runs after arch
    // v0.1 sign-off + namespace verification (A-KT-005).
    `maven-publish`
    signing
}

// The standalone S4-ready host (boots a peer on a localhost port; prints LISTENING/PEER).
// The two-peer loopback smoke runs in-process via the SmokeTest gate; the Host is the
// surface S4's validate-peer + the multisig accept-path's --name probe dial into.
application {
    mainClass.set("org.entitycore.protocol.peer.Host")
}

group = "org.entitycore"
// S5 parked version — 0.1.0-pre (cohort norm). Promotes to 0.1.0 when (a) S4 fully green [met:
// 665·0F @ e8524ed] AND (b) >=1 external consumer confirms it works [not yet met]. Gradle's
// version grammar carries the SemVer-style qualifier directly (contrast A-CL-010). The published
// Maven coordinate is org.entitycore:entity-core-protocol-kotlin:0.1.0-pre. See CHANGELOG.md.
version = "0.1.0-pre"

repositories {
    mavenCentral()
}

// S11: dependency locking — every configuration's resolved versions are pinned in
// gradle.lockfile (committed). Combined with the exact version strings above + the
// image's pre-seeded offline caches, the resolved dependency graph is reproducible.
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.25")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:1.9.25")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}

// ---------------------------------------------------------------------------------------------
// S5 packaging — Maven publication + signing (AUTHORED, NOT executed).
//
// Produces a publish-READY artifact: the `gradle build`/`jar` outputs plus a well-formed POM
// with the org.entitycore:entity-core-protocol-kotlin:0.1.0-pre coordinates, Apache-2.0 license
// metadata, and the cohort developer string. Maven Central requires a -sources + -javadoc jar
// alongside the main jar, so both are wired here.
//
// PUBLISH IS DEFERRED — it is an OPERATOR step (A-KT-005), gated on (1) arch v0.1 sign-off,
// (2) a first external consumer, and (3) a VERIFIED `org.entitycore` reverse-DNS namespace on
// the Sonatype Central Portal. The repository URL + credentials are explicit publish-time TODOs
// below; no `publish` task runs in the pipeline, and the project takes no default repository.
// ---------------------------------------------------------------------------------------------

// Maven Central mandates a sources jar and a javadoc/dokka jar next to the main artifact.
java {
    withSourcesJar()
    withJavadocJar()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            // Maven coordinate: org.entitycore:entity-core-protocol-kotlin:0.1.0-pre
            groupId = project.group.toString()
            artifactId = "entity-core-protocol-kotlin"
            version = project.version.toString()

            pom {
                name.set("entity-core-protocol-kotlin")
                description.set(
                    "Entity Core Protocol V7 — native Kotlin/JVM core peer (keystone REACH peer; " +
                        "Android/JVM ecosystem coverage)."
                )
                // TODO(operator, A-KT-005): point at the chosen home (keystone repo today, or the
                // per-language sibling repo if the S10 lift-out is taken) before first publish.
                url.set("https://github.com/entity-core/entity-core-keystone")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        // Cohort convention — matches the Java peer / LICENSE holder string.
                        name.set("Entity Core Protocol contributors")
                    }
                }
                scm {
                    // TODO(operator): set the real SCM coordinates at publish time.
                    url.set("https://github.com/entity-core/entity-core-keystone")
                }
            }
        }
    }

    repositories {
        // TODO(operator, A-KT-005): wire the Sonatype Central Portal / Maven Central staging
        // repository here at publish time, e.g.:
        //   maven {
        //       name = "centralPortal"
        //       url = uri("<central-portal-staging-url>")   // gated on org.entitycore namespace verification
        //       credentials {
        //           username = providers.gradleProperty("centralUsername").orNull
        //           password = providers.gradleProperty("centralPassword").orNull
        //       }
        //   }
        // Left empty deliberately — no default repository, so no accidental deploy. `/entity-rosetta`
        // never publishes (lifecycle §Publishing); this is an operator action after v0.1 sign-off.
    }
}

signing {
    // Maven Central requires GPG-signed artifacts. Signing is GATED to a real publish:
    // it is a no-op for local build/test (no signing key configured in the container), and
    // is only required once an operator wires the publish repository + provides a key.
    // TODO(operator): supply the signing key via `signing.gnupg.keyName` / an in-memory key
    // (ORG_GRADLE_PROJECT_signingKey/signingPassword) at publish time.
    setRequired { gradle.taskGraph.hasTask("publish") }
    sign(publishing.publications["maven"])
}
