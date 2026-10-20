package org.dxworks.depminer

import org.dxworks.depminer.sanitization.Sanitizer
import org.dxworks.depminer.sanitization.buildHostRules
import org.dxworks.depminer.sanitization.isLockfile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * sanitize.yml was written for config files, and ran on lockfiles too: in petclinic's
 * gradle.lockfile the connection-string rule `jdbc:[^\s;]+` matched `spring-boot-jdbc:4.1.0=...`
 * and replaced four dependency versions with `***REDACTED***`, silently. A pattern can now say
 * `scope: manifests` to stay off lockfiles; the ones with a distinctive prefix keep running there.
 */
class LockfileSanitizeTest {

    private val sanitizeYml = """
        patterns:
          - pattern: "jdbc:[^\\s;]+(?:;[^\\s;]+)*"
            replacement: "jdbc:***REDACTED***"
            scope: manifests
          - pattern: "\\bghp_[A-Za-z0-9_]{36,251}\\b"
            replacement: "***REDACTED***"
    """.trimIndent()

    private val gradleLock = """
        org.springframework.boot:spring-boot-jdbc:4.1.0=compileClasspath,runtimeClasspath
        org.springframework:spring-jdbc:7.0.8=compileClasspath,runtimeClasspath
    """.trimIndent()

    private fun setup(tmp: Path): Pair<Path, Path> {
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        File(tmp.toFile(), "sanitize.yml").writeText(sanitizeYml)
        return target to results
    }

    private fun run(tmp: Path, target: Path, results: Path) =
        Sanitizer().sanitizeFiles(
            results, tmp.resolve("sanitize.yml").toString(),
            buildHostRules(target, results, "/Users/someone"), results
        )

    @Test
    fun `lockfile names`() {
        listOf(
            "Cargo.lock", "composer.lock", "Gemfile.lock", "uv.lock", "poetry.lock", "yarn.lock",
            "package-lock.json", "pnpm-lock.yaml", "gradle.lockfile", "go.sum", "packages.lock.json",
            "npm-shrinkwrap.json"
        ).forEach { assertTrue(isLockfile(it), it) }
        listOf("package.json", "pom.xml", "project.assets.json", "Cargo.toml", "go.mod", "Pipfile")
            .forEach { assertFalse(isLockfile(it), it) }
    }

    @Test
    fun `a manifests-scoped pattern leaves a lockfile alone, a prefixed token is still removed`(@TempDir tmp: Path) {
        val (target, results) = setup(tmp)
        results.resolve("gradle.lockfile").toFile().writeText(gradleLock)
        results.resolve("build.gradle").toFile().writeText("url = \"jdbc:postgresql://db.corp/app\"\n")
        results.resolve("yarn.lock").toFile().writeText(
            "\"@corp/lib@1.0.0\":\n  resolved \"https://npm.corp/lib.tgz#ghp_${"a".repeat(36)}\"\n"
        )
        // A duplicate name ships renamed; it is still a lockfile, by its original name in the index.
        val renamedLock = "\"pg\": { \"resolved\": \"jdbc:not-a-secret\" }"
        results.resolve("package-lock-1.json").toFile().writeText(renamedLock)
        results.resolve("index.json").toFile().writeText(
            """{"gradle.lockfile":"petclinic/gradle.lockfile","build.gradle":"petclinic/build.gradle",""" +
                """"yarn.lock":"web/yarn.lock","package-lock-1.json":"web/api/package-lock.json"}"""
        )

        run(tmp, target, results)

        // The four petclinic versions: still there.
        assertEquals(gradleLock, results.resolve("gradle.lockfile").toFile().readText())
        // Same pattern, manifest file: applied.
        assertTrue(results.resolve("build.gradle").toFile().readText().contains("jdbc:***REDACTED***"))
        // A real token inside a lockfile is not protected by the scope.
        val yarn = results.resolve("yarn.lock").toFile().readText()
        assertFalse(yarn.contains("ghp_"), yarn)
        assertTrue(yarn.contains("@corp/lib@1.0.0"), "the entry itself must survive")
        assertEquals(renamedLock, results.resolve("package-lock-1.json").toFile().readText())
    }

    @Test
    fun `a rewrite inside a lockfile is reported, never silent`(@TempDir tmp: Path) {
        val (target, results) = setup(tmp)
        // Same jdbc pattern but with the default scope - what every existing sanitize.yml does.
        File(tmp.toFile(), "sanitize.yml").writeText(sanitizeYml.replace("scope: manifests", "scope: all"))
        results.resolve("gradle.lockfile").toFile().writeText(gradleLock)
        results.resolve("index.json").toFile().writeText("""{"gradle.lockfile":"petclinic/gradle.lockfile"}""")

        run(tmp, target, results)

        val report = results.resolve("scrub-report.json").toFile().readText()
        assertTrue(report.contains("\"reason\": \"redacted-inside-lockfile\""), report)
        assertTrue(report.contains("\"file\": \"gradle.lockfile\""), report)
        assertTrue(report.contains("\"project\": \"petclinic\""), report)
        assertTrue(report.contains("\"matchCount\": 2"), report)
        // The rule is named by its pattern, the rewritten value is not copied into the report.
        assertTrue(report.contains("jdbc:[^"), report)
        assertFalse(report.contains("spring-boot-jdbc"), report)
    }

    @Test
    fun `a file deleted for a private key is returned as skipped with the reason`(@TempDir tmp: Path) {
        val (target, results) = setup(tmp)
        results.resolve("build.gradle").toFile().writeText("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
        results.resolve("index.json").toFile().writeText("""{"build.gradle":"app/build.gradle"}""")

        val outcome = run(tmp, target, results)

        assertFalse(results.resolve("build.gradle").toFile().exists())
        assertEquals(1, outcome.skipped.size)
        assertEquals("build.gradle", outcome.skipped[0].file)
        assertEquals("private-key-detected", outcome.skipped[0].reason)
    }
}
