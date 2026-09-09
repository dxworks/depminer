package org.dxworks.depminer

import org.dxworks.depminer.sanitization.Flagged
import org.dxworks.depminer.sanitization.ScrubReport
import org.dxworks.depminer.sanitization.Sanitizer
import org.dxworks.depminer.sanitization.buildHostRules
import org.dxworks.depminer.sanitization.scrubLine
import org.dxworks.depminer.sanitization.verifyScrubbed
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * The files the jar copies out of the scanned tree used to ship with the host's layout in them:
 * sanitize.yml carries credential patterns only, so NuGet's project.assets.json went out with
 * `/Users/<someone>/.nuget/packages/` and the absolute path of every csproj intact, silently.
 */
class HostPathScrubTest {

    private val assets = """
        {
          "packageFolders": { "/Users/someone/.nuget/packages/": {} },
          "project": {
            "restore": {
              "projectPath": "/tmp/scan-target/dotnet-app/src/Web/Web.csproj",
              "configFilePaths": [ "/Users/someone/.nuget/NuGet/NuGet.Config" ],
              "sources": { "https://buildbot:glpat-SECRET@nexus.corp.internal/v3/index.json": {} }
            }
          }
        }
    """.trimIndent()

    private fun rules(target: Path, results: Path) = buildHostRules(target, results, "/Users/someone")

    @Test
    fun `host paths and url credentials are removed, package folder still readable`(@TempDir tmp: Path) {
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        val out = assets.lines().joinToString("\n") { scrubLine(it, rules(target, results)) }

        assertFalse(out.contains("/Users/someone"), "home path survived: $out")
        assertFalse(out.contains("glpat-SECRET"), "credentials survived: $out")
        assertFalse(out.contains("buildbot"), "userinfo survived: $out")
        // Rewritten, not deleted: the file still says which folder NuGet restored into.
        assertTrue(out.contains("~/.nuget/packages/"))
        assertTrue(out.contains("nexus.corp.internal"), "only the credentials go, not the host")
    }

    @Test
    fun `verification reports the rule classes that survived, never the value`(@TempDir tmp: Path) {
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        val leaky = results.resolve("project.assets.json").toFile()
        leaky.writeText(assets)          // written WITHOUT scrubbing, as the old code did

        val flagged = verifyScrubbed(leaky, rules(target, results))
        assertNotNull(flagged)
        assertTrue(flagged!!.matchedRules.contains("home"))
        assertTrue(flagged.matchedRules.contains("url-userinfo"))
        assertTrue(flagged.matchCount >= 2)

        ScrubReport.write(results, listOf(flagged.copy(project = "dotnet-app")))
        val report = results.resolve("scrub-report.json").toFile().readText()
        assertTrue(report.contains("\"reason\": \"emitted-despite-failed-scrub-verification\""))
        assertTrue(report.contains("\"project\": \"dotnet-app\""))
        assertTrue(report.contains("\"home\""))
        // The leak is never copied into the report - that would just move it to a new file.
        assertFalse(report.contains("/Users/someone"), "report leaked the value: $report")
        assertFalse(report.contains("glpat-SECRET"), "report leaked the credential: $report")
    }

    @Test
    fun `report entries are on their own line so the wrappers can append to them`(@TempDir tmp: Path) {
        // bin/syft-wrapper.sh reads entries back with `sed -n 's/^    \({"timestamp".*}\),\{0,1\}$/\1/p'`
        // and rewrites the file, so the jar's entries must match that shape or they are dropped.
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        ScrubReport.write(results, listOf(Flagged("a.json", "p", listOf("home"), 1), Flagged("b.json", "p", listOf("out"), 2)))
        val lines = results.resolve("scrub-report.json").toFile().readLines()
        val entries = lines.filter { it.startsWith("    {\"timestamp\"") }
        assertEquals(2, entries.size, "entries not one-per-line with a four-space indent: $lines")
        assertTrue(entries[0].endsWith(","), "all but the last entry need a trailing comma")
        assertTrue(entries[1].endsWith("}"))
    }

    @Test
    fun `a clean run still writes an empty report, so absent and clean are distinguishable`(@TempDir tmp: Path) {
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        results.resolve("index.json").toFile().writeText("""{"pkg.json":"dotnet-app/src/pkg.json"}""")
        results.resolve("pkg.json").toFile().writeText("""{"name":"clean"}""")
        val sanitizeYml = File(tmp.toFile(), "sanitize.yml").apply { writeText("patterns: []\n") }

        Sanitizer().sanitizeFiles(results, sanitizeYml.path, rules(target, results))

        val report = results.resolve("scrub-report.json").toFile()
        assertTrue(report.exists(), "the report must be written even when nothing was flagged")
        assertTrue(report.readText().contains("\"flagged\""))
        assertNull(verifyScrubbed(results.resolve("pkg.json").toFile(), rules(target, results)))
    }
}
