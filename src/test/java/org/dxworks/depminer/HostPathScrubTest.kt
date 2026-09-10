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
    fun `the report goes to the shared dir while the jar's files stay in its own`(@TempDir tmp: Path) {
        // instrument.yml runs the jar with results/depminer as its output and --report-dir=results,
        // so the one scrub report sits beside the three tool folders rather than inside one of them.
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        val out = results.resolve("depminer").also { it.toFile().mkdirs() }
        out.resolve("index.json").toFile().writeText("""{"pkg.json":"dotnet-app/src/pkg.json"}""")
        out.resolve("pkg.json").toFile().writeText("""{"folder":"/Users/someone/.nuget/packages/"}""")
        val sanitizeYml = File(tmp.toFile(), "sanitize.yml").apply { writeText("patterns: []\n") }

        Sanitizer().sanitizeFiles(out, sanitizeYml.path, buildHostRules(target, listOf(out, results), "/Users/someone"), results)

        assertTrue(results.resolve("scrub-report.json").toFile().isFile, "the report is not at the shared root")
        assertFalse(out.resolve("scrub-report.json").toFile().exists(), "the report was left in the subfolder")
        // The file itself still shipped, scrubbed, from the jar's own folder.
        val text = out.resolve("pkg.json").toFile().readText()
        assertTrue(text.contains("~/.nuget/packages/"), text)
        assertFalse(text.contains("/Users/someone"), text)
    }

    @Test
    fun `entries from the wrappers survive a jar write, its own previous ones do not`(@TempDir tmp: Path) {
        // The wrappers rebuild this same file (bin/syft-wrapper.sh, _report_write) and the jar
        // runs first, but it is also runnable on its own against a results dir they already wrote.
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        ScrubReport.write(results, listOf(Flagged("stale.json", "p", listOf("home"), 1)))
        val report = results.resolve("scrub-report.json").toFile()
        report.writeText(
            report.readText().replace(
                "\"wrapper\": \"depminer\", \"project\": \"p\", \"file\": \"stale.json\"",
                "\"wrapper\": \"syft\", \"project\": \"p\", \"file\": \"from-syft.json\""
            )
        )

        ScrubReport.write(results, listOf(Flagged("fresh.json", "p", listOf("out"), 1)))

        val text = report.readText()
        assertTrue(text.contains("from-syft.json"), "a wrapper entry was dropped: $text")
        assertTrue(text.contains("fresh.json"))
        assertFalse(text.contains("stale.json"), "the jar's own previous entry was kept: $text")
        // Still one entry per line with the indent the wrappers parse.
        assertEquals(2, report.readLines().count { it.startsWith("    {\"timestamp\"") })
    }

    @Test
    fun `a file deleted during sanitization is not counted as emitted`(@TempDir tmp: Path) {
        // sanitizeFile deletes a file carrying a private key; it never ships, so it must not be
        // verified or counted among the emitted files.
        val target = tmp.resolve("scan-target").also { it.toFile().mkdirs() }
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        val keyFile = results.resolve("id_rsa").toFile()
        keyFile.writeText("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
        val sanitizeYml = File(tmp.toFile(), "sanitize.yml").apply { writeText("patterns: []\n") }

        Sanitizer().sanitizeFiles(results, sanitizeYml.path, rules(target, results))

        assertFalse(keyFile.exists(), "the private-key file should have been deleted")
        val text = results.resolve("scrub-report.json").toFile().readText()
        assertFalse(text.contains("id_rsa"), "a deleted file must not be flagged: $text")
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

/**
 * The jar is the first of the three commands (instrument.yml), so it is the one that starts the
 * run's shared output clean. Each tool clears its own subfolder of results/; nothing else clears
 * the root, where the shared scrub-report.json lives.
 */
class SharedRootTest {

    @Test
    fun `the root of results is cleared, the tool subfolders are left alone`(@TempDir tmp: Path) {
        val results = tmp.resolve("results").also { it.toFile().mkdirs() }
        val out = results.resolve("depminer").also { it.toFile().mkdirs() }
        // What a pre-split run left behind: a flat SBOM and an index at the root, plus a report
        // still declaring that run clean.
        results.resolve("proj.syft.json").toFile().writeText("{}")
        results.resolve("index.json").toFile().writeText("{}")
        results.resolve("scrub-report.json").toFile().writeText("""{"flagged": []}""")
        results.resolve("syft").toFile().mkdirs()
        results.resolve("syft").resolve("keep.syft.json").toFile().writeText("{}")

        clearSharedRoot(out, results)

        assertFalse(results.resolve("proj.syft.json").toFile().exists(), "a stale SBOM shipped")
        assertFalse(results.resolve("index.json").toFile().exists(), "a stale index shipped")
        assertFalse(results.resolve("scrub-report.json").toFile().exists(), "a stale report shipped")
        // Another tool's folder is its own to clear, and so is its content.
        assertTrue(results.resolve("syft").resolve("keep.syft.json").toFile().isFile)
    }

    @Test
    fun `nothing is cleared unless the results dir sits directly inside the report dir`(@TempDir tmp: Path) {
        // The guard that keeps this from deleting files in whatever an unrelated --report-dir
        // happens to point at - a home directory, say.
        val elsewhere = tmp.resolve("elsewhere").also { it.toFile().mkdirs() }
        val out = tmp.resolve("out").also { it.toFile().mkdirs() }
        elsewhere.resolve("notes.txt").toFile().writeText("keep me")

        clearSharedRoot(out, elsewhere)
        assertTrue(elsewhere.resolve("notes.txt").toFile().isFile, "deleted an unrelated file")

        // Same dir: the standalone shape, where the report sits beside the output.
        out.resolve("scrub-report.json").toFile().writeText("{}")
        clearSharedRoot(out, out)
        assertTrue(out.resolve("scrub-report.json").toFile().isFile, "cleared its own output dir")
    }

    @Test
    fun `a target folder named no-sanitize does not switch scrubbing off`() {
        // A fail-open switch on the control that keeps a client's paths out of the results, so it
        // reads only the arguments meant for it - not the command, and not the target.
        assertTrue(sanitizeByDefault(arrayOf("extract", "no-sanitize")))
        assertTrue(sanitizeByDefault(arrayOf("extract", "/repos", "results")))
        assertFalse(sanitizeByDefault(arrayOf("extract", "/repos", "results", "no-sanitize")))
    }
}
