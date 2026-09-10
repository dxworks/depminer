package org.dxworks.depminer

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The SBOMs are the only artefacts that leave the client's machine, so bin/syft-wrapper.sh
 * rewrites the host paths out of them. Every step of that scrub is a `sed` pipeline, and each one
 * can go wrong while still exiting 0 — which is how the wrapper came to print ">> syft done",
 * exit 0, and ship three SBOMs with the host layout still in them. These tests therefore drive the
 * real wrapper with a stub scanner and assert on the EMITTED BYTES, never on the exit code.
 *
 * The wrapper is copied into a temp dir first: it resolves its scanner relative to its own
 * location, so from there it falls back to the stub `syft` this test puts on PATH.
 */
class SyftWrapperScrubTest {

    private val wrapperSource = File("bin/syft-wrapper.sh")

    private val credential = "glpat-NOTAREALTOKEN"

    private fun tempDir(prefix: String): File =
        Files.createTempDirectory(prefix).toFile().also { it.deleteOnExit() }

    private fun script(dir: File, name: String, body: String): File =
        File(dir, name).apply {
            writeText(body)
            setExecutable(true)
        }

    /**
     * A stub Syft: writes, to every -o destination, a document quoting [pathExpr] — by default the
     * scanned path — and a credentialed registry URL.
     */
    private fun stubSyft(dir: File, pathExpr: String = "\"${'$'}{target}\""): File = script(
        dir, "syft",
        """
        #!/bin/sh
        target=""
        outs=""
        while [ $# -gt 0 ]; do
          case "$1" in
            dir:*) target="${'$'}{1#dir:}" ;;
            -o)    outs="${'$'}outs $2"; shift ;;
          esac
          shift
        done
        for o in ${'$'}outs; do
          printf '{"source":{"metadata":{"path":"%s"}},"resolved":"https://bot:$credential@nexus.corp.internal/repo/x.tgz"}' \
            $pathExpr > "${'$'}{o#*=}"
        done
        """.trimIndent()
    )

    /**
     * Runs the wrapper over [target], returning its exit code; PATH is prefixed with [stubs].
     * [reportDir] is the wrapper's optional third argument — where the shared scrub-report.json
     * goes when the three tools write into separate subfolders of results/.
     */
    private fun runWrapper(stubs: File, target: File, out: File, reportDir: File? = null): Int {
        val here = tempDir("depminer-wrapper")
        val wrapper = File(here, "syft-wrapper.sh").also { wrapperSource.copyTo(it, overwrite = true) }
        val argv = listOfNotNull(
            "bash", wrapper.absolutePath, target.absolutePath, out.absolutePath, reportDir?.absolutePath
        )
        val process = ProcessBuilder(argv)
            .redirectErrorStream(true)
            .also { it.environment()["PATH"] = stubs.absolutePath + File.pathSeparator + System.getenv("PATH") }
            .start()
        process.inputStream.bufferedReader().readText()
        return process.waitFor()
    }

    private fun target(): File = tempDir("depminer-target").also { File(it, "proj").mkdirs() }

    /** The SBOMs: everything the wrapper emitted except its own report. */
    private fun emitted(out: File): List<File> =
        out.listFiles().orEmpty().filter { it.isFile && it.name != "scrub-report.json" }

    private fun report(out: File): String = File(out, "scrub-report.json").readText()

    @Test
    fun `clearing the output dir removes only this wrapper's own leftovers`() {
        // <output-dir> is an argument and the wrapper is documented as runnable standalone, so
        // clearing it wholesale would empty whatever the caller passed - `syft-wrapper.sh /repos .`
        // would take the working directory with it.
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        val target = target()
        val out = tempDir("depminer-out")
        File(out, "gone.syft.json").writeText("{}")          // last run's, for a repo since removed
        File(out, "my-notes.txt").writeText("keep me")       // not ours
        File(out, "important.json").writeText("keep me")     // not one of our shapes
        File(out, "other.trivy.cdx.json").writeText("{}")    // the other wrapper's
        File(out, "sub").mkdirs()

        assertEquals(0, runWrapper(stubs, target, out))

        assertTrue(!File(out, "gone.syft.json").exists(), "this wrapper's leftover survived")
        assertTrue(File(out, "my-notes.txt").exists(), "deleted an unrelated file")
        assertTrue(File(out, "important.json").exists(), "deleted an unrelated file")
        assertTrue(File(out, "other.trivy.cdx.json").exists(), "deleted the other wrapper's output")
        assertTrue(File(out, "sub").isDirectory, "deleted a subdirectory")
    }

    @Test
    fun `the report goes to the shared dir, the sboms to this tool's own subfolder`() {
        // instrument.yml gives each tool its own subfolder of results/ and passes results/ itself
        // as the third argument, so that the one scrub report is shared by all three.
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        val target = target()
        val results = tempDir("depminer-results")
        val out = File(results, "syft")

        assertEquals(0, runWrapper(stubs, target, out, results))

        assertTrue(File(results, "scrub-report.json").isFile, "the report is not at the shared root")
        assertTrue(!File(out, "scrub-report.json").exists(), "the report was also left in the subfolder")
        assertTrue(emitted(out).any { it.name == "proj.syft.json" }, emitted(out).map { it.name }.toString())
        assertTrue(
            results.listFiles().orEmpty().none { it.isFile && it.name.endsWith(".json") && it.name != "scrub-report.json" },
            "an SBOM was left at the root of results/"
        )
    }

    @Test
    fun `clears its own output dir but keeps the entries the other tools recorded`() {
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        val target = target()
        val results = tempDir("depminer-results")
        val out = File(results, "syft").also { it.mkdirs() }
        // Left over from an earlier run: a repo that has since been removed from the target.
        File(out, "gone.syft.json").writeText("{}")
        // The jar runs first and has already recorded a finding of its own into the shared report.
        File(results, "scrub-report.json").writeText(
            """
            {
              "schemaVersion": 1,
              "flagged": [
                {"timestamp": "2026-01-01T00:00:00Z", "wrapper": "depminer", "project": "p", "file": "project.assets.json", "reason": "emitted-despite-failed-scrub-verification", "matchedRules": ["home"], "matchCount": 1}
              ]
            }
            """.trimIndent()
        )

        assertEquals(0, runWrapper(stubs, target, out, results))

        assertTrue(!File(out, "gone.syft.json").exists(), "last run's SBOM survived into this one")
        val report = File(results, "scrub-report.json").readText()
        assertTrue(report.contains("project.assets.json"), "the jar's entry was dropped: $report")
    }

    @Test
    fun `strips the scanned path and any url credentials out of the sbom`() {
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        val target = target()
        val out = tempDir("depminer-out")

        assertEquals(0, runWrapper(stubs, target, out))

        val files = emitted(out)
        assertTrue(files.isNotEmpty(), "expected the wrapper to emit SBOMs")
        // Written on every run, so "nothing to scan" and "withheld" are told apart without the log.
        assertTrue(report(out).contains("\"flagged\""), report(out))
        files.forEach {
            val text = it.readText()
            assertTrue(!text.contains(target.absolutePath), "host path left in ${it.name}: $text")
            assertTrue(!text.contains(credential), "registry credentials left in ${it.name}: $text")
        }
    }

    /**
     * The regression this file exists for. The escaping pipeline is stubbed so that it exits 0
     * with TRUNCATED output: every rule then matches only a prefix of the host path, so the scrub
     * "succeeds" while the host layout survives in the SBOM — and before, NOTHING said so. The
     * file is still emitted (nothing is ever held back), so what is asserted here is that the
     * failure is recorded: the wrapper is no longer silent about it.
     */
    @Test
    fun `records the sbom when the escaping pipeline silently truncates a rule`() {
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        script(
            stubs, "sed",
            """
            #!/bin/sh
            pat='\\&/g'
            case "$1" in
              *"${'$'}pat") /usr/bin/sed "$@" | /usr/bin/head -c 20 ;;
              *)            exec /usr/bin/sed "$@" ;;
            esac
            """.trimIndent()
        )
        val target = target()
        val out = tempDir("depminer-out")

        // The run carries on, and nothing is held back: every file the scanner produced is emitted.
        assertEquals(0, runWrapper(stubs, target, out))
        assertTrue(emitted(out).any { it.name == "proj.syft.json" }, emitted(out).map { it.name }.toString())
        // The report is the only record that what shipped is not clean - and it must not itself
        // repeat the value that leaked.
        val report = report(out)
        assertTrue(report.contains("\"file\": \"proj.syft.json\""), report)
        assertTrue(report.contains("\"reason\": \"emitted-despite-failed-scrub-verification\""), report)
        assertTrue(report.contains("\"wrapper\": \"syft\""), report)
        assertTrue(!report.contains(target.absolutePath), "the report must not repeat the leak: $report")
    }

    /**
     * A rule is anchored on a path boundary, so a SIBLING directory that merely starts with the
     * same characters is no longer rewritten — unanchored, "<target>-other" became ".-other".
     * What the anchor does not rewrite still ships, so it has to be reported.
     */
    @Test
    fun `records the sbom when a sibling directory path survives the scrub`() {
        val stubs = tempDir("depminer-stubs")
        // A directory NEXT TO the target, not under it: nothing may rewrite it, and nothing may
        // ship it either.
        stubSyft(stubs, pathExpr = "\"${'$'}(dirname \"${'$'}{target}\")-other/pkg.tgz\"")
        val target = target()
        val out = tempDir("depminer-out")

        assertEquals(0, runWrapper(stubs, target, out))
        assertTrue(emitted(out).any { it.name == "proj.syft.json" }, emitted(out).map { it.name }.toString())
        assertTrue(report(out).contains("\"matchedRules\": [\"target\"]"), report(out))
        assertTrue(!report(out).contains(target.absolutePath), "the report must not repeat the leak")
    }
}
