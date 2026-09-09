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

    /** Runs the wrapper over [target], returning its exit code; PATH is prefixed with [stubs]. */
    private fun runWrapper(stubs: File, target: File, out: File): Int {
        val here = tempDir("depminer-wrapper")
        val wrapper = File(here, "syft-wrapper.sh").also { wrapperSource.copyTo(it, overwrite = true) }
        val process = ProcessBuilder("bash", wrapper.absolutePath, target.absolutePath, out.absolutePath)
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
    fun `strips the scanned path and any url credentials out of the sbom`() {
        val stubs = tempDir("depminer-stubs")
        stubSyft(stubs)
        val target = target()
        val out = tempDir("depminer-out")

        assertEquals(0, runWrapper(stubs, target, out))

        val files = emitted(out)
        assertTrue(files.isNotEmpty(), "expected the wrapper to emit SBOMs")
        // Written on every run, so "nothing to scan" and "withheld" are told apart without the log.
        assertTrue(report(out).contains("\"withheld\""), report(out))
        files.forEach {
            val text = it.readText()
            assertTrue(!text.contains(target.absolutePath), "host path left in ${it.name}: $text")
            assertTrue(!text.contains(credential), "registry credentials left in ${it.name}: $text")
        }
    }

    /**
     * The regression this file exists for. The escaping pipeline is stubbed so that it exits 0
     * with TRUNCATED output: every rule then matches only a prefix of the host path, the scrub
     * "succeeds", and before the fix the wrapper exited 0 with the rest of the host layout in the
     * SBOM. Those bytes must not reach the output dir now — but the run still finishes normally.
     */
    @Test
    fun `withholds the sbom when the escaping pipeline silently truncates a rule`() {
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

        // The run carries on: a withheld file is not a failed project.
        assertEquals(0, runWrapper(stubs, target, out))
        assertEquals(emptyList(), emitted(out).map { it.name })
        // ...and it is recorded durably, without the leaked value being copied into the report.
        val report = report(out)
        assertTrue(report.contains("\"file\": \"proj.syft.json\""), report)
        assertTrue(report.contains("\"reason\": \"host-path-scrub-verification-failed\""), report)
        assertTrue(report.contains("\"wrapper\": \"syft\""), report)
        assertTrue(!report.contains(target.absolutePath), "the report must not repeat the leak: $report")
    }

    /**
     * A rule is anchored on a path boundary, so a SIBLING directory that merely starts with the
     * same characters is no longer rewritten — unanchored, "<target>-other" became ".-other".
     * What the anchor does not rewrite the wrapper must not ship either: the file is withheld.
     */
    @Test
    fun `withholds the sbom when a sibling directory path survives the scrub`() {
        val stubs = tempDir("depminer-stubs")
        // A directory NEXT TO the target, not under it: nothing may rewrite it, and nothing may
        // ship it either.
        stubSyft(stubs, pathExpr = "\"${'$'}(dirname \"${'$'}{target}\")-other/pkg.tgz\"")
        val target = target()
        val out = tempDir("depminer-out")

        assertEquals(0, runWrapper(stubs, target, out))
        assertEquals(emptyList(), emitted(out).map { it.name })
        assertTrue(report(out).contains("\"matchedRules\": [\"target\"]"), report(out))
    }
}
