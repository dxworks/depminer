package org.dxworks.depminer.sanitization

import java.io.File
import java.nio.file.Path
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Host-path scrubbing for the files the jar copies out of the scanned tree.
 *
 * The wrappers (bin/syft-wrapper.sh, bin/trivy-wrapper.sh) already do this for the SBOMs
 * they emit. The files copied here — package manifests, lockfiles and NuGet's
 * `project.assets.json` above all — went out untouched: sanitize.yml carries credential
 * patterns only, so `/Users/<someone>/.nuget/packages/`, the absolute path of every
 * .csproj and the restore config path all shipped verbatim, with no warning.
 *
 * `project.assets.json` is the one that matters. On a client it routinely carries the
 * private feed URLs of their internal Artifactory or Azure Artifacts, and every internal
 * project name in the tree.
 *
 * Rules are LITERAL strings, not regexes: the paths come from the environment and would
 * otherwise have to be regex-escaped, which is one more thing to get wrong. Longest first,
 * because the results dir may sit under the target, which may sit under HOME.
 */
data class HostRule(val cls: String, val literal: String, val replacement: String)

/** A file that still carried host data after scrubbing. It is emitted anyway; see [ScrubReport]. */
data class Flagged(
    val file: String,
    val project: String,
    val matchedRules: List<String>,
    val matchCount: Int
)

/** `://user:token@host` in a lockfile's resolved URL. A fixed rule, nothing to mis-escape. */
private val URL_USERINFO = Regex("://[^/\"\\s]*@")

fun buildHostRules(target: Path, outPaths: List<Path>, home: String?): List<HostRule> {
    val rules = mutableListOf<HostRule>()
    fun add(cls: String, dir: File?, replacement: String) {
        if (dir == null) return
        // Only absolute paths: a relative one cannot leak a host layout, and rewriting it
        // would corrupt unrelated text.
        val path = dir.path.trimEnd('/')
        if (path.length > 1 && path.startsWith("/")) rules.add(HostRule(cls, path, replacement))
    }
    add("target", target.toFile(), ".")
    add("target", runCatching { target.toRealPath().toFile() }.getOrNull(), ".")
    // The results dir AND the dir holding scrub-report.json, which since the per-tool split is
    // its parent: results/depminer is rewritten before results/, because the rules are applied
    // longest first and the shorter one would otherwise cut the longer one in half.
    outPaths.forEach {
        add("out", it.toFile(), ".")
        add("out", runCatching { it.toRealPath().toFile() }.getOrNull(), ".")
    }
    if (!home.isNullOrBlank()) add("home", File(home), "~")
    return rules.distinctBy { it.literal }.sortedByDescending { it.literal.length }
}

/** Single-results-dir form, for callers that do not split the report out. */
fun buildHostRules(target: Path, resultsPath: Path, home: String?): List<HostRule> =
    buildHostRules(target, listOf(resultsPath), home)

fun scrubLine(line: String, rules: List<HostRule>): String {
    var out = line
    for (r in rules) out = out.replace(r.literal, r.replacement)
    return URL_USERINFO.replace(out, "://")
}

/**
 * What is left in the emitted bytes. The scrub is not trusted to have worked: a rule that
 * matched only part of a path leaves the rest of the host layout in place while every call
 * still succeeds, so the file is read back and checked against the literals themselves.
 */
fun verifyScrubbed(file: File, rules: List<HostRule>): Flagged? {
    val classes = LinkedHashSet<String>()
    var count = 0
    val text = runCatching { file.readText() }.getOrElse {
        // Unverifiable is treated exactly like unclean.
        return Flagged(file.name, "", listOf("unverifiable"), 1)
    }
    for (r in rules) {
        val n = text.split(r.literal).size - 1
        if (n > 0) {
            classes.add(r.cls)
            count += n
        }
    }
    URL_USERINFO.find(text)?.let {
        classes.add("url-userinfo")
        count += 1
    }
    return if (count == 0) null else Flagged(file.name, "", classes.toList(), count)
}

/**
 * `results/scrub-report.json`, in the shape the wrappers write and append to: they parse
 * back any entry sitting on its own line with a four-space indent, so the jar's entries
 * survive into the report the wrappers finish. Written on EVERY run — with an empty list
 * when everything verified — so "nothing was scanned" and "this file shipped with host
 * data in it" can be told apart without reading the log.
 *
 * The leaked value is never written here: only which rule class matched, and how often.
 */
object ScrubReport {
    private val TS: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

    /** The shape both sides read back: one entry per line, four-space indent, optional comma. */
    private val ENTRY = Regex("""^ {4}(\{"timestamp".*\}),?$""")

    fun write(reportDir: Path, flagged: List<Flagged>) {
        val report = reportDir.resolve("scrub-report.json").toFile()
        val now = TS.format(Instant.now())
        val own = flagged.map { f ->
            val rules = f.matchedRules.joinToString(", ") { "\"$it\"" }
            """{"timestamp": "$now", "wrapper": "depminer", "project": "${esc(f.project)}", """ +
                """"file": "${esc(f.file)}", "reason": "emitted-despite-failed-scrub-verification", """ +
                """"matchedRules": [$rules], "matchCount": ${f.matchCount}}"""
        }
        // The wrappers accumulate into this one file (see _report_write in bin/syft-wrapper.sh),
        // so overwriting it would silently drop whatever they had already recorded. The jar
        // normally runs first and finds nothing, but it is also runnable on its own against a
        // populated results dir. Entries from the other producers are carried over verbatim; the
        // jar's own previous entries are not, so a rerun restates this run rather than stacking
        // onto the last one.
        val carried = readEntries(report).filterNot { it.contains(""""wrapper": "depminer"""") }
        val entries = (carried + own).joinToString(",\n") { "    $it" }
        report.writeText("{\n  \"schemaVersion\": 1,\n  \"flagged\": [\n$entries\n  ]\n}\n")
    }

    private fun readEntries(report: File): List<String> = runCatching {
        if (!report.isFile) return emptyList()
        report.readLines().mapNotNull { ENTRY.find(it)?.groupValues?.get(1) }
    }.getOrElse { emptyList() }

    private fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
}
