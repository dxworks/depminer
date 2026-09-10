package org.dxworks.depminer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.commons.io.FileUtils
import org.apache.commons.io.IOCase
import org.apache.commons.io.filefilter.IOFileFilter
import org.apache.commons.io.filefilter.NotFileFilter
import org.apache.commons.io.filefilter.WildcardFileFilter
import org.dxworks.argumenthor.Argumenthor
import org.dxworks.argumenthor.config.ArgumenthorConfiguration
import org.dxworks.argumenthor.config.fields.impl.StringField
import org.dxworks.argumenthor.config.sources.impl.ArgsSource
import org.dxworks.argumenthor.config.sources.impl.EnvSource
import org.dxworks.depminer.sanitization.Sanitizer
import org.dxworks.depminer.sanitization.buildHostRules
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess

val yamlMapper = ObjectMapper(YAMLFactory()).also { it.registerModule(KotlinModule.Builder().build()) }
val jsonMapper = jacksonObjectMapper()

const val IGNORE_FILE = "ignore.file"
const val DEPMINER_FILE = "depminer.file"
const val SANITIZE_FILE = "sanitize.file"

class ExcludedPaths(
    var files: List<String>?,
    var dirs: List<String>?
)

fun main(args: Array<String>) {

    val argumenthor = Argumenthor(
        ArgumenthorConfiguration(
            StringField(IGNORE_FILE, ".ignore.yml"),
            StringField(DEPMINER_FILE, "depminer.yml"),
            StringField(SANITIZE_FILE, "sanitize.yml"),
        ).also {
            it.addSource(ArgsSource().also { it.args = args })
            it.addSource(EnvSource("depminer"))
        })

    if (args.isEmpty()) {
        throw IllegalArgumentException("Bad arguments! Please provide the command you wish to run: extract or construct")
    }

    val command = args.first()
    if (command != "extract" && command != "construct") {
        println("Please provide as a first argument the command you wish to run: extract or construct")
        exitProcess(1)
    }

    println("Starting DepMi (Dependency Miner)\n")

    if (args.size < 2) {
        println("$command command requires at least 1 parameter: the target folder to analyse")
        exitProcess(1)
    }

    val targetPath = Paths.get(args[1])
    if (!Files.exists(targetPath)) {
        println("Target path ${targetPath.toFile().absolutePath} does not exist! Please specify a valid folder!")
        exitProcess(1)
    }
    // Positional args only; the flags (no-sanitize, --report-dir=...) may sit anywhere after them.
    // A single leading "-" is enough: argumenthor's ArgsSource takes its options as -name=value
    // (one dash), so "--" alone would let -sanitize.file=x.yml through as the results dir - and
    // the results dir is deleted recursively below.
    val depminerResultsPath =
        args.drop(2).firstOrNull { !it.startsWith("-") && !it.equals("no-sanitize", ignoreCase = true) }
            ?.let { Paths.get(it) } ?: Paths.get("results")
    val scrubReportPath = reportDirArg(args)?.let { Paths.get(it) } ?: depminerResultsPath

    when (command) {
        "extract" -> {
            if (Files.exists(depminerResultsPath)) {
                depminerResultsPath.toFile().deleteRecursively()
            }
            depminerResultsPath.toFile().mkdirs()
            val sanitize = sanitizeByDefault(args)
            scrubReportPath.toFile().mkdirs()
            clearSharedRoot(depminerResultsPath, scrubReportPath)
            extract(argumenthor, targetPath, depminerResultsPath, scrubReportPath, sanitize)
        }

        "construct" -> {
            if (targetPath.toFile().absolutePath == depminerResultsPath.toFile().absolutePath) {
                println("Target and Results folder cannot be the same!")
                exitProcess(1)
            }
            val indexJson = targetPath.resolve("index.json")
            if (!Files.exists(indexJson)) {
                println("Index.json file not found at ${indexJson.toFile().absolutePath}. Please specify a target that contains such a file!")
                exitProcess(1)
            }
            val filesMap: Map<String, String> = jsonMapper.readValue(indexJson.toFile())
            filesMap.forEach { entry ->
                targetPath.resolve(entry.key).toFile()
                    .copyTo(depminerResultsPath.resolve(Paths.get(entry.value)).toFile())
            }
            println("Finished constructing the folder structure at ${depminerResultsPath.toFile().absolutePath}")
        }
    }

}

// Skips the command and the target, so a folder that happens to be named "no-sanitize" cannot
// switch host-path scrubbing off. This is a fail-OPEN switch on the control that exists to keep
// a client's paths out of the results, so it only ever reads the arguments meant for it.
/**
 * Clears the files sitting at the root of the shared results dir, the jar's own output folder
 * being one level down inside it.
 *
 * Each of the three tools clears its own subfolder, and nothing else clears this level - so
 * without this, whatever an earlier run left at the root would ship untouched: a flat SBOM from
 * before the per-tool split, or a stale scrub-report.json still declaring that run clean. Before
 * the split the jar deleted results/ wholesale and this came for free; it is the same job, and
 * the jar still holds it because instrument.yml runs it first.
 *
 * Only regular files, so the tool subfolders are left to their owners. And only when the results
 * dir is a DIRECT CHILD of the report dir, which is what the instrument layout looks like: it is
 * the difference between clearing results/ and deleting files in whatever an unrelated
 * --report-dir happens to point at.
 */
internal fun clearSharedRoot(resultsPath: Path, reportDir: Path) {
    val results = resultsPath.toAbsolutePath().normalize()
    val report = reportDir.toAbsolutePath().normalize()
    if (results == report || results.parent != report) return
    report.toFile().listFiles()?.filter { it.isFile }?.forEach { it.delete() }
}

internal fun sanitizeByDefault(args: Array<String>): Boolean =
    args.drop(2).none { it.equals("no-sanitize", ignoreCase = true) }

/**
 * `--report-dir=<path>` - where scrub-report.json goes, when that is not the results dir.
 *
 * Each tool now writes into its own subfolder (results/depminer, results/syft, results/trivy)
 * but the scrub report stays ONE file at the root of results/, so a consumer has a single place
 * to look to find out whether anything in the run shipped unclean. The wrappers take the same
 * path as their third argument; see instrument.yml.
 */
private fun reportDirArg(args: Array<String>): String? =
    args.firstOrNull { it.startsWith("--report-dir=") }?.substringAfter("=")?.takeIf { it.isNotBlank() }

private fun extract(
    argumenthor: Argumenthor,
    target: Path,
    depminerResultsPath: Path,
    scrubReportPath: Path,
    sanitize: Boolean
) {

    val depminerFile = argumenthor.getValue<String>(DEPMINER_FILE).also { println("Reading ${File(it).absolutePath}") }
    val languageMap: Map<String, List<String>> = yamlMapper.readValue(File(depminerFile))
    val fileNames = languageMap.values.toList().flatten()
    val ignoreFile =
        argumenthor.getValue<String>(IGNORE_FILE).also { println("Ignoring all files from ${File(it).absolutePath}") }

    val blacklistedGlobs: ExcludedPaths = yamlMapper.readValue(File(ignoreFile))

    val dirFilter = NotFileFilter(WildcardFileFilter.builder().setWildcards(blacklistedGlobs.dirs.orEmpty()).get())

    println("Reading Files...")

    val packageFiles =
        FileUtils.listFiles(
            target.toFile(),
            WildcardFileFilter.builder().setWildcards(fileNames).setIoCase(IOCase.INSENSITIVE).get().and(
                NotFileFilter(
                    WildcardFileFilter.builder()
                        .setWildcards(blacklistedGlobs.files.orEmpty())
                        .setIoCase(IOCase.INSENSITIVE)
                        .get()
                )
            ),
            dirFilter
        )

    val resultsMap = mutableMapOf<String, String>()

    println("Writing Results...")

    packageFiles.groupBy { it.name.lowercase() }.forEach { entry ->
        if (entry.value.size > 1) {
            entry.value.forEachIndexed { index, file: File ->
                val newName =
                    "${file.nameWithoutExtension}-$index${file.extension.let { if (it.isNotEmpty()) ".$it" else "" }}"
                file.copyTo(depminerResultsPath.resolve(newName).toFile())
                resultsMap[newName] = file.relativeTo(target.toFile()).normalize().toString()
            }
        } else {
            entry.value.firstOrNull()?.also {
                it.copyTo(depminerResultsPath.resolve(it.name).toFile())
                resultsMap[it.name] = it.relativeTo(target.toFile()).normalize().toString()
            }
        }
    }

    jacksonObjectMapper().writerWithDefaultPrettyPrinter()
        .writeValue(depminerResultsPath.resolve("index.json").toFile(), resultsMap)

    if (sanitize) {
        val sanitizeFile = argumenthor.getValue<String>(SANITIZE_FILE)
        if (sanitizeFile != null) {
            println("Sanitizing files using patterns from ${File(sanitizeFile).absolutePath}")
            // The copied files carry the host's layout - project.assets.json holds the absolute
            // path of every csproj, the NuGet package folder and the restore config - and
            // sanitize.yml has credential patterns only. Scrub those paths too, then check the
            // emitted bytes and record anything still carrying them in scrub-report.json.
            Sanitizer().sanitizeFiles(
                depminerResultsPath, sanitizeFile,
                buildHostRules(target, listOf(depminerResultsPath, scrubReportPath), System.getenv("HOME")),
                scrubReportPath
            )
        } else {
            println("Sanitization file path is null, skipping sanitization")
        }
    }

    println("\nDepMi (Dependency Miner) finished successfully! Please view your results at ${depminerResultsPath.toFile().absolutePath}")

    reportResolutionState(target.toFile(), dirFilter)
}

/**
 * Advisory only: prints a warning for every stack found in an unresolved state. Never fails the
 * run, never changes the exit code, never changes what is extracted.
 */
private fun reportResolutionState(target: File, dirFilter: IOFileFilter) {
    val warnings = runCatching { ResolutionCheck.warnings(target, dirFilter) }.getOrElse { emptyList() }
    if (warnings.isEmpty()) return

    println("\n─── Resolution check ───────────────────────────────────────────────")
    warnings.forEach { println("$it\n") }
    println("These stacks will be under-reported unless prepared. This is a warning, not an error.")
}
