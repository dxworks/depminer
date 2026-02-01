package org.dxworks.depminer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.apache.commons.io.FileUtils
import org.apache.commons.io.IOCase
import org.apache.commons.io.filefilter.NotFileFilter
import org.apache.commons.io.filefilter.WildcardFileFilter
import org.dxworks.argumenthor.Argumenthor
import org.dxworks.argumenthor.config.ArgumenthorConfiguration
import org.dxworks.argumenthor.config.fields.impl.StringField
import org.dxworks.argumenthor.config.sources.impl.ArgsSource
import org.dxworks.argumenthor.config.sources.impl.EnvSource
import org.dxworks.depminer.sanitization.Sanitizer
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess

val yamlMapper = ObjectMapper(YAMLFactory()).registerKotlinModule()
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
    val depminerResultsPath = if (args.size >= 3) Paths.get(args[2]) else Paths.get("results")

    when (command) {
        "extract" -> {
            if (Files.exists(depminerResultsPath)) {
                depminerResultsPath.toFile().deleteRecursively()
            }
            depminerResultsPath.toFile().mkdirs()
            val sanitize = sanitizeByDefault(args)
            extract(argumenthor, targetPath, depminerResultsPath, sanitize)
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

private fun sanitizeByDefault(args: Array<String>): Boolean = !(args.size >= 4 && args[3].equals("no-sanitize", ignoreCase = true))

private fun extract(
    argumenthor: Argumenthor,
    target: Path,
    depminerResultsPath: Path,
    sanitize: Boolean
) {

    val depminerFile = argumenthor.getValue<String>(DEPMINER_FILE).also { println("Reading ${File(it).absolutePath}") }
    val languageMap: Map<String, List<String>> = yamlMapper.readValue(File(depminerFile))
    val fileNames = languageMap.values.toList().flatten()
    val ignoreFile =
        argumenthor.getValue<String>(IGNORE_FILE).also { println("Ignoring all files from ${File(it).absolutePath}") }

    val blacklistedGlobs: ExcludedPaths = yamlMapper.readValue(File(ignoreFile))

    println("Reading Files...")

    val packageFiles =
        FileUtils.listFiles(
            target.toFile(), WildcardFileFilter(fileNames, IOCase.INSENSITIVE).and(
                NotFileFilter(
                    WildcardFileFilter(
                        blacklistedGlobs.files.orEmpty()
                    )
                )
            ), NotFileFilter(WildcardFileFilter(blacklistedGlobs.dirs.orEmpty()))
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
            Sanitizer().sanitizeFiles(depminerResultsPath, sanitizeFile)
        } else {
            println("Sanitization file path is null, skipping sanitization")
        }
    }

    println("\nDepMi (Dependency Miner) finished successfully! Please view your results at ${depminerResultsPath.toFile().absolutePath}")
}
