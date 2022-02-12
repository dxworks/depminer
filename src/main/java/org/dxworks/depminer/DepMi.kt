package org.dxworks.depminer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.commons.io.FileUtils
import org.apache.commons.io.filefilter.NotFileFilter
import org.apache.commons.io.filefilter.WildcardFileFilter
import org.dxworks.argumenthor.Argumenthor
import org.dxworks.argumenthor.config.ArgumenthorConfiguration
import org.dxworks.argumenthor.config.fields.impl.StringField
import org.dxworks.argumenthor.config.sources.impl.ArgsSource
import org.dxworks.argumenthor.config.sources.impl.EnvSource
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess

val yamlMapper = ObjectMapper(YAMLFactory()).also { it.registerModule(KotlinModule()) }
val jsonMapper = jacksonObjectMapper()

const val IGNORE_FILE = "ignore.file"
const val DEPMINER_FILE = "depminer.file"
const val DEPMINER_TARGET = "depminer.target"
const val DEPMINER_RESULTS = "depminer.results"

fun main(args: Array<String>) {

    val argumenthor = Argumenthor(ArgumenthorConfiguration(
        StringField(IGNORE_FILE, ".ignore.yml"),
        StringField(DEPMINER_FILE, "depminer.yml"),
        StringField(DEPMINER_TARGET, null),
        StringField(DEPMINER_RESULTS, "results")
    ).also {
        it.addSource(ArgsSource().also { it.args = args })
        it.addSource(EnvSource("depminer"))
    })

    if (args.isEmpty()) {
        throw IllegalArgumentException("Bad arguments! Please provide the command you wish to run: extract or construct")
    }

    val command = args.first()

    println("Starting DepMi (Dependency Miner)\n")

    when (command) {
        "extract" -> {
            val target = argumenthor.getValue<String>(DEPMINER_TARGET)
            if (target == null) {
                println("Please specify the target folder: -depminerTarget=<path/to/taraget>")
                exitProcess(1)
            }

            var targetPath = Paths.get(target)

            val depminerResults = argumenthor.getValue<String>(DEPMINER_RESULTS)
            var depminerResultsPath = Paths.get(depminerResults)

            if (Files.exists(depminerResultsPath)) {
                depminerResultsPath.toFile().deleteRecursively()
            }
            depminerResultsPath.toFile().mkdirs()
            extract(argumenthor, targetPath, depminerResultsPath)
        }
        "construct" -> {
            if (args.size > 3 || args.size < 2) {
                println("construct command can get 2 parameters: the target folder (containing the index.json) and the results folder to construct the folder to (by default the current working directory)")
                exitProcess(1)
            }
            val targetPath = Paths.get(args[1])
            val depminerResultsPath = if (args.size == 3) Paths.get(args[2]) else Paths.get(".")

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

private fun extract(
    argumenthor: Argumenthor,
    target: Path,
    depminerResultsPath: Path,
) {

    val depminerFile = argumenthor.getValue<String>(DEPMINER_FILE).also { println("Reading $it") }
    val languageMap: Map<String, List<String>> = yamlMapper.readValue(File(depminerFile))
    val fileNames = languageMap.values.toList().flatten()
    val ignoreFile = argumenthor.getValue<String>(IGNORE_FILE).also { println("Ignoring all files from $it") }
    val blacklistedGlobs: ExcludedPaths = yamlMapper.readValue(File(ignoreFile))

    println("Reading Files...")

    val packageFiles =
        FileUtils.listFiles(
            target.toFile(), WildcardFileFilter(fileNames).and(
                NotFileFilter(
                    WildcardFileFilter(
                        blacklistedGlobs.files.orEmpty()
                    )
                )
            ), NotFileFilter(WildcardFileFilter(blacklistedGlobs.dirs.orEmpty()))
        )

    val resultsMap = mutableMapOf<String, String>()

    println("Writing Results...")

    packageFiles.groupBy { it.name }.forEach { entry ->
        if (entry.value.size > 1) {
            entry.value.forEachIndexed { index, file: File ->
                val newName =
                    "${file.nameWithoutExtension}-$index${file.extension.let { if (it.isNotEmpty()) ".$it" else "" }}"
                file.copyTo(depminerResultsPath.resolve(newName).toFile())
                resultsMap[newName] = file.relativeTo(target.toFile()).toString()
            }
        } else {
            entry.value.firstOrNull()?.also {
                it.copyTo(depminerResultsPath.resolve(it.name).toFile())
                resultsMap[it.name] = it.relativeTo(target.toFile()).toString()
            }
        }
    }

    jacksonObjectMapper().writerWithDefaultPrettyPrinter()
        .writeValue(depminerResultsPath.resolve("index.json").toFile(), resultsMap)

    println("\nDepMi (Dependency Miner) finished successfully! Please view your results in the ./results directory")
}

fun getFileSpecsContent(): Map<String, List<String>> {
    val path = Paths.get("mining-specs.yml")

    return yamlMapper.readValue(path.toFile())
}

class ExcludedPaths(
    var files: List<String>?,
    var dirs: List<String>?
)
