package org.dxworks.dependencyminer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

fun main(args: Array<String>) {

    if (args.size != 1) {
        throw IllegalArgumentException("Bad arguments! Please provide only one argument, namely the path to the folder containing the source code.")
    }

    val dependencyFile = getFileSpecsContent()
    val fileNames = listOf(dependencyFile.java, dependencyFile.javascript, dependencyFile.php, dependencyFile.python, dependencyFile.ruby).flatten()

    val baseFolderArg = args[0]
    val baseFolder = File(baseFolderArg)

    println("Starting DepMi (Dependency Miner)\n")
    println("Reading Files...")

    val packageFiles = baseFolder.walkTopDown()
        .filter { it.isFile }
        .filterNot { it.path.contains("node_modules") }
        .filter { fileNames.contains(it.name) }
        .toList()

    if (Files.exists(Path.of("results"))) {
        File("results").deleteRecursively()
    }

    val resultsPath = Path.of("results","filesMap")
    resultsPath.toFile().mkdirs()

    var counter = 0
    val resultsMap = mutableMapOf<String, String>()

    println("Writing Results...")

    packageFiles.forEach {
        it.copyTo(File("results/" + counter + " - " + it.name))
        resultsMap[counter.toString() + " - " + it.name] = it.relativeTo(baseFolder).toString()
        counter++
    }

    jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValue(Path.of("results/filesMap", "files-map.json").toFile(), resultsMap)

    println("\nDepMi (Dependency Miner) finished successfully! Please view your results in the ./results directory")
}

fun getFileSpecsContent(): DependencyFile {
    val path = Paths.get("mining-specs.yml")
    val mapper = ObjectMapper(YAMLFactory())
    mapper.registerModule(KotlinModule())

    return mapper.readValue(path.toFile(), DependencyFile::class.java)
}