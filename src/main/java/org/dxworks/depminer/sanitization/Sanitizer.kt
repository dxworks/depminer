package org.dxworks.depminer.sanitization

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import java.io.File
import java.nio.file.Path

private val yamlMapper = ObjectMapper(YAMLFactory()).registerModule(KotlinModule.Builder().build())

data class SanitizationPattern(
    val pattern: String,
    val replacement: String
)

data class SanitizationConfig(
    val patterns: List<SanitizationPattern> = emptyList()
)

/**
 * Main sanitization class responsible for sanitizing files based on configured patterns
 */
class Sanitizer {
    private val PRIVATE_KEY_START_REGEX = Regex("^-----BEGIN [A-Z ]+? KEY-----")

    /**
     * Sanitizes files in the results directory using patterns from the sanitization configuration file
     *
     * @param resultsPath Path to the directory containing files to sanitize
     * @param sanitizeFile Path to the sanitization configuration file
     */
    fun sanitizeFiles(resultsPath: Path, sanitizeFile: String) {
        try {
            val sanitizationConfig: SanitizationConfig = yamlMapper.readValue(File(sanitizeFile))

            println("Sanitizing files with ${sanitizationConfig.patterns.size} patterns...")

            val compiledPatterns = sanitizationConfig.patterns.mapNotNull { pattern ->
                try {
                    CompiledPattern(Regex(pattern.pattern), pattern.replacement)
                } catch (e: Exception) {
                    println("Error compiling pattern '${pattern.pattern}': ${e.message}")
                    null
                }
            }

            val startTime = System.currentTimeMillis()
            var sanitizedCount = 0

            resultsPath.toFile().listFiles()?.filter { it.isFile && it.name != "index.json" }
                ?.forEach { file ->
                    if (sanitizeFile(file, compiledPatterns)) {
                        sanitizedCount++
                    }
                }

            val duration = System.currentTimeMillis() - startTime
            println("Sanitized $sanitizedCount files in ${duration}ms")
        } catch (e: Exception) {
            println("Error reading sanitization configuration: ${e.message}")
        }
    }

    private data class CompiledPattern(
        val regex: Regex,
        val replacement: String
    )

    /**
     * Sanitizes a single file by applying patterns to its content
     *
     * @param file The file to sanitize
     * @param patterns List of compiled sanitization patterns to apply
     * @return true if the file was modified, false otherwise
     */
    private fun sanitizeFile(file: File, patterns: List<CompiledPattern>): Boolean {
        val tempFile = File("${file.absolutePath}.tmp")
        var modified = false
        var keyDetected = false

        try {
            file.bufferedReader().use { reader ->
                tempFile.bufferedWriter().use { writer ->
                    reader.lineSequence().forEach { line ->
                        if (PRIVATE_KEY_START_REGEX.containsMatchIn(line)) {
                            keyDetected = true
                            return@forEach
                        }

                        val sanitizedLine = applyPatterns(line, patterns)
                        writer.write(sanitizedLine)
                        writer.newLine()

                        if (line != sanitizedLine) {
                            modified = true
                        }
                    }
                }
            }

            if (keyDetected) {
                println("Private key detected in ${file.name}, skipping and deleting file.")
                file.delete()
                return false
            }

            if (modified) {
                tempFile.copyTo(file, overwrite = true)
                return true
            }

            return false
        } catch (e: Exception) {
            println("Error sanitizing file ${file.name}: ${e.message}")
            return false
        } finally {
            if (tempFile.exists()) {
                tempFile.delete()
            }
        }
    }

    /**
     * Applies compiled sanitization patterns to a line of text
     *
     * @param line The line to sanitize
     * @param patterns List of compiled sanitization patterns to apply
     * @return The sanitized line
     */
    private fun applyPatterns(line: String, patterns: List<CompiledPattern>): String {
        var result = line

        patterns.forEach { pattern ->
            result = pattern.regex.replace(result, pattern.replacement)
        }

        return result
    }
}