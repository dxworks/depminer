package org.dxworks.depminer

import org.apache.commons.io.FileUtils
import org.apache.commons.io.IOCase
import org.apache.commons.io.filefilter.IOFileFilter
import org.apache.commons.io.filefilter.TrueFileFilter
import org.apache.commons.io.filefilter.WildcardFileFilter
import java.io.File

/**
 * Detects projects that are on disk in an UNRESOLVED state — a manifest is present but the file
 * that actually carries the transitive tree is not. Syft and Trivy are static readers: when the
 * resolved state is missing they silently report a fraction of the real dependency set, or nothing
 * at all. Without this check that regression is invisible in the results.
 *
 * This is advisory only. It never fails the run and never changes the exit code.
 */
object ResolutionCheck {

    private val RESOLUTION_RELEVANT_FILES = listOf(
        // .NET
        "*.csproj", "*.fsproj", "*.vbproj", "*.sln", "packages.lock.json",
        // Gradle
        "build.gradle", "build.gradle.kts", "*.lockfile",
        // Maven
        "pom.xml",
    )

    /**
     * @param target the scanned tree
     * @param dirFilter the same directory filter the extraction uses, so both see the same tree
     * @param m2Repository the local Maven cache to test for warmth; null means "not present"
     */
    fun warnings(
        target: File,
        dirFilter: IOFileFilter = TrueFileFilter.INSTANCE,
        m2Repository: File? = defaultM2Repository(),
    ): List<String> {
        if (!target.isDirectory) return emptyList()

        val files = FileUtils.listFiles(
            target,
            WildcardFileFilter.builder()
                .setWildcards(RESOLUTION_RELEVANT_FILES)
                .setIoCase(IOCase.INSENSITIVE)
                .get(),
            dirFilter
        ).toList()

        val warnings = mutableListOf<String>()
        dotnetWarning(target, files)?.let { warnings.add(it) }
        gradleWarning(target, files)?.let { warnings.add(it) }
        mavenWarning(files, m2Repository)?.let { warnings.add(it) }
        return warnings
    }

    // ── .NET ─────────────────────────────────────────────────────────────
    // packages.lock.json is the ONLY file either scanner reads that carries a transitive NuGet
    // graph. project.assets.json — what a plain `dotnet restore` writes — is read by neither.
    private fun dotnetWarning(target: File, files: List<File>): String? {
        val projectFiles = files.filter { it.extension.lowercase() in setOf("csproj", "fsproj", "vbproj") }
        // A solution with no project file next to it still tells us .NET is in play.
        val projects = projectFiles.ifEmpty { files.filter { it.extension.equals("sln", ignoreCase = true) } }
        if (projects.isEmpty()) return null

        val lockDirs = files.filter { it.name.equals("packages.lock.json", ignoreCase = true) }.map { it.dirPath() }
        val unresolved = projects.filter { project -> lockDirs.none { it.startsWith(project.dirPath()) } }
        if (unresolved.isEmpty()) return null

        return message(
            stack = ".NET",
            head = "${unresolved.size} project(s) have no packages.lock.json (e.g. ${unresolved.first().describe(target)})",
            effect = "You will get direct dependencies only — roughly 10 % of the real tree " +
                "(measured on eShopOnWeb: 33 of 303 components, 0 transitive).",
            fix = "dotnet restore YourSolution.sln --use-lock-file   (a plain `dotnet restore` buys nothing: " +
                "obj/project.assets.json is read by neither scanner), then commit the packages.lock.json files."
        )
    }

    // ── Gradle ───────────────────────────────────────────────────────────
    // Trivy's only Gradle input is *.gradle.lockfile; it never reads build.gradle.
    private fun gradleWarning(target: File, files: List<File>): String? {
        val buildFiles = files.filter { it.name.equals("build.gradle", ignoreCase = true) || it.name.equals("build.gradle.kts", ignoreCase = true) }
        if (buildFiles.isEmpty()) return null

        val lockDirs = files.filter { it.isGradleLockfile() }.map { it.dirPath() }
        val unresolved = buildFiles.filter { build -> lockDirs.none { it.startsWith(build.dirPath()) } }
        if (unresolved.isEmpty()) return null

        return message(
            stack = "Gradle",
            head = "${unresolved.size} module(s) have no Gradle lock file (e.g. ${unresolved.first().describe(target)} has no *.gradle.lockfile)",
            effect = "These modules contribute nothing at all: Trivy's only Gradle input is the *.gradle.lockfile — " +
                "it never reads build.gradle. (Measured on spring-petclinic: with the lockfile Trivy reaches " +
                "201 of Black Duck's 209 rows; without it the Gradle build contributes 0.)",
            fix = "add `dependencyLocking { lockAllConfigurations() }` to build.gradle, run " +
                "`./gradlew dependencies --write-locks`, then commit the lock files."
        )
    }

    // ── Maven ────────────────────────────────────────────────────────────
    // A pom.xml alone is fine IF ~/.m2/repository is warm on the machine running the scan — that
    // cache is what makes the offline scan work. So we warn on the cache, not on the pom: warning
    // on every pom.xml would be noise for the (common) case of scanning on a build box.
    private fun mavenWarning(files: List<File>, m2Repository: File?): String? {
        val poms = files.filter { it.name.equals("pom.xml", ignoreCase = true) }
        if (poms.isEmpty()) return null
        if (m2Repository != null && m2Repository.isDirectory && !m2Repository.list().isNullOrEmpty()) return null

        return message(
            stack = "Maven",
            head = "${poms.size} pom.xml project(s) found, but the local Maven cache " +
                "(${m2Repository?.path ?: "~/.m2/repository"}) is missing or empty on this machine",
            effect = "You will get direct declarations only — the cache is what resolves the transitive tree " +
                "offline (measured on spring-petclinic: 106 components with a warm cache, 16 with an empty one).",
            fix = "run `mvn dependency:go-offline` (or a normal build) on THIS machine before scanning."
        )
    }

    // Trivy's Gradle analyzer takes any *.lockfile: gradle.lockfile, buildscript-gradle.lockfile,
    // and the files under gradle/dependency-locks/.
    private fun File.isGradleLockfile(): Boolean = name.endsWith(".lockfile", ignoreCase = true)

    // ── shared ───────────────────────────────────────────────────────────
    private fun message(stack: String, head: String, effect: String, fix: String) = buildString {
        appendLine("WARNING [$stack]: $head.")
        appendLine("  $effect")
        appendLine("  Fix: $fix")
        append("  See PREP_GUIDE.md.")
    }

    private fun File.dirPath(): String = (parentFile ?: this).absoluteFile.normalize().path + File.separator

    private fun File.describe(target: File): String =
        runCatching { this.absoluteFile.normalize().toRelativeString(target.absoluteFile.normalize()) }
            .getOrDefault(name)

    private fun defaultM2Repository(): File? =
        System.getProperty("user.home")?.let { File(it, ".m2/repository") }
}
