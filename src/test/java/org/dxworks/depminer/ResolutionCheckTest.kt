package org.dxworks.depminer

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ResolutionCheckTest {

    private fun tree(vararg paths: String): File {
        val root = Files.createTempDirectory("depminer-resolution-check").toFile()
        root.deleteOnExit()
        paths.forEach { path ->
            val file = File(root, path)
            file.parentFile.mkdirs()
            file.writeText("")
        }
        return root
    }

    private fun warningFor(stack: String, root: File, m2: File? = null): String? =
        ResolutionCheck.warnings(root, m2Repository = m2).firstOrNull { it.startsWith("WARNING [$stack]") }

    // ── .NET ─────────────────────────────────────────────────────────────

    @Test
    fun `warns when a dotnet project has no packages lock json`() {
        val warning = assertNotNull(warningFor(".NET", tree("src/Web/Web.csproj", "eShopOnWeb.sln")), "expected a .NET warning")
        assertTrue(warning.contains("1 project(s) have no packages.lock.json"), warning)
        assertTrue(warning.contains("src/Web/Web.csproj".replace("/", File.separator)), warning)
        assertTrue(warning.contains("dotnet restore YourSolution.sln --use-lock-file"), warning)
        assertTrue(warning.contains("10 %"), warning)
    }

    @Test
    fun `does not warn when packages lock json is present`() {
        val root = tree("src/Web/Web.csproj", "src/Web/packages.lock.json", "eShopOnWeb.sln")
        assertEquals(null, warningFor(".NET", root))
    }

    @Test
    fun `warns only for the dotnet projects that are missing a lock file`() {
        val root = tree(
            "src/Web/Web.csproj", "src/Web/packages.lock.json",
            "src/Api/Api.csproj",
            "src/Core/Core.fsproj",
        )
        val warning = assertNotNull(warningFor(".NET", root))
        assertTrue(warning.contains("2 project(s)"), warning)
    }

    @Test
    fun `does not warn for a dotnet solution whose projects all have lock files`() {
        val root = tree("App.sln", "src/A/A.csproj", "src/A/packages.lock.json")
        assertEquals(null, warningFor(".NET", root))
    }

    // ── Gradle ───────────────────────────────────────────────────────────

    @Test
    fun `warns when a gradle module has no lockfile`() {
        val warning = assertNotNull(warningFor("Gradle", tree("build.gradle", "settings.gradle")), "expected a Gradle warning")
        assertTrue(warning.contains("1 module(s) have no Gradle lock file"), warning)
        assertTrue(warning.contains("--write-locks"), warning)
        assertTrue(warning.contains("never reads build.gradle"), warning)
    }

    @Test
    fun `does not warn when a gradle lockfile is present`() {
        assertEquals(null, warningFor("Gradle", tree("build.gradle", "gradle.lockfile")))
    }

    @Test
    fun `does not warn when a prefixed gradle lockfile is present`() {
        assertEquals(null, warningFor("Gradle", tree("build.gradle.kts", "buildscript-gradle.lockfile")))
    }

    @Test
    fun `warns per unresolved gradle module`() {
        val root = tree(
            "build.gradle", "gradle.lockfile",
            "moduleA/build.gradle",
            "moduleB/build.gradle.kts",
        )
        // the root lockfile does not cover the submodules, but the root module itself is resolved
        val warning = assertNotNull(warningFor("Gradle", root))
        assertTrue(warning.contains("2 module(s)"), warning)
    }

    // ── Maven ────────────────────────────────────────────────────────────

    @Test
    fun `warns for maven when the local cache is empty`() {
        val emptyM2 = Files.createTempDirectory("empty-m2").toFile()
        val warning = assertNotNull(warningFor("Maven", tree("pom.xml"), emptyM2), "expected a Maven warning")
        assertTrue(warning.contains("1 pom.xml project(s)"), warning)
        assertTrue(warning.contains("mvn dependency:go-offline"), warning)
    }

    @Test
    fun `warns for maven when the local cache is absent`() {
        val missingM2 = File(Files.createTempDirectory("no-m2").toFile(), "repository")
        assertTrue(warningFor("Maven", tree("pom.xml"), missingM2) != null)
    }

    @Test
    fun `does not warn for maven when the local cache is warm`() {
        val warmM2 = Files.createTempDirectory("warm-m2").toFile()
        File(warmM2, "org/apache/commons").mkdirs()
        assertEquals(null, warningFor("Maven", tree("pom.xml"), warmM2))
    }

    @Test
    fun `names the maven cache relative to home rather than by its absolute path`() {
        val home = Files.createTempDirectory("fake-home").toFile()
        val emptyM2 = File(home, ".m2/repository").also { it.mkdirs() }
        val realHome = System.getProperty("user.home")
        val warning = try {
            System.setProperty("user.home", home.path)
            assertNotNull(warningFor("Maven", tree("pom.xml"), emptyM2), "expected a Maven warning")
        } finally {
            System.setProperty("user.home", realHome)
        }
        // The wrappers rewrite $HOME to "~" in the SBOMs; a warning printed by the same run must
        // not put the client's absolute layout back into the log.
        assertTrue(!warning.contains(home.path), warning)
        assertTrue(warning.contains("~${File.separator}.m2${File.separator}repository"), warning)
    }

    @Test
    fun `does not warn for maven when there is no pom`() {
        val emptyM2 = Files.createTempDirectory("empty-m2").toFile()
        assertEquals(null, warningFor("Maven", tree("package.json"), emptyM2))
    }

    // ── nothing to say ───────────────────────────────────────────────────

    @Test
    fun `stays silent on a fully resolved tree`() {
        val warmM2 = Files.createTempDirectory("warm-m2").toFile()
        File(warmM2, "org").mkdirs()
        val root = tree(
            "pom.xml",
            "build.gradle", "gradle.lockfile",
            "src/Web/Web.csproj", "src/Web/packages.lock.json",
            "package.json", "package-lock.json",
        )
        assertEquals(emptyList(), ResolutionCheck.warnings(root, m2Repository = warmM2))
    }

    @Test
    fun `stays silent on a tree with none of these stacks`() {
        assertEquals(emptyList(), ResolutionCheck.warnings(tree("go.mod", "Cargo.lock"), m2Repository = null))
    }
}
