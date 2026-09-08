# Preparing Your Project for a Complete Scan

This instrument scans **whatever technologies it finds** in your repositories — Java, Node,
Python, Go, Rust, .NET, PHP, Ruby, and more — automatically, in a single pass. You do **not**
tell it what stack you use; it detects everything present.

The one thing it needs from you is that your project is in a **resolved** state on disk before we
scan. Here is why, and the minimal steps to get there.

## Why any prep is needed at all

Syft and Trivy are **static readers**. They do **not** build your project, run your package
manager, or reach the internet (this instrument is 100% offline). They report exactly the
dependencies that are already written down on disk:

- A **lock file** (`package-lock.json`, `Cargo.lock`, `poetry.lock`, `gradle.lockfile`, …) lists
  the **full transitive tree** — every direct *and* indirect dependency, pinned. When one is
  present, the scan is complete with zero effort.
- A bare **manifest** (`pom.xml`, `build.gradle`, a hand-written `requirements.txt`) lists only
  the **direct** dependencies. Without a resolved lock file or a warm local cache, the scan sees
  the direct deps only — the transitive tree is missing.

So "prep" means one thing: **make the resolved state exist before we scan.** For most projects it
already does.

## The 30-second version

| Your stack | What to do |
|---|---|
| npm / yarn / pnpm, Go, Rust, Ruby, PHP, Python (Poetry / Pipenv / uv) | **Nothing** — just make sure the lock file is committed (it usually is). |
| **Maven** | Run one command to warm the local cache — see [Maven](#maven). |
| **Gradle** | Generate lock files once — see [Gradle](#gradle). |
| **.NET** | Run one command to write the lock files — see [.NET](#net). |
| Python with a bare `requirements.txt` | Regenerate it fully-pinned — see [Python](#python-bare-requirementstxt). |

If your project is only in the first row, you are done. The rest of this page is for the four
cases that need a one-time command.

!!! warning "Prep on a machine that can build the project"
    Do the prep where your build tools live, and — for the one-time resolve step — with internet.
    The *scan itself* is always offline; prep and scan are separate steps. See
    [Where prep must happen](#where-the-prep-must-happen) for the one important detail about Maven.

## Maven

A `pom.xml` does **not** store the resolved dependency tree — Maven normally rebuilds it by
reaching Maven Central. Offline, we instead read your **local Maven cache** at `~/.m2/repository`.
So the prep is to fill that cache once:

```bash
# In the project directory, on a machine with internet + Maven installed:
mvn dependency:go-offline -fae
# (a normal build works too and is more thorough:)
# mvn install -DskipTests
```

That downloads every dependency's metadata into `~/.m2/repository`. After that, both scanners
resolve the **full transitive tree** from the cache — no network.

!!! tip "Use `-fae` (fail at end) — a partial warm cache is still a big win"
    In a large multi-module project, it is normal for a module or two to fail to resolve, and by
    default Maven **stops at the first failure**, leaving the rest of the cache cold. `-fae`
    (`--fail-at-end`) keeps going and warms everything it can. `-fn` (`--fail-never`) is even more
    permissive.

    The common cause is a **JDK mismatch**: older projects declare JDK-8-era artifacts such as
    `jdk.tools:jdk.tools` or `com.sun:tools` (the old `tools.jar`), which do not exist on modern
    JDKs and fail to resolve no matter what. Those modules simply will not be cached — every other
    module still is, and the scan still improves enormously. If you need those modules too, run the
    prep with the older JDK the project was written for.

    Scanning is unaffected either way: prep failures never break the scan, they only limit how much
    of the transitive tree it can see.

!!! example "Measured effect (Apache Zeppelin, offline)"
    Maven components detected went from **~1000 → ~2400 (Trivy)** and **~300 → ~4000 (Syft)** once
    `~/.m2` was warmed. Same repo, same scan — the only difference is the cache.

The warm cache is what makes the offline scan work at all — it is not a speed-up. On
spring-petclinic, Trivy finds **106** components with a populated `~/.m2`; with an empty `~/.m2`
and offline mode it finds **16** — the direct declarations, most without a version. Same repo, same
command.

If your build machine already compiles this project regularly, `~/.m2` is **already warm** and you
need to do nothing.

## Gradle

Gradle has no lock file by default. Generate one so the resolved tree lands in a file that travels
inside the repo:

```bash
# One-time: enable dependency locking in build.gradle (or settings.gradle):
#   dependencyLocking { lockAllConfigurations() }
# Then, on a machine with internet:
./gradlew dependencies --write-locks
```

This writes `gradle.lockfile` (per module). Commit it. Both scanners read it and report the full
tree — and because it lives in the repo, it is portable (no cache needed at scan time).

!!! example "Measured effect (spring-petclinic)"
    With the lock file, Trivy reaches **201 of Black Duck's 209 rows** (222 real components).
    Without it, the repo's Gradle build contributes **0** — Trivy's only Gradle input is
    `*.gradle.lockfile`, it never reads `build.gradle`.

This matters more than it looks, even on a project you think of as Maven. The lock file also locks
the **test** configurations, so it recovers dependencies Trivy's `pom` parser structurally cannot
see: that parser skips `test` and `optional` scope, and the `--include-dev-deps` switch covers
npm/yarn/gradle but **not** `pom`. On spring-petclinic those two effects are the same 96-row gap.

## .NET

`dotnet restore` **is not enough.** A plain restore writes `obj/project.assets.json`, and **neither
scanner reads that file** — it yields 0 components in both Trivy and Syft. The only .NET file
either tool reads that carries a transitive graph is `packages.lock.json`, and that is opt-in:

```bash
# On a machine with the .NET SDK + internet, solution-wide:
dotnet restore YourSolution.sln --use-lock-file
# (no solution file? run it per project:)
# dotnet restore src/YourProject/YourProject.csproj --use-lock-file
```

This writes one `packages.lock.json` per project. **Commit them.** Like the Gradle lock files they
live inside the repo, so they are portable — no cache needed at scan time.

Without them, the scan falls back to `Directory.Packages.props` or the `.csproj` files, which are
flat lists of declared versions with **no graph at all**.

!!! example "Measured effect (eShopOnWeb)"
    Unique NuGet components went from **33 → 303**, transitive dependencies from **0 → 251**, total
    Trivy components from **34 → 1625**, and Syft's NuGet packages from **0 → 308**. Measured
    against a Black Duck run of the same repo, recall went from **10.2% → 98.7%**. Same repo, same
    scan — the only difference is the lock files.

## Python (bare `requirements.txt`)

A hand-written `requirements.txt` usually lists only direct dependencies. Regenerate a fully
resolved one:

```bash
# Option A — pip-tools (does not install anything):
pip-compile            # turns requirements.in / pyproject into a pinned requirements.txt

# Option B — from a virtualenv where the app is already installed:
pip freeze > requirements.txt
```

If you use **Poetry, Pipenv, or uv**, no prep is needed — commit `poetry.lock` / `Pipfile.lock` /
`uv.lock` and you already have the full tree.

## Everything else (npm, Go, Rust, PHP, Ruby …)

No prep beyond having the lock file committed, which is normal practice:

| Stack | Lock file that must be present |
|---|---|
| npm / yarn / pnpm | `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| Go (1.17+) | `go.mod` (+ `go.sum`) |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |

If one is missing, run the ecosystem's install once (`npm ci`, `composer install`, `bundle lock`,
…) to create it, and commit it. **.NET is the exception** — its lock file is opt-in and needs a
specific flag, see [.NET](#net).

## Where the prep must happen

There are two shapes of prep, and they differ in one important way:

| Prep produces… | Lives in… | Portable? |
|---|---|---|
| A **lock file** (Gradle, .NET, npm, Python-lock, etc.) | a file **inside the repo** | :material-check: Yes — prep anywhere, the file ships with the code |
| A **warm cache** (Maven `~/.m2`) | the user's **home directory**, not the repo | :material-alert: No — see below |

**Maven is the one to watch.** Its resolved data sits in `~/.m2` on whichever machine did the
build, *not* in the repo. The scanners read the `~/.m2` of the machine **running the scan**. So for
Maven, do one of:

1. **Run `mvn dependency:go-offline` and the scan on the same machine (same user home).** Simplest,
   and automatic if the client scans on its own build box.
2. Otherwise, carry the warmed `~/.m2` to the scan machine (or point the tools at a project-local
   cache — Syft honors `SYFT_JAVA_MAVEN_LOCAL_REPOSITORY_DIR`).

Lock-file ecosystems have no such constraint — the lock file travels with the repo.

## How to check it worked

After prep, a quick sanity check: the number of Maven/other components in a scan should be much
higher than "just the direct dependencies you wrote in the manifest." If a Maven project reports
only a few dozen components, `~/.m2` was probably not warm on the scan machine.

## What this cannot do

The scanners find any technology **they support** (broad — essentially every mainstream
ecosystem). A stack neither tool catalogs — e.g. Bazel, Scala SBT, Perl/CPAN — will not appear no
matter how you prep, because there is no lock file or cache these tools know how to read for it.
For the full supported-ecosystem list, see the tools' own documentation.
