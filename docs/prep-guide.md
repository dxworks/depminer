# Preparing Your Project

Syft and Trivy read the dependencies **already resolved on disk**. A project with a committed lock
file is ready as it is. Four stacks need one command first.

| Your stack | What to do |
|---|---|
| npm / yarn / pnpm, Go, Rust, Ruby, PHP, Python (Poetry / Pipenv / uv) | **Nothing.** Commit the lock file. |
| [**Maven**](#maven) | `mvn dependency:go-offline -fae` |
| [**Gradle**](#gradle) | `./gradlew dependencies --write-locks` |
| [**.NET**](#net) | `dotnet restore --use-lock-file` |
| [**Python**, bare `requirements.txt`](#python-bare-requirementstxt) | `pip-compile` or `pip freeze` |

Run these once, on a machine that can build the project, with internet. The scan itself is always
offline.

## Maven

```bash
mvn dependency:go-offline -fae     # or: mvn install -DskipTests
```

Fills the local cache at `~/.m2/repository`. Nothing to commit, and nothing to do at all if this
machine already builds the project regularly.

!!! warning "The cache must be on the machine that runs the scan"
    `~/.m2` lives in a home directory, not in the repo, so it does not travel with the code. Run
    the prep and the scan on the same machine, or copy the warmed `~/.m2` across. Syft also honours
    `SYFT_JAVA_MAVEN_LOCAL_REPOSITORY_DIR` for a project-local cache.

??? info "Why, and what to do when modules fail to resolve"
    A `pom.xml` records only direct dependencies, so offline the scanners read `~/.m2` instead.

    `-fae` (fail at end) keeps Maven going after a module fails, instead of stopping at the first
    one and leaving the rest of the cache cold. `-fn` (fail never) is more permissive still.

    The usual cause of a failing module is a JDK mismatch: older projects declare JDK-8-era
    artifacts such as `jdk.tools:jdk.tools` or `com.sun:tools`, which do not exist on modern JDKs.
    Those modules will not be cached, every other one still is. Prep failures never break the scan,
    they only limit how much of the tree it sees.

## Gradle

```bash
# once, in build.gradle or settings.gradle:
#   dependencyLocking { lockAllConfigurations() }
./gradlew dependencies --write-locks
```

Writes a `gradle.lockfile` per module. **Commit them.** They live in the repo, so they travel with
the code and need no cache at scan time.

??? info "Why the lock file is not optional here"
    Trivy's only Gradle input is `*.gradle.lockfile`; it never reads `build.gradle`. Without the
    lock file the Gradle build contributes nothing at all.

    The lock file also covers the **test** configurations, so it recovers dependencies the `pom`
    parser structurally cannot see: that parser skips `test` and `optional` scope, and
    `--include-dev-deps` covers npm/yarn/gradle but not `pom`.

## .NET

```bash
dotnet restore YourSolution.sln --use-lock-file
# no solution file? per project:
# dotnet restore src/YourProject/YourProject.csproj --use-lock-file
```

Writes a `packages.lock.json` per project. **Commit them.** Like Gradle's, they live in the repo.

??? info "Why a plain `dotnet restore` is not enough"
    A plain restore writes `obj/project.assets.json`, which neither scanner reads: 0 components in
    both. `packages.lock.json` is the only .NET file either tool reads that carries a transitive
    graph, and it is opt-in.

    Without it the scan falls back to `Directory.Packages.props` or the `.csproj` files, which are
    flat lists of declared versions with no graph at all.

## Python (bare `requirements.txt`)

```bash
pip-compile                      # pip-tools; installs nothing
pip freeze > requirements.txt    # or, from a virtualenv where the app is installed
```

Only needed for a hand-written `requirements.txt`. **Poetry, Pipenv and uv need nothing**: commit
`poetry.lock` / `Pipfile.lock` / `uv.lock` and you already have the full tree.

## Everything else

Nothing beyond committing the lock file, which is normal practice anyway:

| Stack | Lock file |
|---|---|
| npm / yarn / pnpm | `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| Go (1.17+) | `go.mod` + `go.sum` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |

Missing one? Run the ecosystem's install once (`npm ci`, `composer install`, `bundle lock`) and
commit the result.

## Why any of this is needed

A lock file lists the **full transitive tree**, every direct and indirect dependency, pinned. A
bare manifest (`pom.xml`, `build.gradle`, a hand-written `requirements.txt`) lists only the
**direct** ones. Syft and Trivy are static readers: they do not build your project and do not reach
the network, so they report exactly what is written down. Prep means making the resolved state
exist before the scan.

To check it worked, compare the component count against "just the direct dependencies you wrote
down". A Maven project reporting only a few dozen components probably had a cold `~/.m2`.

A stack neither scanner catalogs, such as Bazel, Scala SBT or Perl/CPAN, will not appear no matter
how you prep.
