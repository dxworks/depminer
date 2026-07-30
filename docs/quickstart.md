# Quick Start

DepMiner runs as a **Voyager instrument**. You give Voyager a mission that points at a folder of
repositories; DepMiner mines the dependencies and writes SBOMs.

## Prerequisites

- **A Java runtime — JDK 11 or newer.** Voyager is a Java application: `voyager.sh` is a one-line
  wrapper around `java -jar dx-voyager.jar`. Verify with `java -version` **before** you start.

    !!! warning "If `java` is missing, the error will not mention Voyager"
        With no JDK on your `PATH`, step 2 below fails with a bare operating-system message such as
        `Unable to locate a Java Runtime` (macOS) or `java: command not found`. Nothing in it points
        at Voyager or DepMiner. Install a JDK (Temurin, or `brew install openjdk` on macOS) and make
        sure it is on your `PATH`.

- **A Voyager installation containing this instrument** — the folder holding `voyager.sh`
  (`voyager.bat` on Windows), `dx-voyager.jar`, and `instruments/depminer/`. **Run every command on
  this page from inside that folder**, and put your `mission.yml` there too.

Syft and Trivy need **nothing** installed — their binaries ship inside the bundle.

## 1. Point a mission at your repositories

Create a `mission.yml`:

```yaml
mission: my-analysis
target: /path/to/repos
instruments:
  depminer:
    commands:
      - Mine Dependencies
      - Syft SBOM
      - Trivy Extract
```

!!! note "Command names are exact"
    The `commands` values must match the [command names](index.md) exactly:
    `Mine Dependencies`, `Syft SBOM`, `Trivy Extract`. If `commands` is empty or missing, Voyager
    runs **all three** (this requires `runsAll: false` in the install's `.config.yml`, which
    voyenv-built bundles already set).

## 2. Run the mission

```bash
./voyager.sh mission.yml
```

## 3. Find your results

**Your results are delivered as a zip file in the Voyager folder**, named after the `mission:` value
inside your mission file:

```
<mission>-voyager-results.zip
```

So the example above (`mission: my-analysis`) produces **`my-analysis-voyager-results.zip`**, next to
`voyager.sh`. Note the name comes from the `mission:` field, **not** from the mission file's
filename — a file called `my-mission.yml` declaring `mission: my-analysis` still yields
`my-analysis-voyager-results.zip`.

!!! warning "Don't go looking for a leftover results folder"
    While the mission runs, the instrument writes into `instruments/depminer/results/`. Voyager
    **zips that folder and then deletes it** as the run finishes, so afterwards it is empty. That is
    normal — the zip is the deliverable. The last lines of the run log confirm it:
    `Results written to <mission>-voyager-results.zip`.

Unzip it and you get a `depminer/results/` directory containing:

| File | Produced by |
|---|---|
| `pom-*.xml`, `package-*.json`, … + `index.json` | depminer |
| `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` | Syft |
| `<project>.trivy.cdx.json` | Trivy |

The zip also contains `mission-report.log` (the per-command SUCCESS/FAILED summary), `depminer.log`,
and a copy of the mission file you ran.

## Getting complete (transitive) results

Syft and Trivy read your project's **already-resolved** dependency state — a lock file or a warm
local cache — they do **not** build your project. For most ecosystems the lock file is already
committed and you need to do **nothing**.

A few stacks (Maven, Gradle, and a bare `requirements.txt`) need one minimal, one-time prep step
so the scan captures the full transitive tree instead of only the directly-declared dependencies.

👉 See **[Preparing Your Project](prep-guide.md)** for the per-technology steps.

## Choosing which tools run

You do not have to run all three every time. See **[Configuration](configuration.md)** for two ways
to select tools: listing commands per mission, or flipping per-tool environment switches.
