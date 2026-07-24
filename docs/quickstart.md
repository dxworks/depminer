# Quick Start

DepMiner runs as a **Voyager instrument**. You give Voyager a mission that points at a folder of
repositories; DepMiner mines the dependencies and writes SBOMs.

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

Everything lands under `depminer/results/`:

| File | Produced by |
|---|---|
| `pom-*.xml`, `package-*.json`, … + `index.json` | depminer |
| `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` | Syft |
| `<project>.trivy.cdx.json` | Trivy |

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
