# DepMiner

**DepMiner (DepMi)** mines dependency information from a target folder of repositories.
As a **Voyager instrument** it runs three tools per mission, side by side:

| Command name (use exactly this in `mission.yml`) | Tool | Output (under `depminer/results/` inside the results zip) |
|---|---|---|
| `Mine Dependencies` | depminer | `depminer/` — mined manifest files (`pom-*.xml`, `package-*.json`, …) + `index.json` |
| `Syft SBOM` | Syft (bundled) | `syft/` — `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` per project |
| `Trivy Extract` | Trivy (bundled) | `trivy/` — `<project>.trivy.cdx.json` per project |

Each tool owns a subfolder, so asking for "the Syft SBOMs" is a folder, not a guess at a filename
suffix. The one file at the root of `results/` is `scrub-report.json`, shared by all three: it is
the single place to look to find out whether anything in the run shipped carrying host data.

Syft and Trivy run **extraction-only and 100% offline**: no vulnerability databases, no
telemetry, no version checks, no registry or Maven Central lookups. They only read the target
folder and write SBOM files. Their binaries are bundled in `bin/` for linux/macOS
(amd64 + arm64) and Windows (amd64) — nothing is downloaded at run time.

!!! tip "All three tools run by default"
    No configuration is needed for the full run. Point it at a folder of repositories and you get
    mined manifests plus three SBOM formats per project.

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quick Start](quickstart.md)** — run DepMiner as a Voyager instrument and find your results.
- :material-wrench: **[Preparing Your Project](prep-guide.md)** — the one-time step some ecosystems need for a *complete* (transitive) scan.
- :material-tune: **[Configuration](configuration.md)** — choose which tools run, per mission or per environment variable.
- :material-package-variant: **[Bundled Tools](tools.md)** — pinned Syft/Trivy versions and the offline guarantees.

</div>

## What it produces

For every project it finds in the target folder, DepMiner produces the following, delivered inside
the run's results zip (`<mission>-voyager-results.zip`, under `depminer/results/` — see
[Quick Start → Find your results](quickstart.md#3-find-your-results)):

- **Mined manifests** (`results/depminer/`) — the raw dependency declarations depminer extracts,
  plus an `index.json` mapping each copied file back to its path under the target.
- **Syft SBOMs** (`results/syft/`) — three formats per project: native Syft JSON, CycloneDX
  (`.cdx.json`), and SPDX.
- **Trivy SBOM** (`results/trivy/`) — CycloneDX per project (`.trivy.cdx.json`).
- **`results/scrub-report.json`** — shared by all three, at the root: whether anything emitted
  still carries host data.

Because Syft and Trivy read your project's **already-resolved** dependency state rather than
building it, most ecosystems need zero setup. A few (Maven, Gradle, a bare `requirements.txt`)
need one minimal, one-time prep step — see [Preparing Your Project](prep-guide.md).
