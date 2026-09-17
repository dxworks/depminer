# DepMiner

**DepMiner** mines dependency information from a target folder of repositories.
As a **Voyager instrument** it runs three **extraction mechanisms** per mission, side by side:

| Command name (use exactly this in `mission.yml`) | Extraction mechanism | Output (under `depminer/results/` inside the results zip) |
|---|---|---|
| `Mine Dependencies` | **proprietary** | `depminer/` — mined manifests and lockfiles (`pom-*.xml`, `package-lock-*.json`, `Cargo.lock`, `go.sum`, …) + `index.json` + `skipped.json` |
| `Syft SBOM` | **Syft SBOM** (bundled) | `syft/` — `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` per project |
| `Trivy Extract` | **Trivy SBOM** (bundled) | `trivy/` — `<project>.trivy.cdx.json` per project |

!!! tip "All three extraction mechanisms run by default"
    No configuration is needed for the full run. Point it at a folder of repositories and you get
    mined manifests plus three SBOM formats per project.

## What you get

Extraction is **completely offline**: no vulnerability databases, no telemetry, no registry or
Maven Central lookups, nothing downloaded at run time. Each mechanism groups its output in its own
subfolder:

- **`results/depminer/`** — mined manifests and lockfiles, plus `index.json` (where each file came from) and `skipped.json` (what did not ship, and why)
- **`results/syft/`** — Syft JSON, CycloneDX and SPDX, per project
- **`results/trivy/`** — CycloneDX, per project
- **`results/scrub-report.json`** — shared by all three: whether anything shipped carrying host data

Most ecosystems need no setup. Maven, Gradle and a bare `requirements.txt` need one one-time prep
step first: see **[Preparing Your Project](prep-guide.md)**.

## Where to go next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Quick Start](quickstart.md)** — run DepMiner as a Voyager instrument and find your results.
- :material-wrench: **[Preparing Your Project](prep-guide.md)** — the one-time step some ecosystems need for a *complete* (transitive) scan.
- :material-tune: **[Configuration](configuration.md)** — choose which tools run, per mission or per environment variable.
- :material-package-variant: **[Bundled Tools](tools.md)** — pinned Syft/Trivy versions and the offline guarantees.

</div>
