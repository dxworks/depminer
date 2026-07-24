# DepMiner

**DepMiner (DepMi)** mines dependency information from a target folder of repositories.
As a **Voyager instrument** it runs three tools per mission, side by side:

| Command name (use exactly this in `mission.yml`) | Tool | Output in `depminer/results/` |
|---|---|---|
| `Mine Dependencies` | depminer | mined manifest files (`pom-*.xml`, `package-*.json`, …) + `index.json` |
| `Syft SBOM` | Syft (bundled) | `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` per project |
| `Trivy Extract` | Trivy (bundled) | `<project>.trivy.cdx.json` per project |

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

For every project it finds in the target folder, DepMiner writes results under
`depminer/results/`:

- **Mined manifests** — the raw dependency declarations depminer extracts, plus an `index.json`.
- **Syft SBOMs** — three formats per project: native Syft JSON, CycloneDX (`.cdx.json`), and SPDX.
- **Trivy SBOM** — CycloneDX per project (`.trivy.cdx.json`).

Because Syft and Trivy read your project's **already-resolved** dependency state rather than
building it, most ecosystems need zero setup. A few (Maven, Gradle, a bare `requirements.txt`)
need one minimal, one-time prep step — see [Preparing Your Project](prep-guide.md).
