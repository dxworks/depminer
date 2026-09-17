# DepMiner (Dependency Miner)

DepMiner mines dependency information from a target folder of repositories. As a
**Voyager instrument** it runs three extraction mechanisms per mission, side by side:

| Command name (use exactly this in mission.yml) | Extraction mechanism | Output |
|---|---|---|
| `Mine Dependencies` | **proprietary** | `results/depminer/` — mined manifests and lockfiles (`pom-*.xml`, `package-lock-*.json`, `Cargo.lock`, `go.sum`, …) + `index.json` + `skipped.json` |
| `Syft SBOM` | **Syft SBOM** (bundled) | `results/syft/` — `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` per project |
| `Trivy Extract` | **Trivy SBOM** (bundled) | `results/trivy/` — `<project>.trivy.cdx.json` per project |

Each mechanism owns a subfolder, so asking for "the Syft SBOMs" is a folder, not a guess at a filename
suffix. The one file at the root of `results/` is `scrub-report.json`, shared by all three: it is
the single place to look to find out whether anything in the run shipped carrying host data.

Syft and Trivy run **extraction-only and 100% offline**: no vulnerability databases,
no telemetry, no version checks, no registry or Maven Central lookups. They only read
the target folder and write SBOM files. Their binaries are bundled in `bin/` for
linux/macOS (amd64 + arm64) and Windows (amd64) — nothing is downloaded at run time.

**All three extraction mechanisms run by default.** No configuration is needed for the full run.

## Getting complete results (transitive dependencies)

Syft and Trivy read your project's **already-resolved** dependency state — lock files, or a
warm local cache — they do **not** build your project. For most ecosystems the lock file is
already committed and you need to do **nothing**. A few (Maven, Gradle, and a bare
`requirements.txt`) need one minimal, one-time prep step first so the scan captures the full
transitive tree instead of only the directly-declared dependencies.

👉 **See [`PREP_GUIDE.md`](PREP_GUIDE.md) for the per-technology prep steps.**

## Choosing which mechanisms run

### Per mission — list only the commands you want

```yaml
mission: my-analysis
target: /path/to/repos
instruments:
  depminer:
    commands:
      - Mine Dependencies
      - Syft SBOM        # Trivy Extract not listed -> Trivy does not run
```

Command names must match the table above exactly. If `commands` is empty or missing,
Voyager runs all three. For a narrower selection to be honoured, the install's `.config.yml`
must set `runsAll: false`; it defaults to `true`, which runs every instrument it finds with all
of their commands regardless of what the mission asked for.

### Per environment variable — explicit on/off switches

| Variable | Effect when set to `"false"` |
|---|---|
| `DEPMINER_RUN_MINER` | skip the proprietary extraction |
| `DEPMINER_RUN_SYFT` | skip Syft |
| `DEPMINER_RUN_TRIVY` | skip Trivy |

Unset or any other value means ON. A skipped command still reports SUCCESS in the
mission summary (it just logs that it was skipped). Set the variables in any of these
places — later ones win:

1. the shell that launches voyager (`DEPMINER_RUN_TRIVY=false ./voyager.sh mission.yml`)
2. `.config.yml` in the voyager folder, under `environment:`
3. `mission.yml` under `environment:` — **highest priority**, recommended for prod:

```yaml
environment:
  DEPMINER_RUN_TRIVY: "false"
```

Two more switches control **Syft's offline Maven resolution** (see PREP_GUIDE.md), and
accept the same three locations: `SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES` and
`SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY`. Both default to `"true"` (resolve the full
transitive tree from the local `~/.m2` cache); set **both** to `"false"` to fall back to
declared-only Maven results. Everything stays offline either way.

## When one project fails to scan

Syft and Trivy scan every project in the target even if one of them fails: the failing
project is logged with a warning, the remaining projects still get their SBOMs, and the
command finishes with a summary of failed projects. The command then reports as FAILED in
the mission summary — check its log to see which projects were affected; all other result
files are still written.

## Bundled tool versions

| Tool | Version | Source |
|---|---|---|
| Syft | 1.46.0 | github.com/anchore/syft (pinned in `scripts/prepare-release-voyager.sh`) |
| Trivy | 0.72.0 | github.com/aquasecurity/trivy (pinned in `scripts/prepare-release-voyager.sh`) |

The wrappers in `bin/` pick the binary matching the host OS/arch and fall back to a
tool on PATH only when no bundled binary exists (a development convenience — release
bundles always contain the binaries).
