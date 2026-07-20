# DepMi (Dependency Miner)

Depminer mines dependency information from a target folder of repositories. As a
**Voyager instrument** it runs three tools per mission, side by side:

| Command name (use exactly this in mission.yml) | Tool | Output in `depminer/results/` |
|---|---|---|
| `Mine Dependencies` | depminer | mined manifest files (`pom-*.xml`, `package-*.json`, …) + `index.json` |
| `Syft SBOM` | Syft (bundled) | `<project>.syft.json`, `<project>.cdx.json`, `<project>.spdx.json` per project |
| `Trivy Extract` | Trivy (bundled) | `<project>.trivy.cdx.json` per project |

Syft and Trivy run **extraction-only and 100% offline**: no vulnerability databases,
no telemetry, no version checks, no registry or Maven Central lookups. They only read
the target folder and write SBOM files. Their binaries are bundled in `bin/` for
linux/macOS (amd64 + arm64) and Windows (amd64) — nothing is downloaded at run time.

**All three tools run by default.** No configuration is needed for the full run.

## Choosing which tools run

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
Voyager runs all three (see the mission.yml section of Voyager's own README; requires
`runsAll: false` in the install's `.config.yml`, which voyenv-built bundles set).

### Per environment variable — explicit on/off switches

| Variable | Effect when set to `"false"` |
|---|---|
| `DEPMINER_RUN_MINER` | skip depminer's own extraction |
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

## Bundled tool versions

| Tool | Version | Source |
|---|---|---|
| Syft | 1.46.0 | github.com/anchore/syft (pinned in `scripts/prepare-release-voyager.sh`) |
| Trivy | 0.72.0 | github.com/aquasecurity/trivy (pinned in `scripts/prepare-release-voyager.sh`) |

The wrappers in `bin/` pick the binary matching the host OS/arch and fall back to a
tool on PATH only when no bundled binary exists (a development convenience — release
bundles always contain the binaries).
