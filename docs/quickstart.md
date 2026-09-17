# Quick Start

DepMiner runs inside Voyager: you point a mission at a folder of repositories, and DepMiner mines
their dependencies and writes SBOMs.

You need two things. A **Voyager install with DepMiner in it**, which takes two steps on
[Installing](install.md). And a **target folder** whose children are the repositories you want
analysed. The **[Voyager Quick Start](https://dxworks.org/voyager/quickstart.html)** walks through
both, including `./voyager.sh doctor` to confirm your runtimes are in place.

## 1. Add DepMiner to your mission

In the `mission.yml` you configured for Voyager, add the `depminer` instrument:

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

The `commands` values must match the [command names](index.md) exactly. Leave `commands` out to
run all three.

## 2. Run the mission

```bash
./voyager.sh
```

## 3. Find DepMiner's output

Inside `<mission>-voyager-results.zip`, under `depminer/results/`:

```
depminer/results/
  scrub-report.json     whether anything shipped carrying host data
  depminer/             mined manifests and lockfiles + index.json
  syft/                 <project>.syft.json, .cdx.json, .spdx.json
  trivy/                <project>.trivy.cdx.json
```

`depminer/index.json` maps each copied file back to the repo it came from.

## Next

- **[Preparing Your Project](prep-guide.md)** — Maven, Gradle and a bare `requirements.txt` need
  one one-time step for a complete transitive scan.
- **[Configuration](configuration.md)** — running fewer than all three mechanisms.
