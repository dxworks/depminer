# DepMiner — Dependency File Miner

## Project Overview

DepMiner is a CLI tool that extracts dependency files (package manifests, lockfiles) from projects based on configurable glob patterns. It supports 9 ecosystems (Java, JavaScript, PHP, Ruby, Python, .NET, etc.) and includes a sanitization engine to redact secrets from extracted files.

The tool is also packaged as a [Voyager](https://github.com/dxworks/voyager) instrument (`depminer-voyager.zip`) and an npm package (`@dxworks/depminer`).

## Build & Run

- **Language:** Kotlin on Java 21
- **Build tool:** Maven (wrapper included: `./mvnw`)
- **Build:** `./mvnw clean package`
- **Output:** `target/depminer.jar` (fat JAR with all dependencies)
- **Run:** `java -jar target/depminer.jar extract /path/to/project [results-dir] [no-sanitize]`
- **Main class:** `org.dxworks.depminer.DepMiKt`

### Commands

| Command | Usage | Description |
|---|---|---|
| `extract` | `extract <target> [output] [no-sanitize]` | Extract dependency files from target directory |
| `construct` | `construct <index-source> [output]` | Reconstruct original directory structure from extracted files |

### Configuration

Parameters can be set via CLI args, environment variables (prefixed `DEPMINER_`), or defaults:

| Parameter | Env Variable | Default | Description |
|---|---|---|---|
| `depminer.file` | `DEPMINER_DEPMINER_FILE` | `depminer.yml` | Glob patterns per language |
| `ignore.file` | `DEPMINER_IGNORE_FILE` | `.ignore.yml` | File/dir exclusion patterns |
| `sanitize.file` | `DEPMINER_SANITIZE_FILE` | `sanitize.yml` | Sanitization regex patterns |

## Project Structure

```
src/main/java/org/dxworks/depminer/
  DepMi.kt                          — CLI entry point, extract/construct commands
  sanitization/Sanitizer.kt         — Regex-based secret sanitization engine

lib/
  depminer.js                       — Node.js CLI entry point
  index.js                          — Commander.js command definition
  lib.js                            — Java caller wrapper (invokes JAR from Node)

bin/
  depminer.sh                       — Unix launcher script
  depminer.bat                      — Windows launcher script

scripts/
  build.sh                          — Build script (wraps mvnw)
  prepare-release.sh                — Package standard release ZIP
  prepare-release-voyager.sh        — Package Voyager instrument ZIP
  regression-test.sh                — Compare output against latest release

depminer.yml                        — Language-to-glob-pattern mappings
sanitize.yml                        — 144+ regex patterns for secret redaction
.ignore.yml                         — Directory/file exclusion patterns
instrument.yml                      — Voyager instrument descriptor
```

## Dependencies

- `jackson-dataformat-yaml` + `jackson-module-kotlin` — YAML/JSON parsing
- `commons-io` — File I/O utilities and wildcard filtering
- `argumenthor` (`org.dxworks.utils`) — CLI argument/config/env parsing

## Docker

- **Image:** `dxworks/depminer` on Docker Hub
- **Base:** `eclipse-temurin:21-jre-alpine`
- **Build:** `docker build -t depminer-test .` (requires `target/depminer.jar` — run `./mvnw clean package` first)
- **Run:** `docker run -v /path/to/project:/project dxworks/depminer extract /project /app/results`

## CI/CD

- **Build:** `build.yml` runs on push to all branches (Maven verify)
- **Release:** Tag `v*` triggers `release.yml` — gate → archive + npm + docker (parallel) → GitHub Release
- **Voyager release:** Tag `v*-voyager` triggers `release-voyager.yml` — gate → archive → GitHub Release
- **Security:** `trivy-security-scan.yml` runs on PRs to `main` (filesystem + Docker image scan); `trivy-daily-scan.yml` runs daily
- **Regression:** `regression-test.yml` runs on PRs (non-blocking) and manual dispatch

All release workflows use reusable pipelines from `dxworks/pipelines@v1`.

## Branching Strategy

- Main development branch: `main`
- Release tags: `v<semver>` (standard) and `v<semver>-voyager` (Voyager instrument)

## Output Format

DepMiner produces extracted dependency files in the results directory along with an `index.json` that maps extracted filenames to their original paths. Files with duplicate names get an index suffix (e.g., `pom-0.xml`, `pom-1.xml`).
