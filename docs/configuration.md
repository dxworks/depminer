# Configuration

All three mechanisms run by default. This page is for turning some off, tuning Syft's Maven
resolution, and changing what gets copied.

## Which mechanisms run

**In the mission**, list only the commands you want:

```yaml
instruments:
  depminer:
    commands:
      - Mine Dependencies
      - Syft SBOM        # Trivy Extract not listed -> Trivy does not run
```

Names must match [the command table](index.md) exactly. Leave `commands` out to run all three.

!!! warning "Your selection is ignored unless `runsAll: false`"
    Voyager's `.config.yml` defaults `runsAll` to `true`, which runs every instrument it finds
    with all of their commands, whatever the mission asked for.

**Or by environment variable:**

| Variable | Set to `"false"` to |
|---|---|
| `DEPMINER_RUN_MINER` | skip the proprietary extraction |
| `DEPMINER_RUN_SYFT` | skip Syft |
| `DEPMINER_RUN_TRIVY` | skip Trivy |

Unset or any other value means **on**. A skipped command still reports SUCCESS.

## Maven resolution

Syft's offline Maven resolution, both on by default (see [Maven prep](prep-guide.md#maven)):

| Variable | Set to `"false"` to |
|---|---|
| `SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES` | stop resolving the transitive tree |
| `SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY` | stop reading the local `~/.m2` cache |

Set both to `"false"` for declared-only Maven results. Everything stays offline either way.

## Setting variables

Any of these three places, later ones winning:

1. the shell that launches voyager: `DEPMINER_RUN_TRIVY=false ./voyager.sh`
2. `.config.yml` in the voyager folder, under `environment:`
3. `mission.yml` under `environment:`, the highest priority:

```yaml
environment:
  DEPMINER_RUN_TRIVY: "false"
```

## Failed projects

Syft and Trivy scan every project even when one fails: the failure is logged, the remaining
projects still get their SBOMs, and the command reports **FAILED** with a summary of which ones.
All other result files are still written.

## Copying and scrubbing

| File | Controls |
|---|---|
| `depminer.yml` | which manifests and lockfiles get copied, per language |
| `.ignore.yml` | what is never copied: `.npmrc`, `nuget.config`, `pip.conf`, `settings.xml` and the like, which carry no dependency information and are where registry tokens live |
| `sanitize.yml` | credential patterns applied to every copied file |

All three are plain wildcard lists and can be edited per install. Each `sanitize.yml` pattern takes
an optional `scope`:

| `scope` | Runs on |
|---|---|
| `all` (default) | every copied file |
| `manifests` | every copied file **except lockfiles** |

??? info "Why lockfiles are scoped out"
    A lockfile is generated text where every line is a resolved package and its version, so a
    pattern written for config files (`jdbc:…`, `token=…`, `host: …`) can match a package *name*
    and rewrite its version. The shipped `sanitize.yml` marks those patterns `manifests`; patterns
    with a distinctive prefix (`AKIA`, `ghp_`, `glpat-`, `_authToken=`, `://user:token@`) keep
    running on lockfiles too.

    When a pattern does rewrite a line inside a lockfile, the file is listed in
    `results/scrub-report.json` with reason `redacted-inside-lockfile`: the rule that matched and
    how many lines, never the value.

A file removed entirely during scrubbing (a private key inside it) is dropped from `index.json` and
listed in `results/depminer/skipped.json` with its original path and the reason.
