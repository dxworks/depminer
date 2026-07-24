# Configuration

All three tools run by default — you only need this page when you want to **turn some off** or tune
Syft's offline Maven resolution.

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

Command names must match [the command table](index.md) exactly. If `commands` is empty or missing,
Voyager runs all three (requires `runsAll: false` in the install's `.config.yml`, which
voyenv-built bundles set).

### Per environment variable — explicit on/off switches

| Variable | Effect when set to `"false"` |
|---|---|
| `DEPMINER_RUN_MINER` | skip depminer's own extraction |
| `DEPMINER_RUN_SYFT` | skip Syft |
| `DEPMINER_RUN_TRIVY` | skip Trivy |

Unset or any other value means **ON**. A skipped command still reports SUCCESS in the mission
summary (it just logs that it was skipped).

Set the variables in any of these places — **later ones win**:

1. the shell that launches voyager (`DEPMINER_RUN_TRIVY=false ./voyager.sh mission.yml`)
2. `.config.yml` in the voyager folder, under `environment:`
3. `mission.yml` under `environment:` — **highest priority**, recommended for prod:

```yaml
environment:
  DEPMINER_RUN_TRIVY: "false"
```

## Syft offline Maven resolution

Two more switches control Syft's offline Maven resolution (see
[Preparing Your Project → Maven](prep-guide.md#maven)). They accept the same three locations and
precedence as above:

| Variable | Default | Set to `"false"` to… |
|---|---|---|
| `SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES` | `"true"` | stop resolving the transitive tree |
| `SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY` | `"true"` | stop reading the local `~/.m2` cache |

Both default to `"true"` — resolve the full transitive tree from the local `~/.m2` cache. Set
**both** to `"false"` to fall back to declared-only Maven results. Everything stays offline either
way.

## When one project fails to scan

Syft and Trivy scan every project in the target even if one of them fails:

- the failing project is logged with a warning,
- the remaining projects still get their SBOMs,
- the command finishes with a summary of failed projects.

The command then reports as **FAILED** in the mission summary — check its log to see which projects
were affected. All other result files are still written.
