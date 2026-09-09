<#
    Voyager depminer instrument - Trivy wrapper (Windows).
    Extraction-only, 100% offline: SBOM formats disable Trivy's security scanning,
    --offline-scan blocks Maven Central lookups, and telemetry/version-check/DB
    updates are all forced off. No network call is ever attempted.
    The instrument runs "once", so <target-path> holds all repositories: each
    subdirectory is scanned as its own project; if there are none, the target itself is.
    Usage: trivy-wrapper.ps1 <target-path> <output-dir>
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = "Stop"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if ($env:DEPMINER_RUN_TRIVY -eq "false") {
    Write-Host ">> Trivy disabled (DEPMINER_RUN_TRIVY=false) - skipping"
    exit 0
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cache = Join-Path (Split-Path -Parent $here) ".trivy-cache"   # stays empty in this mode

# Only windows amd64 is bundled (Trivy publishes no windows-arm64 build).
$bin = Join-Path $here "trivy-windows-amd64.exe"
if (-not (Test-Path $bin)) {
    $onPath = Get-Command trivy -ErrorAction SilentlyContinue
    if ($onPath) { $bin = $onPath.Source }
    else { Write-Error "no bundled 'trivy-windows-amd64.exe' and no 'trivy' on PATH"; exit 1 }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
New-Item -ItemType Directory -Force -Path $cache | Out-Null
Write-Host ">> trivy: $bin"

# --- Staging -------------------------------------------------------------------
# Trivy writes HERE, never straight into $Out: a file reaches $Out only after
# its scrub has succeeded (see Remove-HostPaths). Mirrors the unix twin, and closes the
# same abort paths: a scrub that throws, a Ctrl-C, a mission timeout all leave the
# unscrubbed SBOM in staging - never in $Out, which is what Voyager collects.
#
# It also removes the locked-file hazard: the old code deleted the unscrubbed file from
# $Out with `Remove-Item -Force -ErrorAction SilentlyContinue`, so on Windows a file still
# held open by a scanner or an AV scanner survived the delete and stayed collectable.
# Nothing unscrubbed is written under $Out any more, so a failed delete cannot leak.
# GetRandomFileName keeps concurrent projects apart (the wrappers run per project).
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("depminer-trivy." + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# --- Host-path scrubbing -------------------------------------------------------
# The SBOMs are the ONLY artefacts that leave the client's machine, so they must not
# carry the client's filesystem layout. Both tools record the scanned directory as an
# ABSOLUTE path in several places (Syft: source.name, source.metadata.path, the "file"
# component in CycloneDX, the SPDX document name and namespace, plus HOME-derived cache
# dirs under descriptor.configuration; Trivy: metadata.component.name). No CLI flag
# covers all of them - Syft's --source-name leaves source.metadata.path and the file
# component behind, and Trivy has no equivalent flag at all - so the emitted JSON is
# rewritten here, after the scan.
#
# Repo-RELATIVE paths (syft:location:*:path, Trivy's "pom.xml" application component)
# are deliberately left intact: the downstream parser groups components by them to
# reconstruct project boundaries.
#
# Mirrors the unix wrapper's sanitize_files(). Windows adds one wrinkle: a path can
# appear in the JSON in three spellings - raw (C:\repos\app), JSON-escaped
# (C:\\repos\\app) and forward-slashed (C:/repos/app) - so each rule covers all three.
function Get-AbsPathOrEmpty([string]$p) {
    if (-not $p) { return "" }
    try { return (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { return "" }
}

function Add-ScrubRule([System.Collections.ArrayList]$rules, [string]$from, [string]$to) {
    if (-not $from) { return }
    $from = $from.TrimEnd('\', '/')
    # Only ABSOLUTE paths are rewritten: a relative one cannot leak a host layout, and
    # substituting it would corrupt unrelated text.
    if (-not [System.IO.Path]::IsPathRooted($from)) { return }
    # A ROOT is never a scrub rule. 'C:\'.TrimEnd() is 'C:', which IsPathRooted accepts, and the
    # resulting rule rewrites every occurrence of 'C:' in the SBOM - including inside unrelated
    # strings - corrupting the file wholesale. The unix twin rejects the analogous '/' via its
    # `case $from in /?*)` guard; these are the Windows spellings of the same thing:
    #   'C:'      a drive root              '\' or '/'   a rooted path with no directory
    #   '\\server\share'  a UNC share root (nothing above it belongs to us either)
    if ($from -match '^[A-Za-z]:$') { return }
    if ($from -match '^[\\/]$') { return }
    if ($from -match '^\\\\[^\\/]+\\[^\\/]+$') { return }
    foreach ($spelling in @($from, ($from -replace '\\', '\\'), ($from -replace '\\', '/'))) {
        if ($rules.ToArray() | Where-Object { $_[0] -eq $spelling }) { continue }
        [void]$rules.Add(@($spelling, $to))
    }
}

function Remove-HostPaths([string]$repo, [string]$name, [string[]]$files) {
    $rules = New-Object System.Collections.ArrayList
    # Longest / most specific first: the repo sits under the target, which may sit
    # under HOME. Both the path as passed and its resolved form are covered, because
    # the tools echo back whichever spelling they were given.
    Add-ScrubRule $rules $repo $name
    Add-ScrubRule $rules (Get-AbsPathOrEmpty $repo) $name
    Add-ScrubRule $rules $Target "."
    Add-ScrubRule $rules (Get-AbsPathOrEmpty $Target) "."
    # The staging dir takes the place $Out used to hold in the emitted JSON (Trivy
    # echoes back the output paths it was given), so it is rewritten to the same ".".
    Add-ScrubRule $rules $stage "."
    Add-ScrubRule $rules (Get-AbsPathOrEmpty $stage) "."
    Add-ScrubRule $rules $Out "."
    Add-ScrubRule $rules (Get-AbsPathOrEmpty $Out) "."
    Add-ScrubRule $rules $HOME "~"
    # A file that could not be scrubbed is DELETED from staging, never moved into $Out, and
    # the failure is propagated - the same fail-CLOSED rule the unix twin follows. Shipping it
    # anyway would send the one artefact that leaves the client's machine with the host paths
    # still in it, while the wrapper reports success. A missing file is loud; a leaking file
    # is silent.
    $failures = 0
    foreach ($f in $files) {
        $src = Join-Path $stage $f
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dest = Join-Path $Out $f
        # No absolute path anywhere to rewrite (everything was passed relative): the file
        # still has to reach $Out, it just needs no rewriting.
        if ($rules.Count -eq 0) {
            try { Move-Item -LiteralPath $src -Destination $dest -Force }
            catch {
                Write-Error "could not move $f into the output dir" -ErrorAction Continue
                $failures++
            }
            continue
        }
        # Scrubbed text is written next to its destination and renamed into place, so the
        # file that lands in $Out is complete or absent - never half-written. Only
        # ALREADY-scrubbed bytes are ever written under $Out; the name is per-process.
        $tmp = "$dest.scrub.$PID"
        try {
            $text = [System.IO.File]::ReadAllText($src)
            foreach ($r in $rules) { $text = $text.Replace($r[0], $r[1]) }
            [System.IO.File]::WriteAllText($tmp, $text)
            Move-Item -LiteralPath $tmp -Destination $dest -Force
            Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue
        } catch {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue
            Write-Error "could not strip host paths from $f - nothing was written to the output dir rather than a file with host paths in it" -ErrorAction Continue
            $failures++
        }
    }
    if ($failures -gt 0) { throw "host-path scrubbing failed for $failures file(s)" }
}
# -------------------------------------------------------------------------------

# --include-dev-deps keeps development-scoped packages (npm/yarn/pnpm devDependencies,
# composer packages-dev, uv.lock dev groups, gradle) instead of pruning them: Black Duck reports them,
# so must we. It only changes lockfile parsing - still no network.
function Scan-One([string]$repo, [string]$name) {
    Write-Host ">> trivy scanning: $name"
    # The scan is wrapped so the scrub ALWAYS runs, matching the unix twin's `|| rc=$?`.
    # Under PowerShell 7.4+ $PSNativeCommandUseErrorActionPreference defaults to $true, so with
    # $ErrorActionPreference = "Stop" a non-zero exit from the tool raises a TERMINATING error at
    # the invocation line - which would skip the scrub entirely and leave a partial, unscrubbed
    # SBOM in the output dir for Voyager to collect.
    $rc = 0
    try {
        & $bin fs `
            --cache-dir $cache `
            --offline-scan `
            --skip-db-update --skip-java-db-update `
            --disable-telemetry --skip-version-check `
            --include-dev-deps `
            --format cyclonedx `
            --output "$stage/$name.trivy.cdx.json" `
            --quiet `
            $repo
        $rc = $LASTEXITCODE
    } catch {
        Write-Host ">> WARN: trivy invocation failed for '$name': $_"
        if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE } else { $rc = 1 }
    }
    # Runs even on failure: a partial SBOM must not leak host paths either.
    Remove-HostPaths $repo $name @("$name.trivy.cdx.json")
    if ($rc -ne 0) { throw "trivy failed for '$name' (exit $rc)" }
}

# One failing project must not cost the others their SBOMs: log it, keep going,
# report all failures at the end (the command then still fails in the mission summary).
# The finally block is this script's `trap`: PowerShell has no signal traps, but it runs
# finally on a throw, on `exit`, and on Ctrl-C, so staging does not outlive the run.
$failed = @()
try {
    $projects = Get-ChildItem -LiteralPath $Target -Directory -ErrorAction SilentlyContinue
    if ($projects -and $projects.Count -gt 0) {
        foreach ($p in $projects) {
            try { Scan-One $p.FullName $p.Name }
            catch {
                Write-Host ">> WARN: $_ - continuing with remaining projects"
                $failed += $p.Name
            }
        }
    } else {
        $name = Split-Path -Leaf $Target
        try { Scan-One $Target $name }
        catch {
            Write-Host ">> WARN: $_"
            $failed += $name
        }
    }

    if ($failed.Count -gt 0) {
        Write-Host ">> trivy done with $($failed.Count) failed project(s): $($failed -join ', ') -> $Out"
        exit 1
    }
    Write-Host ">> trivy done -> $Out"
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
