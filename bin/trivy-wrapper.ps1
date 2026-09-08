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
    Add-ScrubRule $rules $Out "."
    Add-ScrubRule $rules (Get-AbsPathOrEmpty $Out) "."
    Add-ScrubRule $rules $HOME "~"
    if ($rules.Count -eq 0) { return }
    # A file that could not be scrubbed is DELETED, and the failure is propagated - the same
    # fail-CLOSED rule the unix twin follows. Leaving the original in place ships the one artefact
    # that leaves the client's machine with the host paths still in it, while the wrapper reports
    # success. A missing file is loud; a leaking file is silent.
    $failures = 0
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $text = [System.IO.File]::ReadAllText($f)
            foreach ($r in $rules) { $text = $text.Replace($r[0], $r[1]) }
            [System.IO.File]::WriteAllText($f, $text)
        } catch {
            Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            Write-Error "could not strip host paths from $(Split-Path -Leaf $f) - the file was deleted rather than shipped with them" -ErrorAction Continue
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
            --output "$Out/$name.trivy.cdx.json" `
            --quiet `
            $repo
        $rc = $LASTEXITCODE
    } catch {
        Write-Host ">> WARN: trivy invocation failed for '$name': $_"
        if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE } else { $rc = 1 }
    }
    # Runs even on failure: a partial SBOM must not leak host paths either.
    Remove-HostPaths $repo $name @("$Out/$name.trivy.cdx.json")
    if ($rc -ne 0) { throw "trivy failed for '$name' (exit $rc)" }
}

# One failing project must not cost the others their SBOMs: log it, keep going,
# report all failures at the end (the command then still fails in the mission summary).
$failed = @()
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
