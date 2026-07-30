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

function Scan-One([string]$repo, [string]$name) {
    Write-Host ">> trivy scanning: $name"
    & $bin fs `
        --cache-dir $cache `
        --offline-scan `
        --skip-db-update --skip-java-db-update `
        --disable-telemetry --skip-version-check `
        --format cyclonedx `
        --output "$Out/$name.trivy.cdx.json" `
        --quiet `
        $repo
    if ($LASTEXITCODE -ne 0) { throw "trivy failed for '$name' (exit $LASTEXITCODE)" }
}

# One failing project must not cost the others their SBOMs: log it, keep going,
# report all failures at the end (the command then still fails in the mission summary).
$failed = @()
$projects = Get-ChildItem -Path $Target -Directory -ErrorAction SilentlyContinue
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
