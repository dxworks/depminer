<#
    Voyager depminer instrument - Syft wrapper (Windows).
    Extraction-only, 100% offline: every Syft network touchpoint is forced off here
    (belt-and-braces with instrument.yml's environment block).
    The instrument runs "once", so <target-path> holds all repositories: each
    subdirectory is scanned as its own project; if there are none, the target itself is.
    Usage: syft-wrapper.ps1 <target-path> <output-dir>
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = "Stop"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if ($env:DEPMINER_RUN_SYFT -eq "false") {
    Write-Host ">> Syft disabled (DEPMINER_RUN_SYFT=false) - skipping"
    exit 0
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$env:SYFT_CHECK_FOR_APP_UPDATE = "false"
$env:SYFT_GOLANG_SEARCH_REMOTE_LICENSES = "false"
$env:SYFT_GOLANG_USE_PACKAGES_LIB = "false"
$env:SYFT_JAVA_USE_NETWORK = "false"
# Maven transitive deps, still offline: resolve the tree from ~/.m2 (BOTH required; still
# offline because USE_NETWORK stays false). No-op unless ~/.m2 is populated - see PREP_GUIDE.md.
# Default-on but overridable: set them to "false" in mission.yml / .config.yml / the host
# shell to skip local-repo resolution (e.g. if it is ever pathologically slow).
if (-not $env:SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES) { $env:SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES = "true" }
if (-not $env:SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY) { $env:SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY = "true" }
$env:SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES = "false"
# Include devDependencies from package-lock.json / yarn.lock (pure lockfile parsing, no
# network). Black Duck reports them, so must we. Javascript is the only Syft cataloger with
# this switch; the other ecosystems come from Trivy's --include-dev-deps (trivy-wrapper.ps1).
$env:SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES = "true"
$env:SYFT_PYTHON_SEARCH_REMOTE_LICENSES = "false"

# Only windows amd64 is bundled (see scripts/prepare-release-voyager.sh).
$bin = Join-Path $here "syft-windows-amd64.exe"
if (-not (Test-Path $bin)) {
    $onPath = Get-Command syft -ErrorAction SilentlyContinue
    if ($onPath) { $bin = $onPath.Source }
    else { Write-Error "no bundled 'syft-windows-amd64.exe' and no 'syft' on PATH"; exit 1 }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
Write-Host ">> syft: $bin"

function Scan-One([string]$repo, [string]$name) {
    Write-Host ">> syft scanning: $name"
    & $bin scan "dir:$repo" `
        -o "syft-json=$Out/$name.syft.json" `
        -o "cyclonedx-json=$Out/$name.cdx.json" `
        -o "spdx-json=$Out/$name.spdx.json" `
        -q
    if ($LASTEXITCODE -ne 0) { throw "syft failed for '$name' (exit $LASTEXITCODE)" }
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
    Write-Host ">> syft done with $($failed.Count) failed project(s): $($failed -join ', ') -> $Out"
    exit 1
}
Write-Host ">> syft done -> $Out"
