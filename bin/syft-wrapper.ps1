<#
    Voyager depminer instrument - Syft wrapper (Windows).
    Extraction-only, 100% offline: every Syft network touchpoint is forced off here
    (belt-and-braces with instrument.yml's environment block).
    The instrument runs "once", so <target-path> holds all repositories: each
    subdirectory is scanned as its own project; if there are none, the target itself is.
    Usage: syft-wrapper.ps1 <target-path> <output-dir> [report-dir]
    <output-dir> is this tool's own subfolder of results/ (see instrument.yml);
    [report-dir] is where the shared scrub-report.json goes, and defaults to <output-dir>.
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$Out,
    # All three producers write into their own subfolder but share ONE scrub report, so that a
    # consumer has a single file to read to learn whether anything in the run shipped unclean.
    # Defaults to $Out, which is what a standalone run wants.
    [Parameter(Mandatory = $false)][string]$ReportDir = ""
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
$reportRoot = if ([string]::IsNullOrWhiteSpace($ReportDir)) { $Out } else { $ReportDir }
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null
# Each producer owns its output dir and clears it, the way the jar clears results/depminer
# (DepMi.kt). Before the per-tool split the jar's wipe of results/ cleaned up after these
# wrappers too; now nothing else does, and two runs into the same install would blend - last
# run's SBOM for a repo since removed from the target sitting beside this run's. Only files
# directly in $Out, which is all this wrapper ever writes there, and never the shared report:
# another producer may already have written into it.
Get-ChildItem -LiteralPath $Out -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne "scrub-report.json" } |
    Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host ">> syft: $bin"

# --- Staging -------------------------------------------------------------------
# Syft writes HERE, never straight into $Out: a file reaches $Out only after
# its scrub has succeeded (see Remove-HostPaths). Mirrors the unix twin, and closes the
# same abort paths: a scrub that throws, a Ctrl-C, a mission timeout all leave the
# unscrubbed SBOM in staging - never in $Out, which is what Voyager collects.
#
# It also removes the locked-file hazard: the old code deleted the unscrubbed file from
# $Out with `Remove-Item -Force -ErrorAction SilentlyContinue`, so on Windows a file still
# held open by a scanner or an AV scanner survived the delete and stayed collectable.
# Nothing unscrubbed is written under $Out any more, so a failed delete cannot leak.
# GetRandomFileName keeps concurrent projects apart (the wrappers run per project).
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("depminer-syft." + [System.IO.Path]::GetRandomFileName())
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

function Add-ScrubRule([System.Collections.ArrayList]$rules, [string]$class, [string]$from, [string]$to) {
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
        [void]$rules.Add(@($spelling, $to, $class))
    }
}

# --- The withheld-file report --------------------------------------------------
# A file that still carries a host path after scrubbing IS STILL EMITTED - Alex's call. Nothing
# is deleted, held back or renamed, and the run carries on and exits on the scanner's own
# result. The consequence is stated plainly because it is the whole point of this block: those
# bytes ship, and $Out\scrub-report.json is the ONLY record that they are not clean.
#
# It is written on EVERY run - with an empty "flagged" list when everything verified - so that
# "there was nothing to scan" and "this file shipped with host data in it" can be told apart
# without reading the log. The array is called "flagged", not "withheld": nothing was.
# The leaked VALUE never goes into the report: that would only copy the leak into a new file.
$script:wrapperName = "syft"
$script:report = Join-Path $reportRoot "scrub-report.json"
# This run's own entries, kept whole: Write-ScrubReport drops this wrapper's previous
# entries from the file and restates them from here, so a rerun replaces them instead of
# stacking a second copy onto the first.
$script:ownEntries = @()
$script:flagged = 0
$script:emitted = 0

function Write-ScrubReport([object[]]$entries) {
    if ($entries) { $script:ownEntries += $entries }
    # Entries from the OTHER producers - the jar and the other wrapper - are carried over
    # verbatim; this wrapper's own are dropped and restated from $script:ownEntries.
    $existing = @()
    if (Test-Path -LiteralPath $script:report) {
        try {
            $parsed = Get-Content -LiteralPath $script:report -Raw | ConvertFrom-Json
            if ($parsed.flagged) {
                $existing = @($parsed.flagged) | Where-Object { $_.wrapper -ne $script:wrapperName }
            }
        } catch { $existing = @() }
    }
    $all = @($existing) + @($script:ownEntries)
    $doc = [ordered]@{ schemaVersion = 1; flagged = $all }
    ($doc | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $script:report -Encoding utf8
}

function Add-Flagged([string]$project, [string]$file, [string[]]$classes, [int]$count) {
    Write-Host (">> WARNING: $file for '$project' was emitted but FAILED scrub verification - it " +
        "still carries host data ($count occurrence(s), rules: $($classes -join ', ')) - see $(Split-Path -Leaf $script:report)")
    Write-ScrubReport @([ordered]@{
        timestamp     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        wrapper       = $script:wrapperName
        project       = $project
        file          = $file
        reason        = "emitted-despite-failed-scrub-verification"
        matchedRules  = $classes
        matchCount    = $count
    })
    $script:flagged++
}

# The aggregate line: a consumer must be able to see that some of this run's output carries host
# data without reading every line of the log.
function Write-RunSummary() {
    Write-ScrubReport @()
    if ($script:flagged -gt 0) {
        Write-Host ">> WARNING: $($script:flagged) of $($script:emitted) emitted file(s) FAILED scrub verification and carry host data - see $(Split-Path -Leaf $script:report)"
    }
}

function Remove-HostPaths([string]$repo, [string]$name, [string[]]$files) {
    $rules = New-Object System.Collections.ArrayList
    # Longest / most specific first: the repo sits under the target, which may sit
    # under HOME. Both the path as passed and its resolved form are covered, because
    # the tools echo back whichever spelling they were given.
    Add-ScrubRule $rules "repo" $repo $name
    Add-ScrubRule $rules "repo" (Get-AbsPathOrEmpty $repo) $name
    Add-ScrubRule $rules "target" $Target "."
    Add-ScrubRule $rules "target" (Get-AbsPathOrEmpty $Target) "."
    # The staging dir takes the place $Out used to hold in the emitted JSON (Syft
    # echoes back the output paths it was given), so it is rewritten to the same ".".
    Add-ScrubRule $rules "staging" $stage "."
    Add-ScrubRule $rules "staging" (Get-AbsPathOrEmpty $stage) "."
    Add-ScrubRule $rules "out" $Out "."
    Add-ScrubRule $rules "out" (Get-AbsPathOrEmpty $Out) "."
    # $Out's parent since the split, and added AFTER it so the longer path is rewritten first:
    # the shorter rule would otherwise cut the longer one in half and leave the tail behind.
    if ($reportRoot -ne $Out) {
        Add-ScrubRule $rules "out" $reportRoot "."
        Add-ScrubRule $rules "out" (Get-AbsPathOrEmpty $reportRoot) "."
    }
    Add-ScrubRule $rules "home" $HOME "~"
    # NOTHING IS EVER DELETED OR HELD BACK - the same rule the unix twin follows. A file whose
    # verification fails is emitted anyway, in its best-effort scrubbed form, and the report is
    # the only record that it is not clean. It does not fail the project either.
    foreach ($f in $files) {
        $src = Join-Path $stage $f
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dest = Join-Path $Out $f
        # Scrubbed text is written next to its destination and renamed into place, so the
        # file that lands in $Out is complete or absent - never half-written. Only
        # ALREADY-scrubbed AND VERIFIED bytes are ever written under $Out; the name is
        # per-process.
        $tmp = "$dest.scrub.$PID"
        try {
            $text = [System.IO.File]::ReadAllText($src)
            foreach ($r in $rules) {
                # Anchored on a path boundary: the match must be followed by a separator or by
                # the closing quote of the JSON string. An unanchored Replace() also rewrites a
                # SIBLING directory that merely starts with the same characters - with
                # HOME=C:\Users\alex, "C:\Users\alexandra\x" came out as "~andra\x":
                # corrupted, and still carrying part of the host layout. Anything the anchor
                # now misses is caught by the verification below instead of passing silently.
                $text = [regex]::Replace($text, [regex]::Escape($r[0]) + '(?=[/\\"])', $r[1].Replace('$', '$$'))
            }
            # Credentials embedded in a lockfile's "resolved" URL - https://user:token@nexus/... -
            # are copied verbatim into the SBOM by the scanner, and sanitize.yml never sees these
            # files (the jar sanitises its own results dir, and it runs before this wrapper).
            $text = [regex]::Replace($text, '://[^/"\s]*@', '://')
            # The scrub is a chain of string rewrites, and a rule that silently matched nothing
            # leaves the host layout in a file the wrapper then reports as done. So the RESULT is
            # checked, not the steps: a file that still carries one of the literal paths, or a
            # credential, is thrown away and its project fails. A missing file is loud, a leaking
            # file is silent.
            $classes = @()
            $count = 0
            foreach ($r in $rules) {
                $hits = ([regex]::Matches($text, [regex]::Escape($r[0]))).Count
                if ($hits -gt 0) {
                    if ($classes -notcontains $r[2]) { $classes += $r[2] }
                    $count += $hits
                }
            }
            if ([regex]::IsMatch($text, '://[^/"\s]*@')) {
                $classes += "url-userinfo"
                $count++
            }
            [System.IO.File]::WriteAllText($tmp, $text)
            Move-Item -LiteralPath $tmp -Destination $dest -Force
            Remove-Item -LiteralPath $src -Force -ErrorAction SilentlyContinue
            $script:emitted++
            if ($count -gt 0) { Add-Flagged $name $f $classes $count }
        } catch {
            # The rewrite itself failed, so there is no scrubbed version: the staged original is
            # the only complete file, and it is emitted rather than dropped.
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            try {
                Move-Item -LiteralPath $src -Destination $dest -Force
                $script:emitted++
                Add-Flagged $name $f @("scrub-command-failed") 0
            } catch {
                Write-Host ">> WARNING: could not move $f into the output dir for '$name'"
            }
        }
    }
}
# -------------------------------------------------------------------------------

function Scan-One([string]$repo, [string]$name) {
    Write-Host ">> syft scanning: $name"
    # --source-name pins the root component to the project name instead of the scanned
    # path; the scrub below covers everything the flag does not reach.
    # The scan is wrapped so the scrub ALWAYS runs, matching the unix twin's `|| rc=$?`.
    # Under PowerShell 7.4+ $PSNativeCommandUseErrorActionPreference defaults to $true, so with
    # $ErrorActionPreference = "Stop" a non-zero exit from the tool raises a TERMINATING error at
    # the invocation line - which would skip the scrub entirely and leave a partial, unscrubbed
    # SBOM in the output dir for Voyager to collect.
    $rc = 0
    try {
        # The scanner's diagnostics were going only to the mission log, which Voyager does not
        # collect with the results: an empty or short SBOM then had no explanation travelling next
        # to it. They are captured here, still echoed so the mission log keeps them, and kept only
        # when non-empty. The log is scrubbed like any other emitted file - it quotes paths too.
        & $bin scan "dir:$repo" `
            --source-name $name `
            -o "syft-json=$stage/$name.syft.json" `
            -o "cyclonedx-json=$stage/$name.cdx.json" `
            -o "spdx-json=$stage/$name.spdx.json" `
            -q 2> "$stage/$name.syft.err.log"
        $rc = $LASTEXITCODE
    } catch {
        Write-Host ">> WARN: syft invocation failed for '$name': $_"
        if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE } else { $rc = 1 }
    }
    # Runs even on failure: a partial SBOM must not leak host paths either.
    $err = Join-Path $stage "$name.syft.err.log"
    if ((Test-Path -LiteralPath $err) -and (Get-Item -LiteralPath $err).Length -gt 0) {
        Get-Content -LiteralPath $err | ForEach-Object { Write-Host $_ }
    } else {
        Remove-Item -LiteralPath $err -Force -ErrorAction SilentlyContinue
    }
    Remove-HostPaths $repo $name @(
        "$name.syft.json",
        "$name.cdx.json",
        "$name.spdx.json",
        "$name.syft.err.log")
    if ($rc -ne 0) { throw "syft failed for '$name' (exit $rc)" }
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

    Write-RunSummary
    if ($failed.Count -gt 0) {
        Write-Host ">> syft done with $($failed.Count) failed project(s): $($failed -join ', ') -> $Out"
        exit 1
    }
    Write-Host ">> syft done -> $Out"
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
