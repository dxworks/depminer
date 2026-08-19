#!/usr/bin/env bash
# Voyager depminer instrument — Trivy wrapper (unix).
# Extraction-only, 100% offline: SBOM formats disable Trivy's security scanning,
# --offline-scan blocks Maven Central lookups, and telemetry/version-check/DB
# updates are all forced off. No network call is ever attempted.
# The instrument runs "once", so <target-path> holds all repositories: each immediate
# subdirectory is scanned as its own project; if there are none, the target itself is.
# Usage: trivy-wrapper.sh <target-path> <output-dir>
set -euo pipefail

TARGET="${1:?target path required}"
OUT="${2:?output dir required}"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if [ "${DEPMINER_RUN_TRIVY:-true}" = "false" ]; then
  echo ">> Trivy disabled (DEPMINER_RUN_TRIVY=false) - skipping"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="${HERE}/../.trivy-cache"   # stays empty in this mode; kept out of results/

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)   arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
esac
case "$os" in
  darwin) os="darwin" ;;
  *)      os="linux"  ;;
esac

BIN="${HERE}/trivy-${os}-${arch}"

# Some unzip implementations (e.g. voyenv's) drop unix exec bits — restore ours.
if [[ -f "$BIN" && ! -x "$BIN" ]]; then
  chmod +x "$BIN" 2>/dev/null || true
fi

if [[ ! -x "$BIN" ]]; then
  if command -v trivy >/dev/null 2>&1; then
    BIN="$(command -v trivy)"
  else
    echo "ERROR: no bundled binary 'trivy-${os}-${arch}' and no 'trivy' on PATH" >&2
    exit 1
  fi
fi

mkdir -p "$OUT" "$CACHE"
echo ">> trivy: $BIN"

TARGET_ABS="$(cd "$TARGET" 2>/dev/null && pwd || true)"
OUT_ABS="$(cd "$OUT" 2>/dev/null && pwd || true)"

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
_esc_re()  { printf '%s' "$1" | sed 's/[][\\.*^$\/&]/\\&/g'; }
_esc_rep() { printf '%s' "$1" | sed 's/[\\\/&]/\\&/g'; }
_abs()     { (cd "$1" 2>/dev/null && pwd) || true; }

# _rule <absolute-path> <replacement> - appended to $_scrub_script.
# Only ABSOLUTE paths are rewritten: a relative one cannot leak a host layout, and
# substituting it would corrupt unrelated text.
_rule() {
  local from="${1%/}" to="$2"
  case "$from" in
    /?*) _scrub_script="${_scrub_script}s/$(_esc_re "$from")/$(_esc_rep "$to")/g;" ;;
  esac
}

# sanitize_files <repo-path-as-passed> <project-name> <file>...
sanitize_files() {
  local repo="${1%/}" name="$2"; shift 2
  local repo_abs f tmp
  repo_abs="$(_abs "$repo")"
  _scrub_script=""
  # Longest / most specific first: the repo sits under the target, which may sit
  # under HOME. Both the path as passed and its symlink-resolved form are covered,
  # because the tools echo back whichever spelling they were given.
  _rule "$repo" "$name"
  if [ -n "$repo_abs" ] && [ "$repo_abs" != "$repo" ]; then _rule "$repo_abs" "$name"; fi
  _rule "$TARGET" "."
  if [ -n "$TARGET_ABS" ] && [ "$TARGET_ABS" != "${TARGET%/}" ]; then _rule "$TARGET_ABS" "."; fi
  _rule "$OUT" "."
  if [ -n "$OUT_ABS" ] && [ "$OUT_ABS" != "${OUT%/}" ]; then _rule "$OUT_ABS" "."; fi
  _rule "${HOME:-}" "~"
  [ -n "$_scrub_script" ] || return 0
  for f in "$@"; do
    [ -f "$f" ] || continue
    tmp="${f}.scrub"
    if sed "$_scrub_script" "$f" > "$tmp"; then mv -f "$tmp" "$f"; else rm -f "$tmp"; fi
  done
}
# -------------------------------------------------------------------------------

scan_one() {
  local repo="$1" name="$2" rc=0
  echo ">> trivy scanning: ${name}"
  "$BIN" fs \
    --cache-dir "$CACHE" \
    --offline-scan \
    --skip-db-update --skip-java-db-update \
    --disable-telemetry --skip-version-check \
    --format cyclonedx \
    --output "${OUT}/${name}.trivy.cdx.json" \
    --quiet \
    "$repo" || rc=$?
  # Runs even on failure: a partial SBOM must not leak host paths either.
  sanitize_files "$repo" "$name" "${OUT}/${name}.trivy.cdx.json"
  return $rc
}

# One failing project must not cost the others their SBOMs: log it, keep going,
# report all failures at the end (the command then still fails in the mission summary).
found=0
fail_count=0
fail_names=""
for d in "$TARGET"/*/; do
  [[ -d "$d" ]] || continue
  found=1
  name="$(basename "${d%/}")"
  scan_one "${d%/}" "$name" || {
    rc=$?
    echo ">> WARN: trivy failed for '${name}' (exit ${rc}) - continuing with remaining projects" >&2
    fail_count=$((fail_count + 1))
    fail_names="${fail_names} ${name}"
  }
done
if [[ $found -eq 0 ]]; then
  name="$(basename "$TARGET")"
  scan_one "$TARGET" "$name" || {
    rc=$?
    echo ">> WARN: trivy failed for '${name}' (exit ${rc})" >&2
    fail_count=1
    fail_names=" ${name}"
  }
fi

if [[ $fail_count -gt 0 ]]; then
  echo ">> trivy done with ${fail_count} failed project(s):${fail_names} -> ${OUT}" >&2
  exit 1
fi
echo ">> trivy done -> ${OUT}"
