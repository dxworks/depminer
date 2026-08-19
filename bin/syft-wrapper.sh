#!/usr/bin/env bash
# Voyager depminer instrument — Syft wrapper (unix).
# Extraction-only, 100% offline: every Syft network touchpoint is forced off here
# (belt-and-braces with instrument.yml's environment block, so the wrapper is also
# safe when run standalone outside Voyager).
# The instrument runs "once", so <target-path> holds all repositories: each immediate
# subdirectory is scanned as its own project; if there are none, the target itself is.
# Usage: syft-wrapper.sh <target-path> <output-dir>
set -euo pipefail

TARGET="${1:?target path required}"
OUT="${2:?output dir required}"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if [ "${DEPMINER_RUN_SYFT:-true}" = "false" ]; then
  echo ">> Syft disabled (DEPMINER_RUN_SYFT=false) - skipping"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

export SYFT_CHECK_FOR_APP_UPDATE=false
export SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false
export SYFT_GOLANG_USE_PACKAGES_LIB=false
export SYFT_JAVA_USE_NETWORK=false
# Maven transitive deps, still offline: resolve the tree from ~/.m2 (BOTH required; still
# offline because USE_NETWORK stays false). No-op unless ~/.m2 is populated — see PREP_GUIDE.md.
# Default-on but overridable: set them to "false" in mission.yml / .config.yml / the host
# shell to skip local-repo resolution (e.g. if it is ever pathologically slow).
export SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES="${SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES:-true}"
export SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY="${SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY:-true}"
export SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=false
export SYFT_PYTHON_SEARCH_REMOTE_LICENSES=false

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

BIN="${HERE}/syft-${os}-${arch}"

# Some unzip implementations (e.g. voyenv's) drop unix exec bits — restore ours.
if [[ -f "$BIN" && ! -x "$BIN" ]]; then
  chmod +x "$BIN" 2>/dev/null || true
fi

if [[ ! -x "$BIN" ]]; then
  if command -v syft >/dev/null 2>&1; then
    BIN="$(command -v syft)"
  else
    echo "ERROR: no bundled binary 'syft-${os}-${arch}' and no 'syft' on PATH" >&2
    exit 1
  fi
fi

mkdir -p "$OUT"
echo ">> syft: $BIN"

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
  echo ">> syft scanning: ${name}"
  # --source-name pins the root component to the project name instead of the scanned
  # path; the scrub below covers everything the flag does not reach.
  "$BIN" scan "dir:${repo}" \
    --source-name "${name}" \
    -o "syft-json=${OUT}/${name}.syft.json" \
    -o "cyclonedx-json=${OUT}/${name}.cdx.json" \
    -o "spdx-json=${OUT}/${name}.spdx.json" \
    -q || rc=$?
  # Runs even on failure: a partial SBOM must not leak host paths either.
  sanitize_files "$repo" "$name" \
    "${OUT}/${name}.syft.json" \
    "${OUT}/${name}.cdx.json" \
    "${OUT}/${name}.spdx.json"
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
    echo ">> WARN: syft failed for '${name}' (exit ${rc}) - continuing with remaining projects" >&2
    fail_count=$((fail_count + 1))
    fail_names="${fail_names} ${name}"
  }
done
if [[ $found -eq 0 ]]; then
  name="$(basename "$TARGET")"
  scan_one "$TARGET" "$name" || {
    rc=$?
    echo ">> WARN: syft failed for '${name}' (exit ${rc})" >&2
    fail_count=1
    fail_names=" ${name}"
  }
fi

if [[ $fail_count -gt 0 ]]; then
  echo ">> syft done with ${fail_count} failed project(s):${fail_names} -> ${OUT}" >&2
  exit 1
fi
echo ">> syft done -> ${OUT}"
