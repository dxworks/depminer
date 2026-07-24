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

scan_one() {
  local repo="$1" name="$2"
  echo ">> syft scanning: ${name}"
  "$BIN" scan "dir:${repo}" \
    -o "syft-json=${OUT}/${name}.syft.json" \
    -o "cyclonedx-json=${OUT}/${name}.cdx.json" \
    -o "spdx-json=${OUT}/${name}.spdx.json" \
    -q
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
