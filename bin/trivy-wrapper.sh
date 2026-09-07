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

# --include-dev-deps keeps development-scoped packages (npm/yarn/pnpm devDependencies,
# composer packages-dev, uv.lock dev groups, gradle) instead of pruning them: Black Duck reports them,
# so must we. It only changes lockfile parsing — still no network.
scan_one() {
  local repo="$1" name="$2"
  echo ">> trivy scanning: ${name}"
  "$BIN" fs \
    --cache-dir "$CACHE" \
    --offline-scan \
    --skip-db-update --skip-java-db-update \
    --disable-telemetry --skip-version-check \
    --include-dev-deps \
    --format cyclonedx \
    --output "${OUT}/${name}.trivy.cdx.json" \
    --quiet \
    "$repo"
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
