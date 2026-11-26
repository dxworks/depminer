#!/usr/bin/env bash
# Splits the all-platform depminer-voyager.zip into one depminer-voyager-<platform>.zip per
# platform of voyager-platforms.sh: the same files, with only that platform's syft and trivy.
# Usage: split-voyager-platforms.sh <depminer-voyager.zip> <output-dir>
set -euo pipefail

ZIP="${1:?Usage: split-voyager-platforms.sh <depminer-voyager.zip> <output-dir>}"
OUT="${2:?Usage: split-voyager-platforms.sh <depminer-voyager.zip> <output-dir>}"
. "$(cd "$(dirname "$0")" && pwd)/voyager-platforms.sh"

ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

while read -r platform suffix _ _; do
  [ -n "$platform" ] || continue
  rm -rf "$WORK/stage" && mkdir "$WORK/stage"
  unzip -q "$ZIP" -d "$WORK/stage"
  bin="$WORK/stage/depminer/bin"
  for tool in syft trivy; do
    [ -f "$bin/$tool-$suffix" ] || { echo "ERROR: $platform: $tool-$suffix is not in $ZIP" >&2; exit 1; }
    find "$bin" -maxdepth 1 -type f -name "$tool-*" ! -name "$tool-$suffix" ! -name "$tool-wrapper.*" -delete
  done
  rm -f "$OUT/depminer-voyager-$platform.zip"
  (cd "$WORK/stage" && zip -r -X -q "$OUT/depminer-voyager-$platform.zip" depminer)
  echo "depminer-voyager-$platform.zip: $(unzip -Z1 "$OUT/depminer-voyager-$platform.zip" 'depminer/bin/*' | grep -vE 'wrapper|/$' | sed 's|depminer/bin/||' | tr '\n' ' ')"
done <<< "$VOYAGER_PLATFORMS"
