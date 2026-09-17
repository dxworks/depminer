#!/usr/bin/env bash
# Fail if the Syft/Trivy versions in docs/tools.md drift from the ones the release
# bundle actually pins. The docs site only redeploys on docs/** changes, so a bump
# in prepare-release-voyager.sh would otherwise leave the published page quietly
# stating a version that no longer ships.
set -euo pipefail

cd "$(dirname "$0")/.."

RELEASE_SCRIPT="scripts/prepare-release-voyager.sh"
DOC="docs/tools.md"
status=0

check() {
  local name="$1" var="$2" pinned documented
  pinned=$(sed -n "s/^${var}=\"\([^\"]*\)\".*/\1/p" "$RELEASE_SCRIPT" | head -1)
  documented=$(awk -F'|' -v n="$name" '
    tolower($2) ~ "^ *" n " *$" { gsub(/ /, "", $3); print $3; exit }' "$DOC")

  if [ -z "$pinned" ]; then
    echo "::error file=$RELEASE_SCRIPT::could not read $var"
    status=1
  elif [ -z "$documented" ]; then
    echo "::error file=$DOC::no version row found for $name"
    status=1
  elif [ "$pinned" != "$documented" ]; then
    echo "::error file=$DOC::$name is documented as '$documented' but $RELEASE_SCRIPT pins '$pinned'"
    status=1
  else
    echo "ok  $name $pinned"
  fi
}

check syft  SYFT_VERSION
check trivy TRIVY_VERSION

exit $status
