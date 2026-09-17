#!/usr/bin/env bash
# Fail if the Syft/Trivy versions in docs/tools.md drift from the ones the release
# bundle actually pins. The docs site only redeploys on docs/** changes, so a bump
# in prepare-release-voyager.sh would otherwise leave the published page quietly
# stating a version that no longer ships.
set -euo pipefail

cd "$(dirname "$0")/.."

RELEASE_SCRIPT="scripts/prepare-release-voyager.sh"
DOCS="docs/tools.md README.md"
status=0

check() {
  local name="$1" var="$2" doc="$3" pinned documented
  pinned=$(sed -n "s/^${var}=\"\([^\"]*\)\".*/\1/p" "$RELEASE_SCRIPT" | head -1)
  documented=$(awk -F'|' -v n="$name" '
    tolower($2) ~ "^ *" n " *$" { gsub(/ /, "", $3); print $3; exit }' "$doc")

  if [ -z "$pinned" ]; then
    echo "::error file=$RELEASE_SCRIPT::could not read $var"
    status=1
  elif [ -z "$documented" ]; then
    echo "::error file=$doc::no version row found for $name"
    status=1
  elif [ "$pinned" != "$documented" ]; then
    echo "::error file=$doc::$name is documented as '$documented' but $RELEASE_SCRIPT pins '$pinned'"
    status=1
  else
    echo "ok  $doc: $name $pinned"
  fi
}

for doc in $DOCS; do
  check syft  SYFT_VERSION  "$doc"
  check trivy TRIVY_VERSION "$doc"
done

exit $status
