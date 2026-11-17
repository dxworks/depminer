#!/usr/bin/env bash
# Bumps the bundled Syft/Trivy pins, checksums and docs to the newest signed, settled releases.
set -euo pipefail

MIN_AGE_DAYS="${MIN_AGE_DAYS:-7}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREP="$ROOT/scripts/prepare-release-voyager.sh"
DOC="$ROOT/docs/tools.md"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for cmd in gh cosign jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd is required" >&2; exit 1; }
done

# GET <api path> for a public repo; anonymous retry if the token is refused (e.g. an org IP allow list).
public_api() {
  local out
  if out="$(gh api "$1" 2>/dev/null)"; then printf '%s\n' "$out"; return; fi
  curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"
}

# Downloads <files...> of <owner/repo> release <tag> into <dir> over public HTTPS, no token needed.
fetch_assets() {
  local repo="$1" tag="$2" dir="$3" f; shift 3
  for f in "$@"; do curl -fsSL --retry 3 -o "$dir/$f" "https://github.com/$repo/releases/download/$tag/$f"; done
}

# Newest non-draft, non-prerelease tag of <owner/repo> published at least MIN_AGE_DAYS before the
# last daily 05:00 UTC (same cutoff as the depinder server), without the leading "v".
newest_settled() {
  local now day=86400 run=18000 cutoff   # run: 05:00 UTC
  now=$(date -u +%s)
  cutoff=$(( now - (now - run) % day - MIN_AGE_DAYS * day ))
  public_api "repos/$1/releases?per_page=30" | jq -r "
    [ .[] | select(.draft == false and .prerelease == false)
          | select((.published_at | fromdateiso8601) <= $cutoff) ][0].tag_name // empty" \
    | sed 's/^v//'
}

# The checksum lines of <assets...> from <owner/repo>'s release <version>, after the Sigstore
# bundle of the checksums file verifies. Fails on a bad signature or a missing asset line.
verified_lines() {
  local repo="$1" tool="$2" version="$3"; shift 3
  local sums="${tool}_${version}_checksums.txt" dir="$WORK/$tool"
  mkdir -p "$dir"
  fetch_assets "$repo" "v$version" "$dir" "$sums" "$sums.sigstore.json"
  cosign verify-blob "$dir/$sums" \
    --bundle "$dir/$sums.sigstore.json" \
    --certificate-identity-regexp "^https://github\.com/${repo//./\\.}/\.github/workflows/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >&2
  local asset line
  for asset in "$@"; do
    line="$(awk -v a="$asset" '$2 == a {print $1"  "$2}' "$dir/$sums")"
    if [ -z "$line" ] || ! [[ "${line%% *}" =~ ^[0-9a-f]{64}$ ]]; then
      echo "ERROR: $sums has no sha256 for $asset" >&2; exit 1
    fi
    echo "$line"
  done
}

current() { sed -n "s/^$1_VERSION=\"\\([^\"]*\\)\"/\\1/p" "$PREP"; }

# Prints the new version if <candidate> is a plain x.y.z newer than <pinned>, else nothing.
newer() {
  local pinned="$1" candidate="$2"
  [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
  [ "$candidate" != "$pinned" ] || return 0
  [ "$(printf '%s\n%s\n' "$pinned" "$candidate" | sort -V | tail -1)" = "$candidate" ] && echo "$candidate"
  return 0
}

syft_old="$(current SYFT)"; trivy_old="$(current TRIVY)"
syft_new="$(newer "$syft_old" "$(newest_settled anchore/syft)")"
trivy_new="$(newer "$trivy_old" "$(newest_settled aquasecurity/trivy)")"
syft_v="${syft_new:-$syft_old}"; trivy_v="${trivy_new:-$trivy_old}"

parts=()
[ -n "$syft_new" ]  && parts+=("Syft $syft_old → $syft_new")
[ -n "$trivy_new" ] && parts+=("Trivy $trivy_old → $trivy_new")

if [ ${#parts[@]} -eq 0 ]; then
  echo "Scanners already current (Syft $syft_old, Trivy $trivy_old; cooldown: ${MIN_AGE_DAYS} days before today's 05:00 UTC)"
  [ -n "${GITHUB_OUTPUT:-}" ] && echo "changed=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

# Rebuild the whole CHECKSUMS block from verified files, also for an unchanged tool, so the block
# is always exactly what the publishers signed.
{
  verified_lines anchore/syft syft "$syft_v" \
    "syft_${syft_v}_linux_amd64.tar.gz" "syft_${syft_v}_linux_arm64.tar.gz" \
    "syft_${syft_v}_darwin_amd64.tar.gz" "syft_${syft_v}_darwin_arm64.tar.gz" \
    "syft_${syft_v}_windows_amd64.zip"
  verified_lines aquasecurity/trivy trivy "$trivy_v" \
    "trivy_${trivy_v}_Linux-64bit.tar.gz" "trivy_${trivy_v}_Linux-ARM64.tar.gz" \
    "trivy_${trivy_v}_macOS-64bit.tar.gz" "trivy_${trivy_v}_macOS-ARM64.tar.gz" \
    "trivy_${trivy_v}_windows-64bit.zip"
} > "$WORK/checksums"

awk -v sums="$WORK/checksums" -v syft="$syft_v" -v trivy="$trivy_v" '
  /^SYFT_VERSION="/  { print "SYFT_VERSION=\"" syft "\"";   next }
  /^TRIVY_VERSION="/ { print "TRIVY_VERSION=\"" trivy "\""; next }
  /^CHECKSUMS="$/    { print; while ((getline l < sums) > 0) print l; skip = 1; next }
  skip && /^"$/      { skip = 0 }
  skip               { next }
                     { print }
' "$PREP" > "$WORK/prep" && cat "$WORK/prep" > "$PREP"

sed -i.bak -E \
  -e "s/^\| Syft \| [0-9.]+ \|/| Syft | $syft_v |/" \
  -e "s/^\| Trivy \| [0-9.]+ \|/| Trivy | $trivy_v |/" "$DOC" && rm -f "$DOC.bak"

summary="$(printf '%s, ' "${parts[@]}")"; summary="${summary%, }"
echo "Bumped: $summary"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "changed=true"; echo "summary=$summary"; } >> "$GITHUB_OUTPUT"
fi
