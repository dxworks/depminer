#!/usr/bin/env bash
# Bumps the bundled Syft/Trivy pins, checksums and docs to the newest signed, settled releases;
# earlier when a release fixes a vulnerability of the pinned one. Needs trivy to compare them.
set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true   # set -e also inside $(...) (bash 4.4+)

MIN_AGE_DAYS="${MIN_AGE_DAYS:-7}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREP="$ROOT/scripts/prepare-release-voyager.sh"
DOC="$ROOT/docs/tools.md"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for cmd in gh cosign jq trivy; do
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

# Highest plain x.y.z release of <owner/repo> (not draft or prerelease) published at or before
# <epoch>, without the "v". Fails when the API answers nothing.
newest_before() {
  local releases
  releases="$(public_api "repos/$1/releases?per_page=30")"
  [ "$(jq 'length' <<< "$releases")" -gt 0 ] || { echo "ERROR: no releases of $1 from the GitHub API" >&2; exit 1; }
  jq -r --argjson cutoff "$2" '
    [ .[] | select(.draft == false and .prerelease == false)
          | select((.published_at | fromdateiso8601) <= $cutoff)
          | .tag_name | ltrimstr("v") | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) ]
    | sort_by(split(".") | map(tonumber)) | last // empty' <<< "$releases"
}

# Cooldown cutoff: MIN_AGE_DAYS before the last daily 05:00 UTC (same as the depinder server).
NOW=$(date -u +%s)
CUTOFF=$(( NOW - (NOW - 18000) % 86400 - MIN_AGE_DAYS * 86400 ))

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
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >&2 \
    || { echo "ERROR: Sigstore verification failed for $sums" >&2; exit 1; }
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

# Trivy findings ("<id> <package> <severity>", sorted) of <tool>'s linux/amd64 binary of <version>:
# the pinned one checked against this repo's CHECKSUMS, a newer one against the signed checksums.
#   <asset> release asset holding the binary at its root, "@" standing for the version
findings() {
  local repo="$1" tool="$2" version="$3" asset="${4//@/$3}" kind="$5"
  local out="$WORK/scan/$tool-$version"
  if [ ! -f "$out" ]; then
    local dir="$WORK/scan/$tool-$version.d" expected
    mkdir -p "$dir/bin"
    if [ "$kind" = pinned ]; then
      awk -v a="$asset" '$2 == a {print $1}' "$PREP" > "$dir/sha"
    else
      verified_lines "$repo" "$tool" "$version" "$asset" | awk '{print $1}' > "$dir/sha"
    fi
    expected="$(cat "$dir/sha")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: no sha256 for $asset" >&2; exit 1; }
    fetch_assets "$repo" "v$version" "$dir" "$asset"
    [ "$(sha256 "$dir/$asset")" = "$expected" ] || { echo "ERROR: checksum mismatch for $asset" >&2; exit 1; }
    tar -xzf "$dir/$asset" -C "$dir/bin" "$tool"
    trivy rootfs --quiet --scanners vuln --list-all-pkgs --format json "$dir/bin" > "$dir/scan.json"
    # No modules read means no findings either: that must not pass for "fixes everything".
    jq -e '[.Results[]?.Packages[]?] | length > 0' "$dir/scan.json" >/dev/null \
      || { echo "ERROR: trivy read no Go modules from $tool $version" >&2; exit 1; }
    jq -r '.Results[]?.Vulnerabilities[]? | "\(.VulnerabilityID) \(.PkgName) \(.Severity)"' "$dir/scan.json" \
      | LC_ALL=C sort -u > "$out"
  fi
  cat "$out"
}

ids() { awk '{print $1" "$2}' | LC_ALL=C sort -u; }

# Picks <tool>'s next version into PICK, with PICK_NOTE (why) and PICK_BLOCK (new HIGH/CRITICAL).
# The newest release is taken before the cooldown when it fixes a finding of the pinned one and
# adds no HIGH/CRITICAL; otherwise the newest settled one, blocked if it adds a HIGH/CRITICAL.
pick() {
  local repo="$1" tool="$2" pinned="$3" asset="$4" latest ripe fresh settled fixed added
  PICK=""; PICK_NOTE=""; PICK_BLOCK=""
  latest="$(newest_before "$repo" "$NOW")"; ripe="$(newest_before "$repo" "$CUTOFF")"
  fresh="$(newer "$pinned" "$latest")"; settled="$(newer "$pinned" "$ripe")"
  [ -n "$fresh" ] || return 0
  findings "$repo" "$tool" "$pinned" "$asset" pinned > "$WORK/scan/old"
  if [ "$fresh" != "$settled" ]; then
    findings "$repo" "$tool" "$fresh" "$asset" candidate > "$WORK/scan/new"
    fixed="$(LC_ALL=C comm -23 <(ids < "$WORK/scan/old") <(ids < "$WORK/scan/new") | awk '{print $1}' | LC_ALL=C sort -u \
      | awk 'NR <= 8 {l = l (NR > 1 ? ", " : "") $0} END {if (NR > 8) l = l " and " NR - 8 " more"; print l}')"
    added="$(new_high)"
    if [ -n "$fixed" ] && [ -z "$added" ]; then
      PICK="$fresh"; PICK_NOTE="$tool $fresh taken before the ${MIN_AGE_DAYS}-day cooldown: it fixes $fixed."
      return 0
    fi
  fi
  [ -n "$settled" ] || return 0
  findings "$repo" "$tool" "$settled" "$asset" candidate > "$WORK/scan/new"
  PICK="$settled"
  PICK_BLOCK="$(new_high | sed "s/^/$tool $settled: /")"
}

# HIGH/CRITICAL findings in scan/new that scan/old does not have.
new_high() {
  LC_ALL=C comm -13 <(ids < "$WORK/scan/old") \
    <(awk '$3 == "HIGH" || $3 == "CRITICAL"' "$WORK/scan/new" | ids)
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$WORK/scan"
syft_old="$(current SYFT)"; trivy_old="$(current TRIVY)"
notes=(); blocks=()
pick anchore/syft syft "$syft_old" "syft_@_linux_amd64.tar.gz"
syft_new="$PICK"; [ -n "$PICK_NOTE" ] && notes+=("$PICK_NOTE"); [ -n "$PICK_BLOCK" ] && blocks+=("$PICK_BLOCK")
pick aquasecurity/trivy trivy "$trivy_old" "trivy_@_Linux-64bit.tar.gz"
trivy_new="$PICK"; [ -n "$PICK_NOTE" ] && notes+=("$PICK_NOTE"); [ -n "$PICK_BLOCK" ] && blocks+=("$PICK_BLOCK")
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
[ ${#notes[@]} -eq 0 ] || printf '%s\n' "${notes[@]}"
[ ${#blocks[@]} -eq 0 ] || { echo "Blocked, new HIGH/CRITICAL:"; printf '%s\n' "${blocks[@]}"; }
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "changed=true"; echo "summary=$summary"
    if [ ${#blocks[@]} -gt 0 ]; then echo "blocked=true"; else echo "blocked=false"; fi
    echo "notes<<NOTES_EOF"
    [ ${#notes[@]} -eq 0 ] || printf -- '- %s\n' "${notes[@]}"
    [ ${#blocks[@]} -eq 0 ] || { echo "- **Not merged automatically:** new HIGH/CRITICAL findings the pinned version does not have:"; printf '%s\n' "${blocks[@]}" | sed 's/^/  - /'; }
    echo "NOTES_EOF"
  } >> "$GITHUB_OUTPUT"
fi
