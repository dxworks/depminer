#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

# Pinned tool versions bundled into the Voyager instrument.
SYFT_VERSION="1.57.2"
TRIVY_VERSION="0.76.2"

# Official sha256 checksums for the pinned versions, taken from each project's release
# checksums file (syft_<v>_checksums.txt / trivy_<v>_checksums.txt on the GitHub release).
# Bump these together with the versions above — a version bump without new checksums
# fails fast with "no pinned checksum".
CHECKSUMS="
ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b  syft_1.57.2_linux_amd64.tar.gz
8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6  syft_1.57.2_linux_arm64.tar.gz
73c6100bc43fbcc1c99aed3428d859c6289c4076be7e296dde7e427324c15908  syft_1.57.2_darwin_amd64.tar.gz
38afbcc03a9d9afac2d7572432fd2c435e051e03930582ea90f4710ffb515224  syft_1.57.2_darwin_arm64.tar.gz
0a10e03ffd124c304fd7e7491262dba2e5f68eb12378b106d7525146675b2e3a  syft_1.57.2_windows_amd64.zip
bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf  trivy_0.76.2_Linux-64bit.tar.gz
ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3  trivy_0.76.2_Linux-ARM64.tar.gz
e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b  trivy_0.76.2_macOS-64bit.tar.gz
ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8  trivy_0.76.2_macOS-ARM64.tar.gz
691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6  trivy_0.76.2_windows-64bit.zip
"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Download <base>/<asset> to <dest> and verify it against the pinned checksum above.
fetch_verified() {
  local base="$1" asset="$2" dest="$3" expected actual
  echo "fetching ${asset}"
  curl -fsSL "${base}/${asset}" -o "$dest"
  expected="$(printf '%s\n' "$CHECKSUMS" | awk -v a="$asset" '$2 == a {print $1}')"
  if [ -z "$expected" ]; then
    echo "ERROR: no pinned checksum for ${asset} - update CHECKSUMS when bumping versions" >&2
    exit 1
  fi
  actual="$(sha256 "$dest")"
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: checksum mismatch for ${asset}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    exit 1
  fi
}

# Start from a clean slate: zip -r appends into an existing archive, and stale files
# in a leftover staging dir would otherwise survive local re-runs.
rm -rf depminer depminer-voyager.zip

mkdir -p depminer/results/depminer depminer/results/syft depminer/results/trivy depminer/bin
mkdir -p depminer/lib/templates
cp README.md depminer/README.md
cp PREP_GUIDE.md depminer/PREP_GUIDE.md
cp target/depminer.jar depminer/depminer.jar
cp instrument.yml depminer/instrument.yml
cp instrument.v2.yml depminer/instrument.v2.yml

# The tool's version, from the release tag, in both manifests (V1 and V2)
for f in depminer/instrument.yml depminer/instrument.v2.yml; do
  awk -v v="$VERSION" '!/^version:/ {print} /^name:/ {print "version: " v}' "$f" > "$f.tmp"
  mv "$f.tmp" "$f"
done

cp depminer.yml depminer/depminer.yml
cp sanitize.yml depminer/sanitize.yml
cp .ignore.yml depminer/.ignore.yml
cp lib/*.py depminer/lib
cp lib/templates/*.html depminer/lib/templates
cp dependency-manager-map.yml depminer/dependency-manager-map.yml

cp bin/syft-wrapper.sh depminer/bin/syft-wrapper.sh
cp bin/syft-wrapper.ps1 depminer/bin/syft-wrapper.ps1
cp bin/trivy-wrapper.sh depminer/bin/trivy-wrapper.sh
cp bin/trivy-wrapper.ps1 depminer/bin/trivy-wrapper.ps1
chmod +x depminer/bin/*.sh

# --- Syft binaries (single self-contained executable per platform) ---
sbase="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
for t in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  os="${t%_*}"; arch="${t#*_}"
  fetch_verified "$sbase" "syft_${SYFT_VERSION}_${t}.tar.gz" /tmp/syft.tgz
  tar -xzf /tmp/syft.tgz -C /tmp syft
  mv /tmp/syft "depminer/bin/syft-${os}-${arch}"
  chmod +x "depminer/bin/syft-${os}-${arch}"
done
fetch_verified "$sbase" "syft_${SYFT_VERSION}_windows_amd64.zip" /tmp/syft-win.zip
unzip -o -q /tmp/syft-win.zip syft.exe -d /tmp
mv /tmp/syft.exe depminer/bin/syft-windows-amd64.exe

# --- Trivy binaries (single self-contained executable per platform) ---
tbase="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
for spec in "linux amd64 Linux-64bit" "linux arm64 Linux-ARM64" \
            "darwin amd64 macOS-64bit" "darwin arm64 macOS-ARM64"; do
  set -- $spec
  os="$1"; arch="$2"; asset="$3"
  fetch_verified "$tbase" "trivy_${TRIVY_VERSION}_${asset}.tar.gz" /tmp/trivy.tgz
  tar -xzf /tmp/trivy.tgz -C /tmp trivy
  mv /tmp/trivy "depminer/bin/trivy-${os}-${arch}"
  chmod +x "depminer/bin/trivy-${os}-${arch}"
done
fetch_verified "$tbase" "trivy_${TRIVY_VERSION}_windows-64bit.zip" /tmp/trivy-win.zip
unzip -o -q /tmp/trivy-win.zip trivy.exe -d /tmp
mv /tmp/trivy.exe depminer/bin/trivy-windows-amd64.exe

zip -r depminer-voyager.zip depminer
