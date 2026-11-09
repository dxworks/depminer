#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

# Pinned tool versions bundled into the Voyager instrument.
SYFT_VERSION="1.57.0"
TRIVY_VERSION="0.76.2"

# Official sha256 checksums for the pinned versions, taken from each project's release
# checksums file (syft_<v>_checksums.txt / trivy_<v>_checksums.txt on the GitHub release).
# Bump these together with the versions above — a version bump without new checksums
# fails fast with "no pinned checksum".
CHECKSUMS="
9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704  syft_1.57.0_linux_amd64.tar.gz
410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb  syft_1.57.0_linux_arm64.tar.gz
f0e8568a9429ac1c8e4ae9e9c399fede5fcd09e4a7348b47b0532baf1c6500c1  syft_1.57.0_darwin_amd64.tar.gz
17012a5a110323bb1069e513a8665f1ae445905c56b4e3f9a9df4f95c5bb6161  syft_1.57.0_darwin_arm64.tar.gz
06e9663e55f7f38ff966710670fbe0763182c621f7ac2f191bcb209a6dfbd969  syft_1.57.0_windows_amd64.zip
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
cp README.md depminer/README.md
cp PREP_GUIDE.md depminer/PREP_GUIDE.md
cp target/depminer.jar depminer/depminer.jar
cp instrument.yml depminer/instrument.yml
cp depminer.yml depminer/depminer.yml
cp sanitize.yml depminer/sanitize.yml
cp .ignore.yml depminer/.ignore.yml

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
