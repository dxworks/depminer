#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

# Pinned tool versions bundled into the Voyager instrument.
SYFT_VERSION="1.46.0"
TRIVY_VERSION="0.72.0"

# Official sha256 checksums for the pinned versions, taken from each project's release
# checksums file (syft_<v>_checksums.txt / trivy_<v>_checksums.txt on the GitHub release).
# Bump these together with the versions above — a version bump without new checksums
# fails fast with "no pinned checksum".
CHECKSUMS="
d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca  syft_1.46.0_linux_amd64.tar.gz
9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e  syft_1.46.0_linux_arm64.tar.gz
5c983db13533de02e5331aae88091116f25365840741f86234084a30166672a7  syft_1.46.0_darwin_amd64.tar.gz
cd4e2c40e075684a5746d8959f76b6572bb2d2dda8cf6877dbfff1cc0baeea01  syft_1.46.0_darwin_arm64.tar.gz
1e515c1ac4bc65917f8d0a52b6ae0e611082779cbf2da9d470282158dd24ea13  syft_1.46.0_windows_amd64.zip
bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea  trivy_0.72.0_Linux-64bit.tar.gz
2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467  trivy_0.72.0_Linux-ARM64.tar.gz
ee5e60df8a98e5b89fd74a6d86f9e5c7e9a266a35002cb1e43291698b3bfee08  trivy_0.72.0_macOS-64bit.tar.gz
88f208680dc05da2b459e19b4f5aa2b4dc7c2117892ba4aab2ae63baba330016  trivy_0.72.0_macOS-ARM64.tar.gz
ed3cf122060f61818fe1f735fd97557954e16e10bc8b058af9852271cf2e91b3  trivy_0.72.0_windows-64bit.zip
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

mkdir -p depminer/results depminer/bin
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
