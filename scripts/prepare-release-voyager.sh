#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

# Pinned tool versions bundled into the Voyager instrument.
SYFT_VERSION="1.46.0"
TRIVY_VERSION="0.72.0"

mkdir -p depminer/results depminer/bin
cp README.md depminer/README.md
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
  echo "fetching syft_${SYFT_VERSION}_${t}.tar.gz"
  curl -sSL "${sbase}/syft_${SYFT_VERSION}_${t}.tar.gz" -o /tmp/syft.tgz
  tar -xzf /tmp/syft.tgz -C /tmp syft
  mv /tmp/syft "depminer/bin/syft-${os}-${arch}"
  chmod +x "depminer/bin/syft-${os}-${arch}"
done
echo "fetching syft_${SYFT_VERSION}_windows_amd64.zip"
curl -sSL "${sbase}/syft_${SYFT_VERSION}_windows_amd64.zip" -o /tmp/syft-win.zip
unzip -o -q /tmp/syft-win.zip syft.exe -d /tmp
mv /tmp/syft.exe depminer/bin/syft-windows-amd64.exe

# --- Trivy binaries (single self-contained executable per platform) ---
tbase="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
for spec in "linux amd64 Linux-64bit" "linux arm64 Linux-ARM64" \
            "darwin amd64 macOS-64bit" "darwin arm64 macOS-ARM64"; do
  set -- $spec
  os="$1"; arch="$2"; asset="$3"
  echo "fetching trivy_${TRIVY_VERSION}_${asset}.tar.gz"
  curl -sSL "${tbase}/trivy_${TRIVY_VERSION}_${asset}.tar.gz" -o /tmp/trivy.tgz
  tar -xzf /tmp/trivy.tgz -C /tmp trivy
  mv /tmp/trivy "depminer/bin/trivy-${os}-${arch}"
  chmod +x "depminer/bin/trivy-${os}-${arch}"
done
echo "fetching trivy_${TRIVY_VERSION}_windows-64bit.zip"
curl -sSL "${tbase}/trivy_${TRIVY_VERSION}_windows-64bit.zip" -o /tmp/trivy-win.zip
unzip -o -q /tmp/trivy-win.zip trivy.exe -d /tmp
mv /tmp/trivy.exe depminer/bin/trivy-windows-amd64.exe

zip -r depminer-voyager.zip depminer
