#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release.sh <version>}"

mkdir -p depminer/results
cp README.md depminer/README.md
cp target/depminer.jar depminer/depminer.jar
cp bin/depminer.sh depminer/depminer.sh
cp bin/depminer.bat depminer/depminer.bat
chmod +x depminer/depminer.sh
cp depminer.yml depminer/depminer.yml
cp sanitize.yml depminer/sanitize.yml
cp .ignore.yml depminer/.ignore.yml

zip -r depminer.zip depminer
