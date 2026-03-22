#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

mkdir -p depminer/results
cp README.md depminer/README.md
cp target/depminer.jar depminer/depminer.jar
cp instrument.yml depminer/instrument.yml
cp depminer.yml depminer/depminer.yml
cp sanitize.yml depminer/sanitize.yml
cp .ignore.yml depminer/.ignore.yml

zip -r depminer-voyager.zip depminer
