#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: prepare-release-voyager.sh <version>}"

mkdir -p depminer/results
mkdir -p depminer/lib/templates
cp README.md depminer/README.md
cp target/depminer.jar depminer/depminer.jar
cp instrument.yml depminer/instrument.yml
cp instrument.v2.yml depminer/instrument.v2.yml
cp depminer.yml depminer/depminer.yml
cp sanitize.yml depminer/sanitize.yml
cp .ignore.yml depminer/.ignore.yml
cp lib/*.py depminer/lib
cp lib/templates/*.html depminer/lib/templates

zip -r depminer-voyager.zip depminer
