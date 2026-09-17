# Installing

DepMiner is an instrument for **[Voyager](https://dxworks.org/voyager/)**, the DxWorks software
analysis tool aggregator. This page assumes you already have a Voyager install. If you don't, set
one up with the **[Voyager Quick Start](https://dxworks.org/voyager/quickstart.html)** first, then
come back here.

## Add DepMiner to your Voyager install

1. Download `depminer-voyager.zip` from the
   [releases page](https://github.com/dxworks/depminer/releases) (a `v*-voyager` release).
2. Unzip it into `instruments/`, so you get `instruments/depminer/`.

!!! info "`depminer-voyager.zip` is a few hundred MB"
    It bundles executables for multiple operating systems, which is what buys the 100%-offline
    scan. See [Bundled Tools](tools.md).

## Building a Voyager install with only DepMiner

`voyenv` builds a fresh Voyager install from a list of instruments. Use it to keep DepMiner
isolated from your other instruments, or to pin an exact version. Needs **Node.js**.

```bash
npm i -g @dxworks/voyenv
```

Write a `voyenv.yml` in an empty folder:

```yaml
name: voyager
voyager_version: v1.6.2

instruments:
  - name: dxworks/depminer
    tag: v0.4.0-voyager        # a real v*-voyager tag; omit the line for latest
    asset: depminer-voyager.zip

tokens:
runtimes:
```

```bash
voyenv install
```

You get a `voyager/` folder with `voyager.sh` / `voyager.bat`, `dx-voyager.jar`,
`instruments/depminer/`, and `.config.yml` already set to `runsAll: false`.

## Running it

Running is Voyager's job: see the
**[Voyager Quick Start](https://dxworks.org/voyager/quickstart.html)**. The only DepMiner-specific
part, choosing which mechanisms run, is on our [Quick Start](quickstart.md).

## Where the results land

One zip next to `voyager.sh`, named after the `mission:` field:

```
<mission>-voyager-results.zip
  depminer/results/
    scrub-report.json
    depminer/   mined manifests and lockfiles + index.json
    syft/       Syft JSON, CycloneDX and SPDX, per project
    trivy/      CycloneDX, per project
```
