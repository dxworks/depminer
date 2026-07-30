# Installing

[Quick Start](quickstart.md) assumes you already have a **Voyager installation that contains this
instrument**. This page is how you get one.

You do **not** need the official `voyager-full.zip` bundle, and you do not need to wait for DepMiner
to be included in it. You can build your own Voyager install containing exactly the instruments you
want — that is the normal way to try a new instrument version.

!!! info "Download size"
    `depminer-voyager.zip` is large (**several hundred MB**) because it bundles the Syft and Trivy
    binaries for five OS/architecture targets. That is what buys the 100%-offline guarantee: the
    scan itself never downloads anything. See [Bundled Tools](tools.md).

## Option A — build your own bundle with voyenv (recommended)

`voyenv` is the tool that assembles a Voyager installation from a list of instruments. It needs
**Node.js**.

**1. Install voyenv**

```bash
npm i -g @dxworks/voyenv
```

**2. Write a `voyenv.yml`** in an empty folder:

```yaml
name: voyager
voyager_version: v1.6.2

instruments:
  - name: dxworks/depminer
    tag: v0.4.0-voyager
    asset: depminer-voyager.zip

tokens:
runtimes:
```

**3. Build the install**

```bash
voyenv install
```

This downloads Voyager itself plus each instrument listed, unpacks them, and writes a ready-to-use
`voyager/` folder containing `voyager.sh` / `voyager.bat`, `dx-voyager.jar`, and
`instruments/depminer/`. It also writes a `.config.yml` with `runsAll: false`, which is what lets a
mission select individual commands.

`cd voyager/` and continue with [Quick Start](quickstart.md).

!!! tip "Mixing in other instruments"
    Add more entries under `instruments:` to build a bundle with several tools — the format is the
    same for every dxworks instrument:

    ```yaml
      - name: dxworks/inspector-git
        tag: v1.7.0-voyager
        asset: iglog-voyager.zip
    ```

!!! note "Pinning versions"
    The `tag:` line pins the exact instrument release, and must match a tag that actually exists —
    check the [releases page](https://github.com/dxworks/depminer/releases) and use the newest
    `v*-voyager` entry. Omit the line to always take the latest. Pinning is recommended when you
    want a reproducible install — a rebuild then always produces the same bundle.

## Option B — add it to an existing Voyager install

If you already have a Voyager installation, you can drop the instrument in beside the others:

1. Download `depminer-voyager.zip` from the
   [releases page](https://github.com/dxworks/depminer/releases) (pick a `v*-voyager` release).
2. Unzip it into the install's `instruments/` folder, so you end up with `instruments/depminer/`
   containing `instrument.yml`, `depminer.jar`, and `bin/`.
3. Confirm the install's `.config.yml` has `runsAll: false` — without it, mission command selection
   is ignored and Voyager runs everything it finds.

!!! note "Executable permissions are handled for you"
    Some unzip implementations drop the executable bit on the bundled Syft/Trivy binaries. The
    wrappers restore it themselves at run time, so this normally needs no action. If you do hit a
    permission error, `chmod +x instruments/depminer/bin/*` clears it.

## Verifying the install

From inside the `voyager/` folder:

```bash
java -version                      # JDK 11+ must be present — see Quick Start prerequisites
ls instruments/depminer            # expect: instrument.yml, depminer.jar, bin/, README.md
```

Then run a mission as described in [Quick Start](quickstart.md). A successful run prints a summary
with one line per command and writes `<mission>-voyager-results.zip`.
