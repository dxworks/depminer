# Bundled Tools

DepMiner ships Syft and Trivy **inside the release bundle** so a mission run never downloads
anything.

## Versions

| Tool | Version | Source |
|---|---|---|
| Syft | 1.46.0 | [github.com/anchore/syft](https://github.com/anchore/syft) |
| Trivy | 0.72.0 | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) |

Both are pinned in `scripts/prepare-release-voyager.sh` and bundled for **Linux** and **macOS**
(amd64 + arm64) and **Windows** (amd64). The wrappers in `bin/` pick the binary matching the host
OS/arch and fall back to a tool on `PATH` only when no bundled binary exists (a development
convenience; release bundles always contain the binaries).

## Offline guarantees

Syft and Trivy run **extraction-only and 100% offline**. Specifically, they do **not**:

- consult vulnerability databases,
- send telemetry,
- perform version / update checks,
- reach registries or Maven Central.

They only **read the target folder and write SBOM files**. The single exception to "no network"
is the *optional, one-time* prep step some ecosystems need, and that is run by you, separately,
before the scan (see [Preparing Your Project](prep-guide.md)). The scan itself never touches the
network.

## Output formats

| Tool | Formats written per project |
|---|---|
| Syft | native Syft JSON (`.syft.json`), CycloneDX (`.cdx.json`), SPDX (`.spdx.json`) |
| Trivy | CycloneDX (`.trivy.cdx.json`) |

## Supported ecosystems

Between them the two scanners catalog essentially every mainstream ecosystem: Java, Node, Python,
Go, Rust, .NET, PHP, Ruby, and more. A stack neither tool catalogs (e.g. Bazel, Scala SBT,
Perl/CPAN) will not appear. The authoritative lists are
[Syft's supported ecosystems](https://github.com/anchore/syft#supported-ecosystems) and
[Trivy's language coverage](https://trivy.dev/latest/docs/coverage/language/).
