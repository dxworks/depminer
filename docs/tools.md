# Bundled Tools

DepMiner ships Syft and Trivy **inside the release bundle** so a mission run never downloads
anything. This page documents the pinned versions and the offline guarantees.

## Versions

| Tool | Version | Source |
|---|---|---|
| Syft | 1.46.0 | [github.com/anchore/syft](https://github.com/anchore/syft) (pinned in `scripts/prepare-release-voyager.sh`) |
| Trivy | 0.72.0 | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) (pinned in `scripts/prepare-release-voyager.sh`) |

The wrappers in `bin/` pick the binary matching the host OS/arch and fall back to a tool on `PATH`
only when no bundled binary exists (a development convenience — release bundles always contain the
binaries).

## Platforms

Binaries are bundled for:

- **Linux** — amd64 + arm64
- **macOS** — amd64 + arm64
- **Windows** — amd64

## Offline guarantees

Syft and Trivy run **extraction-only and 100% offline**. Specifically, they do **not**:

- consult vulnerability databases,
- send telemetry,
- perform version / update checks,
- reach registries or Maven Central.

They only **read the target folder and write SBOM files**. The single exception to "no network"
is the *optional, one-time* prep step some ecosystems need — and that is run by you, separately,
before the scan (see [Preparing Your Project](prep-guide.md)). The scan itself never touches the
network.

## Output formats

| Tool | Formats written per project |
|---|---|
| Syft | native Syft JSON (`.syft.json`), CycloneDX (`.cdx.json`), SPDX (`.spdx.json`) |
| Trivy | CycloneDX (`.trivy.cdx.json`) |

## Supported ecosystems

Between them the two scanners catalog essentially every mainstream ecosystem — Java, Node, Python,
Go, Rust, .NET, PHP, Ruby, and more. A stack neither tool catalogs (e.g. Bazel, Scala SBT,
Perl/CPAN) will not appear. For the authoritative supported-ecosystem lists, see each tool's own
documentation.
