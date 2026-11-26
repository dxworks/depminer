# shellcheck shell=bash
# The platforms of the Voyager bundle: one depminer-voyager-<platform>.zip each, plus the
# all-platform depminer-voyager.zip. Sourced by prepare-release-voyager.sh (downloads),
# split-voyager-platforms.sh (per-platform zips) and bump-scanners.sh (signed checksums),
# so a platform is added or removed here only.
#   <voyager platform>  <binary suffix in bin/>  <syft asset tail>  <trivy asset tail>
# The binary suffix is what bin/*-wrapper.sh and bin/*-wrapper.ps1 start: <tool>-<suffix>.
VOYAGER_PLATFORMS="
linux-x64    linux-amd64        linux_amd64.tar.gz    Linux-64bit.tar.gz
linux-arm64  linux-arm64        linux_arm64.tar.gz    Linux-ARM64.tar.gz
macos-x64    darwin-amd64       darwin_amd64.tar.gz   macOS-64bit.tar.gz
macos-arm64  darwin-arm64       darwin_arm64.tar.gz   macOS-ARM64.tar.gz
win-x64      windows-amd64.exe  windows_amd64.zip     windows-64bit.zip
"
