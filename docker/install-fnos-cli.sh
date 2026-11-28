#!/bin/sh
# Build-time only: download the official fnos-cli Linux binary for the
# pinned version and verify it (.gz SHA-256 pin + --version self-check).
# Runtime never downloads the CLI.
# Inputs (Dockerfile ARGs, visible as env in RUN):
#   FNOS_CLI_VERSION, FNOS_CLI_X64_SHA256, FNOS_CLI_ARM64_SHA256
#
# Release layout (verified 2026-11-24 against the live v0.6.2 release):
# - assets are named fnos-cli-<version>-linux-<arch>.gz, one per arch;
# - the tag carries neither release.json nor SHA256SUMS; the Dockerfile
#   pins were computed by downloading the assets and hashing them
#   directly. This script verifies the downloaded .gz against the
#   pinned hash and the binary's --version.
# - the .gz is a raw gzip of the ELF binary (NOT a tarball): gunzip it,
#   do not tar -xzf it (tar fails: "This does not look like a tar archive").
# - 0.6.2 hashes (x64 f3233408..., arm64 db7d7a1e...) were verified by
#   direct download + hashing of both assets.
set -eux
arch="$(uname -m)"
case "$arch" in
  x86_64) want_sha="${FNOS_CLI_X64_SHA256}"; asset_arch="x64" ;;
  aarch64) want_sha="${FNOS_CLI_ARM64_SHA256}"; asset_arch="arm64" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
asset="fnos-cli-${FNOS_CLI_VERSION}-linux-${asset_arch}.gz"
url="https://github.com/fnnas-labs/fnos-cli-skill/releases/download/v${FNOS_CLI_VERSION}/${asset}"
curl -fsSL -o /tmp/fnos-cli.gz "$url"
echo "${want_sha}  /tmp/fnos-cli.gz" | sha256sum -c -
gzip -dc /tmp/fnos-cli.gz > /usr/local/bin/fnos-cli
chmod 0755 /usr/local/bin/fnos-cli
rm -f /tmp/fnos-cli.gz
version="$(fnos-cli --version | head -n 1)"
echo "installed: $version"
echo "$version" | grep -Fq "fnos-cli ${FNOS_CLI_VERSION}" || {
  echo "version mismatch: expected fnos-cli ${FNOS_CLI_VERSION}, got: $version" >&2
  exit 1
}
