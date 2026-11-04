#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$project_dir"
release_version=$(tr -d '\r\n' < VERSION)
[[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || { echo 'Invalid VERSION' >&2; exit 1; }
if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "v$release_version" ]]; then
  echo 'Tag and VERSION do not match' >&2; exit 1
fi
command -v go >/dev/null || { echo 'Go 1.26 or later is required to build releases' >&2; exit 1; }
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
for arch in amd64 arm64; do
  package="$stage/$arch"
  mkdir -p -- "$package/scripts" "$package/systemd"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$release_version" -o "$package/tunnellab" .
  cp -- README.md README_FA.md INSTALL_FA.md VALIDATION.md CHANGELOG.md DIAGNOSTICS_FA.md ROADMAP_FA.md VERSION "$package/"
  cp -- systemd/tunnellab@.service "$package/systemd/"
  cp -- scripts/install.sh "$package/scripts/"
  chmod 755 "$package/tunnellab" "$package/scripts/install.sh"
  (cd -- "$package" && sha256sum tunnellab > BINARY_SHA256SUMS)
  asset="tunnellab_v${release_version}_linux_${arch}.tar.gz"
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$package" -czf "dist/$asset" tunnellab README.md README_FA.md INSTALL_FA.md VALIDATION.md CHANGELOG.md DIAGNOSTICS_FA.md ROADMAP_FA.md VERSION BINARY_SHA256SUMS scripts systemd
done
(cd dist && sha256sum "tunnellab_v${release_version}_linux_amd64.tar.gz" "tunnellab_v${release_version}_linux_arm64.tar.gz" > SHA256SUMS)
echo "Built linux/amd64 and linux/arm64 release assets in dist/"
