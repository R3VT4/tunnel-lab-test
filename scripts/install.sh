#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
binary=""
staging=""
while (($#)); do
  case "$1" in
    --binary) [[ $# -ge 2 ]] || { echo 'Missing --binary value' >&2; exit 2; }; binary=$2; shift 2 ;;
    --staging-dir) [[ $# -ge 2 ]] || { echo 'Missing --staging-dir value' >&2; exit 2; }; staging=$2; shift 2 ;;
    --help) echo 'install.sh [--binary PATH] [--staging-dir EMPTY_TEST_ROOT]'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $(uname -s) == Linux ]] || { echo 'Linux required' >&2; exit 1; }
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
if [[ -z "$binary" ]]; then
  binary="$project_dir/tunnellab"
  [[ -f "$binary" ]] || binary="$project_dir/bin/tunnellab-linux-$arch"
fi
[[ -x "$binary" ]] || { echo 'Executable binary missing; build or extract a release first' >&2; exit 1; }
unit="$project_dir/systemd/tunnellab@.service"
[[ -f "$unit" ]] || { echo 'systemd template missing' >&2; exit 1; }
"$binary" version
if [[ -n "$staging" ]]; then
  [[ "$staging" = /* && "$staging" != / && ! -e "$staging" ]] || { echo 'Staging path must be a new absolute directory' >&2; exit 1; }
  mkdir -m 700 -- "$staging"
  install -d -m 755 -- "$staging/usr/local/bin" "$staging/etc/systemd/system"
  install -d -m 750 -- "$staging/etc/tunnellab/instances"
  install -m 755 -- "$binary" "$staging/usr/local/bin/tunnellab"
  install -m 644 -- "$unit" "$staging/etc/systemd/system/tunnellab@.service"
  echo 'Staged only; no service account, systemd call, or global change.'
  exit 0
fi
[[ $EUID == 0 ]] || { echo 'Run with sudo for system installation' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd host is required' >&2; exit 1; }
for tool in install getent useradd systemctl; do command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }; done
if ! getent passwd tunnellab >/dev/null; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tunnellab
fi
[[ $(id -u tunnellab) != 0 ]] || { echo 'Refusing a root service identity' >&2; exit 1; }
getent group tunnellab >/dev/null || { echo 'Service group missing' >&2; exit 1; }
install -d -o root -g tunnellab -m 750 /etc/tunnellab /etc/tunnellab/instances
install -d -m 755 /usr/local/bin /etc/systemd/system
[[ ! -L /usr/local/bin/tunnellab && ! -L /usr/local/bin/tunnellab.previous ]] || { echo 'Refusing symbolic link binary destinations' >&2; exit 1; }
tmp_binary=$(mktemp /usr/local/bin/.tunnellab-install.XXXXXX)
trap 'rm -f -- "$tmp_binary"' EXIT
install -m 755 -- "$binary" "$tmp_binary"
if [[ -f /usr/local/bin/tunnellab ]]; then
  install -m 755 /usr/local/bin/tunnellab /usr/local/bin/tunnellab.previous
fi
mv -f -- "$tmp_binary" /usr/local/bin/tunnellab
install -m 644 -- "$unit" /etc/systemd/system/tunnellab@.service
systemctl daemon-reload
echo 'Installed. No instance started or restarted. Next: tunnellab service add -name NAME -config FILE'
