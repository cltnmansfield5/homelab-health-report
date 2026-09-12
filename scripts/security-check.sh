#!/usr/bin/env bash
# Development/CI only. Downloads pinned scanners; never runs in the collector.
set -euo pipefail
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This scanner runner currently supports Linux x86_64; use the CI result on other platforms.' >&2
  exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
security_dir="$(mktemp -d)"
trap 'rm -rf -- "$security_dir"' EXIT

download_scanner() {
  local name="$1" url="$2" sha="$3"
  curl --fail --silent --show-error --location --retry 3 "$url" -o "$security_dir/$name.tar.gz"
  printf '%s  %s\n' "$sha" "$security_dir/$name.tar.gz" | sha256sum --check --status
  tar -xzf "$security_dir/$name.tar.gz" -C "$security_dir" "$name"
}

download_scanner gitleaks \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
"$security_dir/gitleaks" git --redact --no-banner --log-opts=--all .
"$security_dir/gitleaks" dir --redact --no-banner .

python3 -m venv "$security_dir/venv"
"$security_dir/venv/bin/pip" --disable-pip-version-check install --quiet bandit==1.9.4
"$security_dir/venv/bin/bandit" -r homelab_health -ll -ii

if [[ $# -gt 0 ]]; then
  download_scanner trivy \
    https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz \
    2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
  for image in "$@"; do
    "$security_dir/trivy" image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --no-progress "$image"
  done
fi
