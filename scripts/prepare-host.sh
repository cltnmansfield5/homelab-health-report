#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo 'Run with sudo from the project checkout.' >&2
  exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
/usr/bin/python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required (Ubuntu 24.04+ recommended)"'
if [[ ! -S /var/run/docker.sock ]]; then
  echo 'Expected native rootful Docker at /var/run/docker.sock. See README for rootless/WSL limitations.' >&2
  exit 1
fi
if ! getent group homelab-health >/dev/null; then
  groupadd --system homelab-health
fi
if ! id homelab-health >/dev/null 2>&1; then
  useradd --system --gid homelab-health --home-dir /nonexistent --shell /usr/sbin/nologin homelab-health
fi
health_uid="$(id -u homelab-health)"
health_gid="$(getent group homelab-health | cut -d: -f3)"
socket_gid="$(stat -c '%g' /var/run/docker.sock)"
install -d -o root -g homelab-health -m 0750 /var/lib/homelab-health
install -d -o root -g homelab-health -m 0750 /var/lib/homelab-health/host
for directory in outbox samples collector-state uploader-state credentials; do
  install -d -o "$health_uid" -g "$health_gid" -m 0700 "/var/lib/homelab-health/$directory"
done
# Root-owned package copy prevents a container or unprivileged checkout edit from changing the helper.
install -d -o root -g root -m 0755 /opt/homelab-health/homelab_health /etc/homelab-health
for source in "$project_dir"/homelab_health/*.py; do
  install -o root -g root -m 0644 "$source" /opt/homelab-health/homelab_health/
done
if [[ ! -f /etc/homelab-health/host.toml ]]; then
  install -o root -g root -m 0600 "$project_dir/config/host.toml" /etc/homelab-health/host.toml
fi
if [[ ! -f /etc/homelab-health/private-redactions.txt ]]; then
  install -o root -g homelab-health -m 0640 /dev/null /etc/homelab-health/private-redactions.txt
fi
install -o root -g root -m 0644 "$project_dir/deploy/systemd/homelab-health-host.service" /etc/systemd/system/
if [[ -f "$project_dir/.env" ]]; then
  echo 'Preserved existing .env; verify IDs if this is a reinstall.'
else
  umask 077
  cat > "$project_dir/.env" <<EOF
HH_UID=$health_uid
HH_GID=$health_gid
DOCKER_GID=$socket_gid
DOCKER_SOCKET=/var/run/docker.sock
HH_DATA_DIR=/var/lib/homelab-health
HH_HOSTNAME=homelab
HH_TIMEZONE=UTC
HH_DRIVE_REMOTE=homelab
HH_INBOX_FOLDER_ID=
HH_REPORTS_FOLDER_ID=
EOF
  if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
    chown "$SUDO_UID:$SUDO_GID" "$project_dir/.env"
  fi
fi
systemctl daemon-reload
echo 'Prepared directories, root-owned helper, and Compose IDs. No service has been started.'
echo 'Review /etc/homelab-health/host.toml, then follow README.md to start collection.'
