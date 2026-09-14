# Homelab Health

Drive binary downloads unavailable in your report worker? The uploader includes
a [lossless text fallback](docs/text-transport.md) that preserves the original
archive hashes, safety checks, and receipt-gated retention.

Collect Docker and native Ubuntu diagnostics, build verified archives, and
optionally upload completed drops to private Google Drive folders for reporting.
The runtime uses Python's standard library. It never repairs or restarts monitored
services.

| Component | Access |
| --- | --- |
| Docker gateway | Docker socket; a small GET allowlist; internal network only |
| Collector | Gateway, read-only helper exports, writable sample/bundle queue |
| Ubuntu helper | Root-owned systemd service; fixed host checks; restricted capabilities |
| Uploader | Bundle queue, state and its own rclone credentials; separate outbound network |

No container publishes a port. See [security boundaries](SECURITY.md) before
deployment. A read-only socket mount does not restrict Docker API operations.

## Try it offline

Python 3.11+ is required. The demo uses invented data and no host/cloud access.

~~~bash
python3 -m unittest discover -v
python3 scripts/demo.py
~~~

Open demo-output/Synthetic-Homelab-Report.md.

## Install

Target: native Ubuntu 24.04+, systemd, rootful Docker Engine and Compose v2.
Rootless Docker, WSL and Docker Desktop need a separate host-access review.

~~~bash
sudo apt-get update
sudo apt-get install -y python3 smartmontools lm-sensors iproute2 iputils-ping rclone
sudo bash scripts/prepare-host.sh
sudoedit /etc/homelab-health/host.toml
~~~

The installer creates the service account, private directories, root-owned helper
and local .env. It preserves installed configuration and starts no services.
Set filesystem_paths to actual mount targets; add backup service/timer names to
job_units if wanted. Missing or unsupported checks remain visible coverage gaps.

Set your hostname fallback and timezone in .env. Keep private settings out of Git.
Then start local collection:

~~~bash
sudo systemctl enable --now homelab-health-host.service
docker compose up -d --build docker-api collector
docker compose ps
~~~

For **Portainer Community**, follow [its setup and upgrade guide](docs/portainer.md)
instead of starting another Compose project.

## Optional Drive uploads

Create or reuse an rclone remote with rclone config. An Ubuntu Online Accounts
connection alone does not supply rclone credentials. Create/select two private
folders, Inbox and Reports, and set HH_DRIVE_REMOTE, HH_INBOX_FOLDER_ID and
HH_REPORTS_FOLDER_ID in .env or Portainer. The examples contain no real account
or folder identifiers. Empty folder IDs stop the uploader.

~~~bash
rclone listremotes
rclone config file
sudo install -o homelab-health -g homelab-health -m 0600 /PATH/TO/rclone.conf /var/lib/homelab-health/credentials/rclone.conf
docker compose up -d --build uploader
sudo cat /var/lib/homelab-health/uploader-state/status.json
~~~

Use [rclone's Drive authorization guide](https://rclone.org/drive/).
A working-folder ID is not an OAuth permission boundary; an existing-folder setup
usually needs broader Drive access. Only the uploader mounts credentials, writable
for token refresh. Inspect a real bundle's redaction before enabling uploads.

## Reports, limits and operation

- Host/container counters: every 60 seconds; selected journals and status: every
  5 minutes; SMART, temperatures and cached update state: daily.
- Bundles: startup catch-up, then 06:00 in HH_TIMEZONE; default UTC. Five-minute
  overlap, at most seven days of backfill. History starts when collection starts.
- Each source spool: 64 MiB/day, current UTC date plus seven preceding dates.
  Bundles: 128 MiB payload; queue: 2 GiB. Limits and source gaps are recorded.
- Reviewed bundles: 7 days locally / 30 days in Drive, measured from collection
  completion. Cleanup requires a matching receipt and saved report. Unprocessed
  bundles are preserved; a full queue stops new bundles.

Run from the checkout, replacing BUNDLE with the exact basename:

~~~bash
sudo python3 -m homelab_health report /var/lib/homelab-health/outbox/BUNDLE.tar.gz --marker /var/lib/homelab-health/outbox/BUNDLE.ready.json --output /var/lib/homelab-health/First-Report.md
~~~

This creates Markdown and companion JSON triage; it does not issue a processing
receipt. See [reporting](docs/reporting.md) and the [bundle protocol](docs/bundle-protocol.md).

Check container health and the host, collector-state and uploader-state
status.json files under /var/lib/homelab-health. For private exact-string
redaction, edit /etc/homelab-health/private-redactions.txt and restart the helper
and collector. Pattern redaction cannot guarantee that free-form logs are safe
to publish.

For updates, use a reviewed revision, rerun the helper installer, rebuild the
images and restart this project's services. Preserve data, state and credentials.
Installed host configuration is preserved; compare new examples manually.
Watchtower updates are disabled for these containers.

[Architecture](docs/architecture.md) · [QA](docs/validation.md)
