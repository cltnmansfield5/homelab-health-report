# Komodo setup and migration

Deploy `compose.yaml` from a reviewed commit of the chosen repository. For new
installations, prefer `cltnmansfield5/homelab-health-report`. The old
`homelab-health` repository has the same project/image/data names and must not
run alongside it against the same state. Keep the health network separate from
`npm_proxy`; no public health-collector endpoint is required.

## Prepare the host

Follow the README's native-host installation and rclone steps first. The
installer creates directories, a service account, root-owned helper code, a
systemd unit and a private `.env`; it does not start services. Run it from the
same reviewed source revision as the container build. A Komodo repository clone
alone does not update `/opt/homelab-health` or `/etc/homelab-health`.

Set these private Komodo Stack variables from the existing installation:

| Variable | Source / meaning |
| --- | --- |
| `HH_UID`, `HH_GID` | Numeric IDs from `id homelab-health` |
| `DOCKER_GID` | Group ID of the host Docker socket |
| `DOCKER_SOCKET` | Supported default `/var/run/docker.sock` |
| `HH_DATA_DIR` | Existing data root, normally `/var/lib/homelab-health` |
| `HH_HOSTNAME` | Fallback host identity; helper status supplies the actual hostname |
| `HH_TIMEZONE` | IANA timezone controlling the daily bundle schedule |
| `HH_DRIVE_REMOTE` | Existing rclone remote name, without its trailing colon |
| `HH_INBOX_FOLDER_ID`, `HH_REPORTS_FOLDER_ID` | Distinct private Drive folder IDs |

The Compose file's fixed name is `homelab-health`; an explicit manager project-name
option can override it. Preserve the actual previous project when adopting a
stack and verify labels before deployment. Use `compose.yaml`, build context `.`,
and a full checkout so Dockerfile, package and non-secret TOML files are present.
The services build local images (`pull_policy: build`); do not replace this with
registry-only image pulling. Keep service selection explicit: `docker-api` and
`collector` work locally; enable `uploader` only after its credentials/folders are
configured. A whole-stack deployment includes the uploader.

## Adopt an existing Portainer deployment

1. Record the actual Compose project labels, data bind paths, current image IDs,
   private variables and the selected commit. Back up credentials and small state.
2. Configure the replacement Komodo Stack and render/validate its Compose config
   without starting it. Preserve storage and ownership. Confirm all paths visible
   to Periphery are mounted consistently on the host and inside the agent.
3. Stop the old collector/uploader through their existing owner during a short
   maintenance window. Confirm no other instances or one-shot jobs use their state.
4. Deploy the existing project through Komodo. Retire the old manager's redeploy
   webhook/schedule so it cannot start a second instance. Do not delete volumes,
   outbox, receipts or credential files as part of adoption.
5. Update/restart the native helper from the same reviewed checkout when its code
   changes, preserving the existing host TOML and private-redaction file:

```bash
sudo systemctl stop homelab-health-host.service
sudo bash scripts/prepare-host.sh
sudo systemctl start homelab-health-host.service
```

The helper service and installer use `/var/lib/homelab-health/host` explicitly.
Changing only `HH_DATA_DIR` does not move the helper or provision matching
permissions. Moving this data root requires a coordinated host-unit/config/data
migration; do not infer storage location from where the Git checkout lives.

## Verify and roll back

Confirm exactly one collector and uploader, gateway health, a recent healthy
helper status, a fresh archive/marker pair and (when enabled) a verified Drive
upload. Status files live in `host`, `collector-state`, and `uploader-state` under
the data root. Validate first without publishing private logs.

If rollback is necessary, stop the new owner before starting the previous one.
Restore the recorded revision and helper code consistently. Preserve evidence and
state; verify backwards compatibility before reusing state after a feature update.
See [operations](operations.md) for contention and collection-limit diagnosis.
