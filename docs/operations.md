# Operations and troubleshooting

## Storage contract

| Host location | Contents / owner |
| --- | --- |
| `/opt/homelab-health` | Installed root-owned Python helper code |
| `/etc/homelab-health` | Private host config and literal-redaction file |
| `/var/lib/homelab-health/host` | Helper status and bounded raw host evidence |
| `/var/lib/homelab-health/samples` | Bounded Docker sample/event spool |
| `/var/lib/homelab-health/outbox` | Immutable archive/marker pairs awaiting upload/review |
| `/var/lib/homelab-health/collector-state` | Schedule, event cursor and collector lock |
| `/var/lib/homelab-health/uploader-state` | Remote identities, retries, receipts-related bookkeeping and lock |
| `/var/lib/homelab-health/credentials` | Private writable rclone OAuth configuration |

These paths default to the OS filesystem, independently of the SSD application
layout used by the media repos. Check `findmnt -T` on each actual path. Keep
uploader state with the outbox and retain the private credential during migration.

## BlockingIOError / Errno 11

The shared `lock()` function uses nonblocking `flock` for singleton roles. A
second collector, uploader, helper or manual one-shot invocation using the same
state fails with `BlockingIOError: [Errno 11] Resource temporarily unavailable`.
A traceback ending in `fcntl.flock` confirms this cause. Errno 11 at a different
call site can instead mean a resource/process limit; obtain the full traceback.

Inspect the actual lock owner and all project labels before changing limits:

```bash
docker ps -a --format 'table {{.Names}}	{{.Status}}	{{.Label "com.docker.compose.project"}}	{{.Label "com.docker.compose.service"}}'
sudo lslocks --output PID,COMMAND,PATH
```

Identify the old Portainer/CLI/Komodo deployment or overlapping one-shot job and
stop only that duplicate through its owner. An inactive file is harmless; the OS
lock is released on process exit. **Do not delete an active lock file**: another
process can then lock a new inode, allowing two writers. Do not remove state or
credentials to clear contention. Raising spool or PID limits cannot fix a lock
held by a second process.

## Gaps, caps and stale status

Read the status and gap/pruning records together. A spool cap is measured in bytes
per UTC date, independently for host and Docker sources. Daily raw retention is
separate from the immutable outbox's receipt-gated cleanup. Unprocessed archives
are intentionally retained. A full queue requires capacity/processing recovery;
blindly deleting archives loses evidence and can invalidate retention records.

Collector TOML is baked into the image, so changing limits or selection requires
a rebuild. Host TOML is installed outside the image and preserved by the helper
installer; edit it privately and restart the helper. Preserve locally increased
caps when updating code. A new config example does not overwrite existing host
settings. Noise compaction exists only in the public successor and cannot recover
already dropped data.

Never equate a running container with a successful upload. Verify folder IDs,
remote name, credential ownership/token refresh, image revision and upload status.
The report command creates Markdown/JSON only; it does not create a full-review
processing receipt or send email. Those actions belong to the separate report
worker and require its own setup.

[Komodo guide](komodo.md) · [Protocol](bundle-protocol.md) · [Security](../SECURITY.md)
