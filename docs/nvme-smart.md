# Isolated NVMe SMART collection

Linux NVMe admin log reads require `CAP_SYS_ADMIN`; the general host helper
deliberately lacks it. A successful manual root read does not prove that the
restricted helper can read the same log.

The separate `homelab-health-nvme-smart.service` runs only a fixed, bounded
`/usr/sbin/smartctl --json --all --quietmode=noserial --device=nvme /dev/nvmeN`
read for controllers enumerated from sysfs. It accepts no commands, paths or
configuration from containers or callers and starts no tests or repairs.
Its timer runs shortly after boot and every six hours, with up to five minutes
random delay. The installer installs files but starts no service.

The probe retains its original observation times and writes one sanitized JSON
cache atomically to `/var/lib/homelab-health/nvme/smart.json` (root-owned,
0640, group `homelab-health`). The general helper imports changed results during
its five-minute snapshot, checking file type/ownership/mode, size/schema, host,
boot, device identity and a maximum source age of seven hours. Serial numbers,
WWNs, EUI-64 and NGUID fields are suppressed recursively. A boot-salted identity
digest prevents accepting a previous physical controller's cache after replacement.
The cache is not mounted into any container; sanitized evidence goes through
the existing host spool and bundle checks.

Missing, failed, malformed, stale or mismatched results remain explicit gaps.
A failed refresh replaces the previous healthy cache. Health-warning bitmasks
and large integer counters are retained. A complete read is not proof of full
device health or an explanation for application I/O latency.

## Rollout

After reviewing and checking out the change, run from that checkout on the host:

```bash
sudo bash scripts/prepare-host.sh
sudo systemctl start homelab-health-nvme-smart.service
sudo systemctl enable --now homelab-health-nvme-smart.timer
sudo systemctl restart homelab-health-host.service
```

The first command preserves installed host settings, private data and credentials.
Rebuild/redeploy the existing collector through its deployment owner as usual
so bundled trusted code and the local reporter match the installed helper.
Do not create a second Compose stack. No extra capabilities are added to the
general helper or any container.

Verify on the actual host:

```bash
systemctl show homelab-health-host.service -p CapabilityBoundingSet
systemctl show homelab-health-nvme-smart.service -p Result -p ExecMainStatus -p CapabilityBoundingSet
systemctl list-timers homelab-health-nvme-smart.timer --no-pager
sudo python3 -m json.tool /var/lib/homelab-health/nvme/smart.json
sudo journalctl -u homelab-health-nvme-smart.service --since '15 minutes ago' --no-pager
```

Confirm the main helper still lacks `CAP_SYS_ADMIN`, the probe succeeded and the
cache identifies the current host/boot/controller. Check the next completed
bundle for `smart` records with `source = "nvme_cache"` and original
`observed_at_utc` values. The helper's daily-date state need not be deleted;
the next five-minute snapshot imports the cache. Do not publish the private
cache or bundle in a PR. Offline tests cannot prove the hardware/ioctl policy.

## Rollback and failure handling

```bash
sudo systemctl disable --now homelab-health-nvme-smart.timer
sudo systemctl stop homelab-health-nvme-smart.service
```

The reader will report stale/missing coverage instead of reusing old healthy
data as a new reading. For a full rollback, reinstall the previous reviewed
revision with `scripts/prepare-host.sh`, rebuild the existing stack and restart
the host helper. Leave the new timer disabled; the old helper will again report
its NVMe permission gap. Preserve caches, spools and existing private settings.
Do not add `CAP_SYS_ADMIN` to the general helper, make device nodes world-writable,
or apply file capabilities to the shared smartctl executable.

If the probe fails, inspect its journal and cached error/bitmask. Its device
policy allows only the `char-nvme` controller class. Unsupported device layouts
remain gaps and require a reviewed change; this is not a generic disk proxy.

[Security boundary](../SECURITY.md) · [Operations](operations.md)
