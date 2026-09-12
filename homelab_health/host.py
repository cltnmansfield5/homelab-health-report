"""Native host helper: fixed read-only checks, no listening socket or shell."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
import signal
import socket
import time

from .common import MIB, Redactor, Spool, atomic_json, bounded_int, command, lock, now, read_json, redactor_from, stamp, status

UNIT = re.compile(r"[A-Za-z0-9_@.:-]+\.(?:service|timer)\Z")
DEVICE = re.compile(r"/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+|disk/by-id/[A-Za-z0-9_.:-]+)\Z")


def read_text(path, limit=512 * 1024):
    with open(path) as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise ValueError("Host source exceeds limit")
    return text


def host_sample(proc=Path("/proc")):
    data = {"hostname": socket.gethostname(), "monotonic_seconds": time.monotonic(), "errors": {}}
    def get(name, fn):
        try:
            data[name] = fn()
        except (OSError, ValueError, IndexError) as exc:
            data["errors"][name] = type(exc).__name__
    get("boot_id", lambda: read_text(proc / "sys/kernel/random/boot_id").strip())
    get("uptime_seconds", lambda: float(read_text(proc / "uptime").split()[0]))
    get("cpu_ticks", lambda: [int(v) for v in read_text(proc / "stat").splitlines()[0].split()[1:]])
    get("load_average", lambda: [float(v) for v in read_text(proc / "loadavg").split()[:3]])
    get("memory_kib", lambda: {k.rstrip(":"): int(v) for k, v, *_ in (line.split() for line in read_text(proc / "meminfo").splitlines()) if k.rstrip(":") in {"MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SwapTotal", "SwapFree", "Dirty", "Writeback"}})
    get("vm_counters", lambda: {k: int(v) for k, v in (line.split() for line in read_text(proc / "vmstat").splitlines()) if k in {"pswpin", "pswpout", "pgmajfault", "oom_kill", "pgpgin", "pgpgout"}})
    for resource in ("cpu", "memory", "io"):
        get("pressure_" + resource, lambda r=resource: {line.split()[0]: {k: float(v) for k, v in (part.split("=") for part in line.split()[1:])} for line in read_text(proc / "pressure" / r).splitlines()})
    get("network_counters", lambda: {line.split(":")[0].strip(): {"rx_bytes": int(line.split(":")[1].split()[0]), "rx_errors": int(line.split(":")[1].split()[2]), "rx_drops": int(line.split(":")[1].split()[3]), "tx_bytes": int(line.split(":")[1].split()[8]), "tx_errors": int(line.split(":")[1].split()[10]), "tx_drops": int(line.split(":")[1].split()[11])} for line in read_text(proc / "net/dev").splitlines()[2:]})
    get("disk_counters", lambda: {v[2]: {"reads": int(v[3]), "read_sectors_512b": int(v[5]), "read_ms": int(v[6]), "writes": int(v[7]), "write_sectors_512b": int(v[9]), "write_ms": int(v[10]), "in_flight": int(v[11]), "io_ms": int(v[12]), "weighted_io_ms": int(v[13])} for v in (line.split() for line in read_text(proc / "diskstats").splitlines()) if len(v) >= 14 and not v[2].startswith(("loop", "ram"))})
    return data


class HostHelper:
    def __init__(self, config, directory):
        self.config = config
        self.directory = Path(directory)
        self.redactor = redactor_from(config)
        self.interval = bounded_int(config.get("sample_seconds", 60), 10, 3600, "sample_seconds")
        self.snapshot_interval = bounded_int(config.get("snapshot_seconds", 300), 60, 86400, "snapshot_seconds")
        self.journal_lines = bounded_int(config.get("journal_lines", 5000), 100, 20000, "journal_lines")
        self.spool = Spool(self.directory, self.redactor, bounded_int(config.get("daily_spool_mib", 64), 1, 1024, "daily_spool_mib") * MIB)
        self.units = config.get("journal_units", ["docker.service", "systemd-resolved.service", "NetworkManager.service", "systemd-networkd.service", "unattended-upgrades.service"])
        self.jobs = config.get("job_units", [])
        if any(not UNIT.fullmatch(v) for v in self.units + self.jobs) or len(self.units + self.jobs) > 32:
            raise ValueError("Invalid or excessive systemd units")
        self.devices = config.get("smart_devices", [])
        if any(not DEVICE.fullmatch(v) for v in self.devices) or len(self.devices) > 32:
            raise ValueError("Invalid SMART device")
        self.stop = False

    def snapshot(self, start, end):
        base = ["journalctl", "--no-pager", "--output=json", "--since=@" + str(int(start.timestamp())), "--until=@" + str(int(end.timestamp())), "--lines=" + str(self.journal_lines + 1)]
        queries = {"journal_warnings": base + ["--priority=0..4"], "kernel_journal": base + ["--dmesg"]}
        if self.units + self.jobs:
            queries["unit_journal"] = base + [arg for unit in self.units + self.jobs for arg in ("--unit", unit)]
        for kind, argv in queries.items():
            result = command(argv, limit=2 * MIB)
            rows = []
            malformed = 0
            for line in result.pop("text", "").splitlines():
                try:
                    raw = json.loads(line)
                    rows.append({k: raw[k] for k in ("__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "PRIORITY", "MESSAGE", "__CURSOR") if k in raw})
                except ValueError:
                    malformed += 1
            result.update({"requested_start_utc": stamp(start), "requested_end_utc": stamp(end), "rows": rows[-self.journal_lines:], "line_limit_reached": len(rows) > self.journal_lines, "unparsed_lines": malformed})
            self.spool.append(kind, result)
        checks = {
            "failed_units": ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"],
            "boot_history": ["journalctl", "--list-boots", "--no-pager", "--lines=10"],
            "clock": ["timedatectl", "show", "--property=NTPSynchronized", "--property=TimeUSec", "--property=Timezone"],
            "links": ["ip", "-j", "-s", "link", "show"],
            "routes": ["ip", "-j", "route", "show"],
            "dns_state": ["resolvectl", "status", "--no-pager"],
            "mounts": ["findmnt", "--json", "--output=TARGET,SOURCE,FSTYPE"],
        }
        for name, argv in checks.items():
            result = command(argv)
            if name == "clock" and result.get("ok") and "NTPSynchronized=" not in result.get("text", ""):
                result.update(ok=False, error="clock_properties_missing")
            self.spool.append(name, result)
        filesystems = []
        for path in self.config.get("filesystem_paths", ["/"]):
            if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
                raise ValueError("Filesystem paths must be absolute")
            try:
                s = os.statvfs(path)
                filesystems.append({"path": path, "total_bytes": s.f_blocks * s.f_frsize, "available_bytes": s.f_bavail * s.f_frsize, "free_bytes": s.f_bfree * s.f_frsize, "inodes": s.f_files, "free_inodes": s.f_favail})
            except OSError as exc:
                filesystems.append({"path": path, "error": type(exc).__name__})
        self.spool.append("filesystems", filesystems)
        for unit in self.jobs:
            properties = ("LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestamp", "ExecMainExitTimestamp", "LastTriggerUSec", "NextElapseUSecRealtime")
            result = command(["systemctl", "show", unit, *["--property=" + name for name in properties]])
            if result.get("ok") and ("ActiveState=" not in result.get("text", "") or "LoadState=not-found" in result.get("text", "")):
                result.update(ok=False, error="job_properties_missing_or_unit_not_found")
            self.spool.append("job_status", {"unit": unit, **result})
        for host in self.config.get("dns_probe_hosts", []):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
                raise ValueError("Invalid DNS probe host")
            started = time.monotonic()
            self.spool.append("dns_probe", {"host": host, "result": command(["getent", "ahosts", host], timeout=5), "elapsed_ms": round((time.monotonic() - started) * 1000)})
        for target in self.config.get("ping_targets", []):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", target):
                raise ValueError("Invalid connectivity target")
            self.spool.append("connectivity_probe", {"target": target, "result": command(["ping", "-n", "-c", "1", "-W", "2", target], timeout=4)})

    def daily(self):
        self.spool.append("os", {"hostname": socket.gethostname(), "release": read_text("/etc/os-release"), "kernel": os.uname().release})
        self.spool.append("updates", {"reboot_required": Path("/var/run/reboot-required").exists(), "apt_cache_only": True, "upgradable": command(["apt", "list", "--upgradable"], timeout=30), "note": "Cached package state; no apt update or upgrade is run."})
        self.spool.append("temperatures", command(["sensors", "-j"]))
        if self.config.get("nvidia_gpu", False):
            self.spool.append("gpu", command(["nvidia-smi", "--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw", "--format=csv,noheader,nounits"]))
        devices = self.devices[:]
        if not devices and self.config.get("smart_autodetect", True):
            scan = command(["lsblk", "--json", "--nodeps", "--output=NAME,TYPE,TRAN"])
            try:
                devices = ["/dev/" + d["name"] for d in json.loads(scan.get("text", "{}"))["blockdevices"] if d["type"] == "disk" and DEVICE.fullmatch("/dev/" + d["name"])]
            except (ValueError, KeyError, TypeError):
                self.spool.append("smart_discovery", {"error": "device_discovery_failed", "result": scan})
        if not devices:
            self.spool.append("smart", {"error": "no_supported_devices_configured_or_found"})
        for device in devices[:32]:
            # -n standby avoids spinning up sleeping ATA disks. No tests or settings changes.
            result = command(["smartctl", "--json", "--all", "--quietmode=noserial", "--nocheck=standby", device], timeout=30)
            try:
                parsed = json.loads(result.pop("text", "{}"))
                parsed.pop("serial_number", None)
                parsed.pop("wwn", None)
                result["data"] = parsed
            except ValueError:
                result["error"] = "invalid_smart_json"
            self.spool.append("smart", {"device": device, "exit_status_is_bitmask": True, **result})

    def once(self, full=True):
        sample = host_sample()
        accepted = self.spool.append("host_sample", sample)
        if full:
            end = now()
            self.snapshot(end - dt.timedelta(minutes=5), end)
            self.daily()
        status(self.directory / "status.json", accepted and not sample["errors"], hostname=socket.gethostname(), sample_errors=sample["errors"], sample_seconds=self.interval)

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "stop", True))
        with lock(self.directory / ".helper.lock"):
            try:
                state = read_json(self.directory / "helper-state.json")
            except (OSError, ValueError):
                state = {}
            last_snapshot = float(state.get("last_snapshot", time.time() - self.snapshot_interval))
            while not self.stop:
                started = time.monotonic()
                try:
                    self.once(full=False)
                    end = now()
                    if end.timestamp() - last_snapshot >= self.snapshot_interval:
                        start = dt.datetime.fromtimestamp(max(last_snapshot - 60, end.timestamp() - 86400), dt.timezone.utc)
                        self.snapshot(start, end)
                        if end.timestamp() - last_snapshot > 86400:
                            self.spool.append("helper_gap", {"error": "helper_absence_exceeded_journal_backfill", "last_snapshot_epoch": last_snapshot})
                        last_snapshot = end.timestamp()
                        state["last_snapshot"] = last_snapshot
                    if state.get("daily_date") != end.date().isoformat():
                        self.daily()
                        state["daily_date"] = end.date().isoformat()
                    atomic_json(self.directory / "helper-state.json", state)
                except Exception as exc:
                    status(self.directory / "status.json", False, error=type(exc).__name__)
                while not self.stop and time.monotonic() - started < self.interval:
                    time.sleep(0.5)
