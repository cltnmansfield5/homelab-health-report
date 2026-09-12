"""Synthetic fixtures only. No personal logs, credentials or host access."""
import datetime as dt
import hashlib
import json
from pathlib import Path

from homelab_health.common import UTC, atomic_json, stamp

CONTAINER = "a" * 64
AT = dt.datetime(2026, 9, 10, 6, tzinfo=UTC)


def sample(at, offset=0, boot="fixture-boot"):
    return {"schema_version": 1, "kind": "host_sample", "at": stamp(at), "data": {
        "hostname": "synthetic-host", "boot_id": boot, "monotonic_seconds": 1000 + offset,
        "cpu_ticks": [100 + offset, 0, 100 + offset, 800 + offset, 0, 0, 0, 0, 90, 0],
        "memory_kib": {"MemTotal": 1000, "MemAvailable": 300},
        "network_counters": {"eth0": {"rx_bytes": 1000 + offset * 100, "tx_bytes": 2000 + offset * 50}},
        "disk_counters": {"sda": {"read_sectors_512b": 100 + offset, "write_sectors_512b": 200 + offset}}, "errors": {}}}


class FakeDocker:
    base = "http://fixture.invalid"

    def containers(self):
        return [{"Id": CONTAINER, "Names": ["/synthetic-plex"], "Labels": {}}]

    def inspect(self, container):
        return {"id": container, "name": "synthetic-plex", "image": "fixture:1", "tty": False,
                "state": {"Running": True, "Status": "running", "OOMKilled": False},
                "health": {"status": "healthy"}, "restart_count_snapshot": 2}

    def stats(self, container):
        return {"id": container, "memory_stats": {"usage": 1024, "limit": 8192}}

    def logs(self, container, start, end, tty, **kwargs):
        return stamp(end) + " ERROR fixture reconnect; token=secret-fixture-value\n", {"byte_limit_reached": False, "incomplete_frame": False, "line_limit_may_be_reached": False}


class MemoryDrive:
    def __init__(self):
        self.files = {"inbox": {}, "reports": {}}
        self.calls = []
        self.fail_archives = False

    def seed(self, folder, name, data, identity=None):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        self.files[folder][name] = {"raw": data, "Name": name, "Size": len(data),
                                    "Hashes": {"MD5": hashlib.md5(data, usedforsecurity=False).hexdigest()},
                                    "ID": identity or "id-" + hashlib.sha256((folder + name).encode()).hexdigest()[:20]}
        return self.files[folder][name]

    def list(self, folder):
        return {k: {x: v for x, v in item.items() if x != "raw"} for k, item in self.files[folder].items()}

    def put(self, path, name, folder):
        self.calls.append(("put", folder, name))
        if self.fail_archives and name.endswith(".tar.gz"):
            raise OSError("synthetic upload failure")
        return self.seed(folder, name, Path(path).read_bytes())

    def read(self, name, folder, limit=65536):
        return json.loads(self.files[folder][name]["raw"])

    def delete(self, name, folder, expected_id):
        self.calls.append(("delete", folder, name))
        item = self.files[folder].get(name)
        if item and item["ID"] != expected_id:
            raise ValueError("Identity changed")
        self.files[folder].pop(name, None)


def receipt(drive, uploaded, at):
    name = "Homelab-Health-2026-09-11-fixture.md"
    report = drive.seed("reports", name, b"# Synthetic verified report\n")
    marker = uploaded["marker"]
    data = {"schema_version": 1, "sha256": marker["sha256"], "archive_name": marker["archive_name"],
            "archive_id": uploaded["archive_id"], "processed_at_utc": stamp(at),
            "observed_coverage": {"start_utc": marker["requested_start_utc"], "end_utc": marker["requested_end_utc"]},
            "report_file_id": report["ID"], "report_url": "https://drive.google.com/file/d/" + report["ID"] + "/view"}
    drive.seed("reports", "processed-" + marker["sha256"] + ".json", data)
    return data
