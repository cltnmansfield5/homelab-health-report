#!/usr/bin/env python3
"""Generate a small synthetic bundle and report without Docker, root or network."""
import datetime as dt
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from homelab_health.bundle import BundleWriter
from homelab_health.common import now, stamp
from homelab_health.report import report
from tests.fixtures import CONTAINER, FakeDocker, sample

root = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-output")
root.mkdir(parents=True, exist_ok=True)
end = now()
start = end - dt.timedelta(minutes=5)
writer = BundleWriter(root, "synthetic-host", start, end)
writer.manifest["synthetic_fixture"] = True
writer.add("README.txt", "SYNTHETIC DEMONSTRATION ONLY. These are invented measurements, not diagnostics from your computer.\n")
rows = [sample(start + dt.timedelta(minutes=i), i * 60) for i in range(6)]
rows.append({"kind": "filesystems", "at": stamp(end), "data": [{"path": "/synthetic-media", "total_bytes": 1000, "available_bytes": 70, "inodes": 1000, "free_inodes": 900}]})
writer.add("host/evidence-000.jsonl", ("\n".join(json.dumps(r) for r in rows) + "\n").encode(), records=len(rows), first_record_utc=stamp(start), last_record_utc=stamp(end))
state = FakeDocker().inspect(CONTAINER)
state["health"]["status"] = "unhealthy"
writer.add("docker/evidence-000.jsonl", (json.dumps({"kind": "docker_state", "at": stamp(end), "data": state}) + "\n").encode(), records=1, first_record_utc=stamp(end), last_record_utc=stamp(end))
writer.add("logs/" + CONTAINER + ".log", stamp(end) + " ERROR synthetic timeout; token=demonstration-secret\n")
marker = writer.finish()
report(root / marker["archive_name"], root / (marker["bundle_id"] + ".ready.json"), root / "Synthetic-Homelab-Report.md")
print(root.resolve() / "Synthetic-Homelab-Report.md")
