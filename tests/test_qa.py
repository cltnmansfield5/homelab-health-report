"""Regressions from the public-release review; synthetic inputs only."""
import datetime as dt
import io
import json
import os
from pathlib import Path
import signal
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from homelab_health.bundle import BundleWriter, read_verified_bundle
from homelab_health.common import MIB, Redactor, atomic_json, command, digest_file, load_config, now, read_json, stamp
from homelab_health.host import HostHelper
from homelab_health.report import analyze
from homelab_health.uploader import valid_receipt
from tests.fixtures import AT, CONTAINER, sample


class QARegressions(unittest.TestCase):
    def test_cookie_header_redacts_every_cookie(self):
        result = Redactor().text("Cookie: session=first-private-value; second=another-private-value\nSet-Cookie: sid=third-private-value; HttpOnly")
        for value in ("first-private-value", "another-private-value", "third-private-value"):
            self.assertNotIn(value, result)

    def test_environment_settings_override_only_allowed_keys(self):
        with tempfile.TemporaryDirectory() as root:
            config = Path(root) / "config.toml"
            config.write_text('timezone="UTC"\nremote="homelab"\n')
            with patch.dict(os.environ, {"HH_TIMEZONE": "America/Denver", "HH_DRIVE_REMOTE": "private-remote"}):
                result = load_config(config, {"timezone": "HH_TIMEZONE"})
            self.assertEqual(result, {"timezone": "America/Denver", "remote": "homelab"})

    def test_clock_and_job_properties_are_captured(self):
        def fixed_command(argv, **kwargs):
            if argv[:2] in (["timedatectl", "show"], ["systemctl", "show"]):
                properties = [arg.removeprefix("--property=") for arg in argv if arg.startswith("--property=")]
                values = {"NTPSynchronized": "yes", "ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": "1"}
                return {"ok": True, "text": "\n".join(k + "=" + values[k] for k in properties if k in values)}
            return {"ok": True, "text": ""}
        with tempfile.TemporaryDirectory() as root:
            helper = HostHelper({"filesystem_paths": [], "job_units": ["backup.service"]}, root)
            with patch("homelab_health.host.command", side_effect=fixed_command):
                helper.snapshot(AT, AT)
            rows = [json.loads(line) for p in Path(root).glob("*.jsonl") for line in p.read_text().splitlines()]
        self.assertIn("NTPSynchronized=yes", next(r["data"]["text"] for r in rows if r["kind"] == "clock"))
        self.assertIn("Result=exit-code", next(r["data"]["text"] for r in rows if r["kind"] == "job_status"))

    def test_empty_properties_and_failed_samples_are_unhealthy(self):
        with tempfile.TemporaryDirectory() as root:
            helper = HostHelper({"filesystem_paths": [], "job_units": ["missing.service"]}, root)
            with patch("homelab_health.host.command", return_value={"ok": True, "text": ""}):
                helper.snapshot(AT, AT)
            rows = [json.loads(line) for p in Path(root).glob("*.jsonl") for line in p.read_text().splitlines()]
            self.assertTrue(all(not r["data"]["ok"] for r in rows if r["kind"] in ("clock", "job_status")))
            with patch("homelab_health.host.host_sample", return_value={"errors": {"memory_kib": "OSError"}}):
                helper.once(full=False)
            self.assertFalse(read_json(Path(root) / "status.json")["ok"])

    def test_smart_requests_identifier_suppression(self):
        with tempfile.TemporaryDirectory() as root:
            helper = HostHelper({"smart_devices": ["/dev/nvme0n1"]}, root)
            with patch("homelab_health.host.read_text", return_value="fixture"), patch("homelab_health.host.command", return_value={"ok": True, "text": "{}"}) as run:
                helper.daily()
            argv = next(c.args[0] for c in run.call_args_list if c.args[0][0] == "smartctl")
            self.assertIn("--quietmode=noserial", argv)
            self.assertFalse(any(arg.startswith(("--test", "--set")) for arg in argv))

    def test_timeout_kills_descendant_after_parent_exits(self):
        code = "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); print(p.pid,flush=True)"
        result = command([sys.executable, "-c", code], timeout=0.3)
        self.assertTrue(result["timed_out"])
        pid = int(result["text"].strip())
        path = Path(f"/proc/{pid}/status")
        try:
            stopped = False
            for _ in range(100):
                try:
                    state = next(line.split()[1] for line in path.read_text().splitlines() if line.startswith("State:"))
                    stopped = state in ("Z", "X")
                except FileNotFoundError:
                    stopped = True
                if stopped:
                    break
                time.sleep(0.01)
            self.assertTrue(stopped, "Timed-out descendant is still running")
        finally:
            if not stopped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_pax_metadata_cannot_bypass_expansion_budget(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            writer = BundleWriter(root, "fixture", AT - dt.timedelta(minutes=1), AT)
            writer.add("README.txt", "fixture")
            marker = writer.finish()
            archive, ready = root / marker["archive_name"], root / (marker["bundle_id"] + ".ready.json")
            _, _, files = read_verified_bundle(archive, ready)
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": "x" * (3 * MIB)}) as tar:
                for name, raw in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    tar.addfile(info, io.BytesIO(raw))
            marker.update(archive_bytes=archive.stat().st_size, sha256=digest_file(archive))
            atomic_json(ready, marker)
            with self.assertRaisesRegex(ValueError, "stream limit"):
                read_verified_bundle(archive, ready, max_expanded=4096)

    def test_nonobject_receipt_cannot_authorize_retention(self):
        self.assertFalse(valid_receipt([], {}, "archive-id", {}))

    def test_old_empty_status_is_a_gap_and_logs_use_service_name(self):
        at = stamp(now())
        rows = [{"kind": kind, "at": at, "data": {"ok": True, "text": "", "unit": "backup.service"}} for kind in ("clock", "job_status")]
        rows.append({"kind": "docker_state", "at": at, "data": {"id": CONTAINER, "name": "fixture-app"}})
        rows.append(sample(now()))
        result = analyze({"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": at, "requested_end_utc": at, "collection_finished_utc": at}, {"files": [], "issues": []}, {
            "host/evidence-000.jsonl": "\n".join(json.dumps(row) for row in rows).encode(),
            "logs/" + CONTAINER + ".log": (at + " ERROR fixture").encode()
        })
        messages = " ".join(f["message"] for f in result["findings"])
        self.assertIn("Clock synchronization status unavailable", messages)
        self.assertIn("Configured job status unavailable", messages)
        self.assertEqual(next(f["service"] for f in result["findings"] if f["key"].startswith("log_review:")), "fixture-app")
