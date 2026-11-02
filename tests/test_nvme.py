import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_health import nvme
from homelab_health.common import atomic_json, read_json, stamp
from homelab_health.host import HostHelper
from homelab_health.report import analyze
from tests.fixtures import AT

BOOT = "00000000-1111-2222-3333-444444444444"
HEALTH = {"smart_status": {"passed": True},
          "nvme_smart_health_information_log": {"critical_warning": 0, "data_units_written": 2 ** 70},
          "serial_number": "synthetic-private-serial", "wwn": {"naa": 1},
          "nvme_namespaces": [{"id": 1, "eui64": "synthetic-eui", "nguid": "synthetic-guid"}]}


def result(data=None, code=0, **extra):
    return {"ok": code == 0, "returncode": code, "truncated": False, "timed_out": False,
            "text": json.dumps(HEALTH if data is None else data), **extra}


class NvmeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sysfs = self.root / "sysfs"
        self.sysfs.mkdir()
        self.controller("nvme0")
        self.cache = self.root / "smart.json"
        boot = self.root / "boot-id"
        boot.write_text(BOOT)
        self.stack = []
        for name, value in (("SYSFS", self.sysfs), ("BOOT_ID", boot), ("CACHE", self.cache)):
            manager = patch.object(nvme, name, value)
            manager.start()
            self.stack.append(manager)
        manager = patch.object(nvme, "now", return_value=AT)
        manager.start()
        self.stack.append(manager)
        manager = patch.object(nvme, "stamp", side_effect=lambda: stamp(AT))
        manager.start()
        self.stack.append(manager)

    def tearDown(self):
        for manager in reversed(self.stack):
            manager.stop()
        self.tmp.cleanup()

    def controller(self, name):
        root = self.sysfs / name
        root.mkdir()
        for key, value in (("serial", "synthetic-private-serial"), ("model", "Synthetic NVMe"), ("firmware_rev", "TEST1")):
            (root / key).write_text(value)
        (root / (name + "n1")).mkdir()

    def captured(self, response=None):
        with patch.object(nvme, "command", return_value=response or result()):
            return nvme.capture()

    def saved(self, payload=None):
        payload = self.captured() if payload is None else payload
        atomic_json(self.cache, payload)
        return payload

    def read(self):
        # CI uses an unprivileged UID; only this file-owner assertion is
        # substituted. Production always requires a root-owned, nonwritable file.
        actual = nvme._read_file
        with patch.object(nvme, "_read_file", side_effect=lambda path: actual(path, owner_uid=os.getuid())):
            return nvme.read_cache()

    def test_fixed_read_argv_and_recursive_identifier_suppression(self):
        with patch.object(nvme, "command", return_value=result()) as run:
            payload = nvme.capture()
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/sbin/smartctl", "--json", "--all", "--quietmode=noserial", "--device=nvme", "/dev/nvme0"])
        self.assertEqual(run.call_args.kwargs, {"timeout": 10, "limit": nvme.MAX_OUTPUT})
        raw = json.dumps(payload)
        for secret in ("synthetic-private-serial", "synthetic-eui", "synthetic-guid"):
            self.assertNotIn(secret, raw)
        self.assertEqual(payload["devices"][0]["data"]["nvme_smart_health_information_log"]["data_units_written"], 2 ** 70)
        self.assertTrue(payload["ok"])

    def test_read_roundtrip_and_atomic_replacement(self):
        self.saved()
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.read()["devices"][0]["observed_at_utc"], stamp(AT))
        old_inode = self.cache.stat().st_ino
        self.saved()
        self.assertNotEqual(self.cache.stat().st_ino, old_inode)
        self.assertFalse(list(self.root.glob(".pending-*")))

    def test_wrong_owner_writable_symlink_fifo_and_oversized_cache_rejected(self):
        self.saved()
        with self.assertRaises(nvme.CacheError):
            nvme._read_file(self.cache, owner_uid=os.getuid() + 1)
        self.cache.chmod(0o660)
        with self.assertRaises(nvme.CacheError):
            self.read()
        self.cache.unlink()
        target = self.root / "target"
        target.write_text("{}")
        self.cache.symlink_to(target)
        with self.assertRaises(nvme.CacheError):
            self.read()
        self.cache.unlink()
        os.mkfifo(self.cache)
        with self.assertRaises(nvme.CacheError):
            self.read()
        self.cache.unlink()
        self.cache.write_bytes(b" " * (nvme.MAX_CACHE + 1))
        with self.assertRaises(nvme.CacheError):
            self.read()

    def test_stale_future_wrong_host_boot_and_hot_replaced_device_rejected(self):
        original = self.captured()
        cases = [
            {"observed_at_utc": stamp(AT - dt.timedelta(hours=8))},
            {"observed_at_utc": stamp(AT + dt.timedelta(minutes=1))},
            {"hostname": "another-synthetic-host"}, {"boot_id": "another-boot"},
            {"schema_version": True}, {"schema_version": 2},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.saved({**original, **changes})
                with self.assertRaises(nvme.CacheError):
                    self.read()
        self.saved(original)
        (self.sysfs / "nvme0" / "serial").write_text("replacement-private-serial")
        with self.assertRaisesRegex(nvme.CacheError, "device_identity_mismatch"):
            self.read()

    def test_duplicate_devices_corrupt_json_and_invalid_rows_rejected(self):
        original = self.captured()
        invalid = []
        duplicated = copy.deepcopy(original)
        duplicated["devices"] *= 2
        invalid.append(duplicated)
        for field, value in (("device", "/dev/../etc/passwd"), ("returncode", True),
                             ("data", "not a result"), ("observed_at_utc", "invalid"),
                             ("identity_sha256", None), ("namespaces", [])):
            payload = copy.deepcopy(original)
            payload["devices"][0][field] = value
            invalid.append(payload)
        for payload in invalid:
            with self.subTest(payload=payload):
                self.saved(payload)
                with self.assertRaises(nvme.CacheError):
                    self.read()
        for raw in ('{"schema_version":1,"schema_version":1}', '{"a":NaN}', '{"unfinished":'):
            self.cache.write_text(raw)
            with self.assertRaises(nvme.CacheError):
                self.read()

    def test_failed_read_replaces_prior_healthy_result_and_preserves_bitmask(self):
        self.saved()
        for response in (result(code=4), result(timed_out=True), result(truncated=True), result(data={}),
                         {"ok": False, "error": "command_unavailable"}):
            with self.subTest(response=response):
                with patch.object(nvme, "command", return_value=response), patch.object(nvme.sys, "argv", ["nvme"]):
                    self.assertEqual(nvme.main(), 1)
                row = self.read()["devices"][0]
                self.assertFalse(row["collection_complete"])
                self.assertFalse(row["ok"])
                self.assertTrue(row.get("error"))
                self.assertFalse(read_json(self.cache)["ok"])

    def test_no_nvme_is_supported_without_running_smartctl(self):
        with patch.object(nvme, "SYSFS", self.root / "absent-class"), patch.object(nvme, "command") as run:
            payload = nvme.capture()
        run.assert_not_called()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["devices"], [])

    def test_health_failure_is_preserved_as_complete_evidence(self):
        health = copy.deepcopy(HEALTH)
        health["smart_status"]["passed"] = False
        health["nvme_smart_health_information_log"]["critical_warning"] = 1
        self.saved(self.captured(result(health, code=8)))
        row = self.read()["devices"][0]
        self.assertTrue(row["collection_complete"])
        self.assertFalse(row["ok"])
        self.assertEqual(row["returncode"], 8)
        self.assertFalse(row["data"]["smart_status"]["passed"])

    def test_device_limit_and_identity_change_during_probe_are_visible(self):
        with patch.object(nvme, "MAX_DEVICES", 0):
            payload = self.captured()
            self.assertEqual(payload["issues"], ["nvme_device_limit"])
            self.assertFalse(payload["ok"])
        with patch.object(nvme, "controller_identity", side_effect=[("first", ["nvme0n1"]), ("second", ["nvme0n1"])]):
            row = self.captured()["devices"][0]
            self.assertNotIn("data", row)
            self.assertEqual(row["error"], "nvme_identity_changed_during_read")

    def test_entrypoint_accepts_no_configuration_arguments(self):
        with patch.object(nvme.sys, "argv", ["nvme", "--device=/dev/sda"]), patch.object(nvme, "command") as run:
            self.assertEqual(nvme.main(), 2)
            run.assert_not_called()

    def test_host_imports_nvme_without_direct_admin_command_and_rechecks_age(self):
        self.saved()
        actual = nvme._read_file
        with tempfile.TemporaryDirectory() as out, patch.object(nvme, "_read_file", side_effect=lambda path: actual(path, owner_uid=os.getuid())):
            helper = HostHelper({"smart_devices": ["/dev/nvme0n1"]}, out)
            with patch("homelab_health.host.command", return_value={"ok": True, "text": "{}"}) as run:
                helper.daily()
                helper.nvme_smart()
            self.assertFalse(any(call.args[0][0] == "smartctl" for call in run.call_args_list))
            rows = [json.loads(line) for path in Path(out).glob("*.jsonl") for line in path.read_text().splitlines()]
            smart = [row for row in rows if row["kind"] == "smart"]
            self.assertEqual(len(smart), 1)
            self.assertEqual(smart[0]["data"]["observed_at_utc"], stamp(AT))
            with patch.object(nvme, "now", return_value=AT + dt.timedelta(hours=8)):
                helper.nvme_smart()
            rows = [json.loads(line) for path in Path(out).glob("*.jsonl") for line in path.read_text().splitlines()]
            self.assertTrue(any(row["data"].get("error") == "nvme_cache_stale_or_future" for row in rows if row["kind"] == "smart"))

    def test_missing_cache_is_visible_and_never_falls_back_to_privileged_read(self):
        with tempfile.TemporaryDirectory() as out:
            helper = HostHelper({"smart_devices": ["/dev/nvme0n1"]}, out)
            with patch("homelab_health.host.command", return_value={"ok": True, "text": "{}"}) as run:
                helper.daily()
            self.assertFalse(any(call.args[0][0] == "smartctl" for call in run.call_args_list))
            rows = [json.loads(line) for path in Path(out).glob("*.jsonl") for line in path.read_text().splitlines()]
            self.assertTrue(any(row["data"].get("error") == "nvme_cache_missing" for row in rows if row["kind"] == "smart"))

    def test_report_uses_source_time_and_keeps_health_failure_without_false_gap(self):
        health = copy.deepcopy(HEALTH)
        health["smart_status"]["passed"] = False
        payload = self.captured(result(health, code=8))
        row = {"schema_version": 1, "kind": "smart", "at": stamp(AT + dt.timedelta(hours=1)),
               "data": {"source": "nvme_cache", **payload["devices"][0]}}
        marker = {"sha256": "a" * 64, "hostname": "synthetic", "requested_start_utc": stamp(AT),
                  "requested_end_utc": row["at"], "collection_finished_utc": row["at"]}
        imported_again = {**row, "at": stamp(AT + dt.timedelta(hours=2))}
        summary = analyze(marker, {"files": [], "issues": []},
                          {"host/evidence.jsonl": (json.dumps(row) + "\n" + json.dumps(imported_again)).encode()})
        finding = next(f for f in summary["findings"] if f["key"] == "smart:/dev/nvme0")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["first_utc"], stamp(AT))
        self.assertEqual(finding["observations"], 1)
        self.assertFalse(any(f["key"].startswith("coverage:") and "SMART" in f["message"] for f in summary["findings"]))


if __name__ == "__main__":
    unittest.main()
