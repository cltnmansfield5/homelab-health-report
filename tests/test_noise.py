import datetime as dt
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from homelab_health.common import Redactor, Spool, read_json
from homelab_health.docker import EventPump, selected_event
from homelab_health.host import HostHelper
from homelab_health.noise import compact_exec, compact_journal
from homelab_health.report import analyze
from tests.fixtures import AT, CONTAINER


def event(n, action, exit_code=None, container=CONTAINER):
    attrs = {"name": "fixture", "image": "fixture:1"}
    if exit_code is not None:
        attrs["exitCode"] = exit_code
    return {"Type": "container", "Action": action, "Actor": {"ID": container, "Attributes": attrs},
            "time": int(AT.timestamp()) + n // 10, "timeNano": int(AT.timestamp()) * 10**9 + n * 100000000}


def denial(n, pid=123, boot="boot-a", **extra):
    return {"__CURSOR": f"cursor-{boot}-{n}", "__REALTIME_TIMESTAMP": str(int(AT.timestamp()) * 10**6 + n),
            "_BOOT_ID": boot, "PRIORITY": "6", "SYSLOG_IDENTIFIER": "kernel",
            "MESSAGE": f'audit: type=1400 audit(1790500000.123:{n}): apparmor="DENIED" operation="ptrace" class="ptrace" profile="docker-default" pid={pid} comm="tokio-rt-worker" requested_mask="read" denied_mask="read" peer="unconfined"', **extra}


def records(root):
    return [json.loads(line) for p in Path(root).glob("????-??-??.jsonl") for line in p.read_text().splitlines()]


class ExecNoiseTests(unittest.TestCase):
    def pump(self, root, config=None):
        return EventPump(None, Spool(root), Path(root) / "cursor.json", threading.Event(), config)

    def test_batch_retains_exact_routine_events_and_individual_failures(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root)
            inputs = [event(n, ("exec_create: command-secret", "exec_start: command-secret", "exec_die")[n % 3], "0") for n in range(120)]
            for raw in inputs:
                pump.record_event(raw)
            important = [event(200, "exec_die", "1"), event(201, "exec_die"), event(202, "oom"),
                         event(203, "health_status: unhealthy"), event(204, "die", "137"), event(205, "start")]
            for raw in important:
                pump.record_event(raw)
            pump.flush_exec()
            rows = records(root)
            self.assertEqual([r["data"]["action"] for r in rows if r["kind"] == "docker_event"],
                             [r["Action"] for r in important])
            compacted = [r["data"] for r in rows if r["kind"] == "docker_exec_summary"]
            self.assertEqual(sum(g["count"] for g in compacted), 120)
            expected = {(r["Action"].split(":")[0], r["timeNano"]) for r in inputs}
            self.assertEqual({tuple(pair) for g in compacted for pair in g["events"]}, expected)
            self.assertNotIn("command-secret", json.dumps(rows) + (Path(root) / "cursor.json").read_text())
            self.assertLess(len(json.dumps(compacted)), len(json.dumps([selected_event(r) for r in inputs])) // 2)

    def test_pending_survives_restart_and_reconnect_replay(self):
        with tempfile.TemporaryDirectory() as root:
            original = self.pump(root)
            inputs = [event(n, "exec_start: private") for n in range(5)]
            for raw in inputs:
                original.record_event(raw)
            restored = self.pump(root)
            restored.restore()
            for raw in inputs:
                restored.record_event(raw)
            self.assertEqual(len(restored.pending_exec), 5)
            restored.flush_exec()
            self.assertEqual(records(root)[0]["data"]["count"], 5)
            self.assertEqual(read_json(Path(root) / "cursor.json")["pending_exec"], [])

    def test_crash_after_append_replays_same_identity_not_extra_observations(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root)
            for n in range(3):
                pump.record_event(event(n, "exec_die", "0"))
            with patch.object(pump, "checkpoint", side_effect=OSError("simulated crash")):
                with self.assertRaises(OSError):
                    pump.flush_exec()
            recovered = self.pump(root)
            recovered.restore()
            recovered.flush_exec()
            evidence = records(root)
            summary = analyze({"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": AT.isoformat(),
                               "requested_end_utc": AT.isoformat(), "collection_finished_utc": AT.isoformat()},
                              {"files": [], "issues": []}, {"docker/evidence-000.jsonl": b"\n".join(json.dumps(r).encode() for r in evidence)})
            self.assertEqual(len(evidence), 2)
            self.assertEqual(summary["noise_reduction"]["unique_compacted_exec_events"], 3)

    def test_bound_and_failed_flush_preserve_pending_state(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root)
            with patch.object(pump.spool, "append", return_value=False):
                for n in range(270):
                    pump.record_event(event(n, "exec_start"))
            self.assertEqual(len(pump.pending_exec), 256)
            self.assertEqual(len(read_json(Path(root) / "cursor.json")["pending_exec"]), 256)
            self.assertTrue(pump.flush_exec())
            self.assertEqual(records(root)[0]["data"]["count"], 256)

    def test_config_off_and_container_exclusion(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root, {"compact_exec_events": False})
            pump.record_event(event(0, "exec_start"))
            self.assertEqual(records(root)[0]["kind"], "docker_event")
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root, {"exclude_containers": ["fixture"]})
            pump.record_event(event(0, "exec_start"))
            self.assertFalse(pump.pending_exec)
            self.assertFalse(records(root))

    def test_checkpoint_uses_configured_redaction(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root)
            pump.spool.redactor = Redactor(["private-name"])
            raw = event(0, "exec_create: secret-command")
            raw["Actor"]["Attributes"]["name"] = "private-name"
            pump.record_event(raw)
            saved = (Path(root) / "cursor.json").read_text()
            self.assertNotIn("private-name", saved)
            self.assertNotIn("secret-command", saved)

    def test_oversized_selected_metadata_falls_back_without_growing_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            pump = self.pump(root)
            raw = event(0, "exec_start: secret-command")
            raw["Actor"]["Attributes"]["image"] = "a" * 5000
            pump.record_event(raw)
            self.assertEqual(pump.pending_exec, [])
            self.assertEqual(records(root)[0]["kind"], "docker_event")
            self.assertLess((Path(root) / "cursor.json").stat().st_size, 1024)


class JournalNoiseTests(unittest.TestCase):
    def test_known_repetition_compacted_but_failures_new_denials_and_pids_distinct(self):
        inputs = [denial(n) for n in range(100)]
        inputs += [denial(101, pid=456), denial(102, pid=456)]
        critical = denial(103, PRIORITY="2")
        unknown = denial(104, MESSAGE='apparmor="DENIED" operation="open" profile="docker-default"')
        disk = denial(105, MESSAGE="EXT4-fs error: example")
        rows, groups, duplicates = compact_journal(inputs + [inputs[0], critical, unknown, disk])
        self.assertEqual(duplicates, 1)
        self.assertEqual(rows, [critical, unknown, disk])
        self.assertEqual([g["count"] for g in groups], [100, 2])
        self.assertLess(len(json.dumps(groups)), len(json.dumps(inputs)) // 2)
        self.assertEqual(groups[0]["first_realtime_timestamp"], inputs[0]["__REALTIME_TIMESTAMP"])

    def test_overlapping_summary_counts_are_a_union_and_original_timeline_survives(self):
        evidence = []
        for start, stop in [(0, 100), (50, 150)]:
            rows, summaries, _ = compact_journal([denial(n) for n in range(start, stop)])
            evidence.append({"kind": "kernel_journal", "at": AT.isoformat(), "data": {"ok": True, "rows": rows, "summaries": summaries}})
        marker = {"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": AT.isoformat(),
                  "requested_end_utc": AT.isoformat(), "collection_finished_utc": AT.isoformat()}
        result = analyze(marker, {"files": [], "issues": []}, {"host/evidence-000.jsonl": b"\n".join(json.dumps(r).encode() for r in evidence)})
        self.assertEqual(result["noise_reduction"]["unique_compacted_apparmor_denials"], 150)
        findings = [f for f in result["findings"] if f["key"].startswith("apparmor_summary:")]
        self.assertEqual(findings[0]["observations"], 150)
        self.assertEqual(findings[0]["severity"], "warning")

    def test_helper_integration_retains_caps_and_can_disable_compaction(self):
        for enabled in (True, False):
            with tempfile.TemporaryDirectory() as root:
                helper = HostHelper({"compact_journal_denials": enabled, "journal_lines": 100,
                                     "journal_units": [], "filesystem_paths": []}, root)
                journal = "\n".join(json.dumps(denial(n)) for n in range(101))
                def command(argv, **kwargs):
                    return {"ok": True, "text": journal if argv[0] == "journalctl" and "--output=json" in argv else ""}
                with patch("homelab_health.host.command", side_effect=command):
                    helper.snapshot(AT - dt.timedelta(minutes=5), AT)
                result = next(r["data"] for r in records(root) if r["kind"] == "kernel_journal")
                self.assertTrue(result["line_limit_reached"])
                if enabled:
                    self.assertEqual(result["summaries"][0]["count"], 100)
                else:
                    self.assertEqual(len(result["rows"]), 100)
                    self.assertNotIn("summaries", result)
