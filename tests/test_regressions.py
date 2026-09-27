import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from homelab_health.common import now, parse_time
from homelab_health.docker import Docker, EventPump, selected_event
from homelab_health.proxy import Handler
from homelab_health.report import analyze
from tests.fixtures import CONTAINER, receipt, sample
from tests.test_pipeline import PipelineTests


class GatewayUnitTests(unittest.TestCase):
    def test_exec_action_arguments_are_removed_before_any_spooling(self):
        for field in ("Action", "status"):
            for action in ("exec_create", "exec_start"):
                with self.subTest(field=field, action=action):
                    raw = {field: action + ": /bin/task positional-private-value",
                           "Actor": {"ID": CONTAINER, "Attributes": {"name": "synthetic"}},
                           "time": 1, "timeNano": 1000000000}
                    event = selected_event(raw)
                    self.assertEqual(event["action"], action)
                    self.assertNotIn("positional-private-value", json.dumps(event))
                    self.assertEqual(event["timeNano"], raw["timeNano"])
        event = selected_event({"Action": "health_status: unhealthy"})
        self.assertEqual(event["action"], "health_status: unhealthy")

    def test_event_capture_respects_include_and_exclude_configuration(self):
        pump = EventPump(None, None, None, None, {"include_containers": ["plex*"], "exclude_containers": ["plex-private"]})
        self.assertTrue(pump.include({"Actor": {"Attributes": {"name": "plex-main"}}}))
        self.assertFalse(pump.include({"Actor": {"Attributes": {"name": "plex-private"}}}))
        self.assertFalse(pump.include({"Actor": {"Attributes": {"name": "different"}}}))
        self.assertFalse(pump.include({"Actor": {"Attributes": {"name": "plex-main", "homelab-health.exclude": "true"}}}))

    def test_gateway_forwards_only_approved_request_and_no_client_headers(self):
        handler = object.__new__(Handler)
        handler.path = "/version"
        handler.headers = {"Authorization": "client-secret"}
        handler.server = MagicMock(socket_path="/synthetic/docker.sock")
        handler.wfile = io.BytesIO()
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.send_error = MagicMock()
        with patch("homelab_health.proxy.UnixConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "application/json"
            response.read.side_effect = [b'{"ApiVersion":"1.55"}', b""]
            handler.do_GET()
            connection.return_value.request.assert_called_once_with("GET", "/version", headers={"Connection": "close"})
            self.assertIn(b"1.55", handler.wfile.getvalue())
        handler.path = "/containers/create"
        with patch("homelab_health.proxy.UnixConnection") as connection:
            handler.do_GET()
            connection.assert_not_called()
            handler.send_error.assert_called_with(403)

    def test_selected_metadata_never_includes_environment_or_exec_arguments(self):
        docker = Docker()
        source = {"Id": CONTAINER, "Config": {"Env": ["PRIVATE=env-secret"], "Cmd": ["command-secret"], "Labels": {"private": "label-secret"}}, "HostConfig": {}, "State": {}}
        with patch.object(docker, "json", return_value=source):
            output = json.dumps(docker.inspect(CONTAINER))
        for secret in ("env-secret", "command-secret", "label-secret"):
            self.assertNotIn(secret, output)
        source["Config"]["Labels"] = None
        source["State"]["Health"] = None
        with patch.object(docker, "json", return_value=source):
            self.assertIsNone(docker.inspect(CONTAINER)["compose_project"])
        event = selected_event({"Actor": {"ID": CONTAINER, "Attributes": {"name": "plex", "private": "event-secret", "execCommand": "exec-secret"}}})
        self.assertNotIn("event-secret", json.dumps(event))
        self.assertNotIn("exec-secret", json.dumps(event))

    def test_body_on_get_is_rejected_before_socket_access(self):
        handler = object.__new__(Handler)
        handler.path = "/version"
        handler.headers = {"Content-Length": "4"}
        handler.send_error = MagicMock()
        with patch("homelab_health.proxy.UnixConnection") as connection:
            handler.do_GET()
            connection.assert_not_called()
        handler.send_error.assert_called_with(403)


class ReportRegressionTests(unittest.TestCase):
    def test_filesystem_finding_keeps_worst_severity_in_any_order(self):
        start = dt.datetime(2026, 9, 27, 12, tzinfo=dt.timezone.utc)
        marker = {"sha256": "a" * 64, "hostname": "synthetic",
                  "requested_start_utc": start.isoformat(),
                  "requested_end_utc": (start + dt.timedelta(minutes=2)).isoformat(),
                  "collection_finished_utc": (start + dt.timedelta(minutes=2)).isoformat()}
        rows = [{"kind": "filesystems", "at": (start + dt.timedelta(minutes=i)).isoformat(),
                 "data": [{"path": "/synthetic", "total_bytes": 100, "available_bytes": free}]}
                for i, free in enumerate((10, 2, 12))]
        for records in (rows, list(reversed(rows))):
            with self.subTest(order=[r["at"] for r in records]):
                contents = {"host/evidence-000.jsonl": "\n".join(map(json.dumps, records)).encode()}
                result = analyze(marker, {"files": [], "issues": []}, contents)
                finding = next(f for f in result["findings"] if f["key"] == "filesystem:/synthetic:space")
                self.assertEqual(finding["severity"], "critical")
                self.assertIn("98.0%", finding["message"])
                self.assertEqual(finding["source"], "host/evidence-000.jsonl:2")
                self.assertEqual(finding["observations"], 3)
                self.assertEqual(finding["first_utc"], rows[0]["at"])
                self.assertEqual(finding["last_utc"], rows[2]["at"])

    def test_overlap_events_and_journal_rows_are_deduplicated(self):
        at = now()
        event = {"kind": "docker_event", "at": at.isoformat(), "data": {"id": CONTAINER, "time": int(at.timestamp()), "timeNano": int(at.timestamp()) * 10**9, "action": "oom"}}
        journal = {"kind": "journal_warnings", "at": at.isoformat(), "data": {"ok": True, "rows": [{"_BOOT_ID": "boot", "__REALTIME_TIMESTAMP": str(int(at.timestamp()) * 10**6), "MESSAGE": "oom-kill: test"}]}}
        contents = {"docker/evidence-000.jsonl": (json.dumps(event) + "\n" + json.dumps(event)).encode(), "host/evidence-000.jsonl": (json.dumps(journal) + "\n" + json.dumps(journal)).encode()}
        summary = analyze({"sha256": "a" * 64, "hostname": "synthetic", "requested_start_utc": at.isoformat(), "requested_end_utc": at.isoformat(), "collection_finished_utc": at.isoformat()}, {"files": [], "issues": []}, contents)
        for finding in summary["findings"]:
            if finding["key"].startswith(("event:", "kernel:")):
                self.assertEqual(finding["observations"], 1)


# Reuse fixture setup without discovering the base test class twice.
class RetentionRegressionTests(unittest.TestCase):
    setUp = PipelineTests.setUp
    tearDown = PipelineTests.tearDown

    def test_remote_same_id_changed_contents_preserves_local_copy(self):
        uploaded = self.uploader.upload_one(self.ready)
        finished = parse_time(self.marker["collection_finished_utc"])
        receipt(self.drive, uploaded, finished + dt.timedelta(seconds=1))
        self.drive.files["inbox"][self.archive.name]["Hashes"]["MD5"] = "changed"
        result = self.uploader.retention(finished + dt.timedelta(days=8))
        self.assertTrue(result["issues"])
        self.assertTrue(self.archive.exists())

    def test_local_tampering_prevents_deletion(self):
        uploaded = self.uploader.upload_one(self.ready)
        finished = parse_time(self.marker["collection_finished_utc"])
        receipt(self.drive, uploaded, finished + dt.timedelta(seconds=1))
        self.archive.write_bytes(b"changed")
        self.assertTrue(self.uploader.retention(finished + dt.timedelta(days=8))["issues"])
        self.assertTrue(self.archive.exists())


del PipelineTests

