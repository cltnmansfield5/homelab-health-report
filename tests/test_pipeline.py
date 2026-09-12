import datetime as dt
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import socketserver
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request

from homelab_health.bundle import read_verified_bundle
from homelab_health.collector import Collector
from homelab_health.common import Spool, atomic_json, now, parse_time, read_json, stamp
from homelab_health.docker import Docker
from homelab_health.proxy import Server
from homelab_health.report import report
from homelab_health.uploader import Rclone, Uploader, valid_receipt
from tests.fixtures import CONTAINER, FakeDocker, MemoryDrive, receipt, sample


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.host = self.root / "host"
        at = now()
        spool = Spool(self.host)
        for offset in (120, 60):
            data = sample(at - dt.timedelta(seconds=offset), 120 - offset)["data"]
            spool.append("host_sample", data, at - dt.timedelta(seconds=offset))
        atomic_json(self.host / "status.json", {"at": stamp(at), "ok": True, "hostname": "synthetic-host"})
        self.collector = Collector({"data_dir": str(self.root / "collector"), "host_dir": str(self.host), "timezone": "America/Denver"}, FakeDocker())
        self.collector.sample()
        self.marker = self.collector.bundle()
        self.archive = self.collector.outbox / self.marker["archive_name"]
        self.ready = self.collector.outbox / (self.marker["bundle_id"] + ".ready.json")
        self.drive = MemoryDrive()
        self.uploader = Uploader({"outbox_dir": str(self.collector.outbox), "state_dir": str(self.root / "upload")}, self.drive)

    def tearDown(self):
        self.tmp.cleanup()

    def test_collect_verify_report_and_redaction(self):
        _, manifest, contents = read_verified_bundle(self.archive, self.ready)
        all_bytes = b"\n".join(contents.values())
        self.assertNotIn(b"secret-fixture-value", all_bytes)
        self.assertIn(b"[REDACTED]", all_bytes)
        for name, data in contents.items():
            if name.endswith(".json"):
                json.loads(data)
            elif name.endswith(".jsonl"):
                for line in data.splitlines():
                    json.loads(line)
        summary = report(self.archive, self.ready, self.root / "report.md")
        self.assertEqual(summary["host_trends"]["samples"], 2)
        self.assertTrue(any(f["key"].startswith("log_review:") for f in summary["findings"]))
        self.assertTrue((self.root / "report.json").is_file())
        self.assertIn("keyword counts are not incident counts", (self.root / "report.md").read_text())

    def test_failed_archive_upload_never_publishes_ready(self):
        self.drive.fail_archives = True
        result = self.uploader.once()
        self.assertTrue(result["failures"])
        self.assertFalse(any(name.endswith(".ready.json") for _, _, name in self.drive.calls))
        self.assertTrue(self.archive.exists())
        retries = list(self.uploader.state.glob("retry-*.json"))
        self.assertEqual(len(retries), 1)
        self.assertGreater(read_json(retries[0])["next_attempt_epoch"], now().timestamp())

    def test_upload_archive_before_marker_and_idempotency(self):
        self.uploader.once()
        puts = [x[2] for x in self.drive.calls if x[0] == "put"]
        self.assertEqual(puts, [self.archive.name, self.ready.name])
        self.drive.calls.clear()
        self.uploader.once()
        self.assertFalse(self.drive.calls)

    def test_retention_never_deletes_unprocessed_bundles(self):
        self.uploader.upload_one(self.ready)
        future = parse_time(self.marker["collection_finished_utc"]) + dt.timedelta(days=60)
        self.uploader.retention(future)
        self.assertTrue(self.archive.exists())
        self.assertIn(self.archive.name, self.drive.files["inbox"])
        self.assertFalse(any(x[0] == "delete" for x in self.drive.calls))

    def test_retention_requires_real_report_and_uses_7_30_day_boundaries(self):
        uploaded = self.uploader.upload_one(self.ready)
        finished = parse_time(self.marker["collection_finished_utc"])
        receipt(self.drive, uploaded, finished + dt.timedelta(seconds=1))
        self.uploader.retention(finished + dt.timedelta(days=6))
        self.assertTrue(self.archive.exists())
        self.uploader.retention(finished + dt.timedelta(days=7))
        self.assertFalse(self.archive.exists())
        self.assertIn(self.archive.name, self.drive.files["inbox"])
        self.uploader.retention(finished + dt.timedelta(days=29))
        self.assertIn(self.archive.name, self.drive.files["inbox"])
        self.uploader.retention(finished + dt.timedelta(days=30))
        self.assertNotIn(self.archive.name, self.drive.files["inbox"])
        self.assertNotIn(self.ready.name, self.drive.files["inbox"])
        self.assertEqual(len(self.drive.files["reports"]), 2)

    def test_wrong_hash_or_missing_report_cannot_authorize_cleanup(self):
        uploaded = self.uploader.upload_one(self.ready)
        finished = parse_time(self.marker["collection_finished_utc"])
        data = receipt(self.drive, uploaded, finished + dt.timedelta(seconds=1))
        data["sha256"] = "b" * 64
        self.drive.seed("reports", "processed-" + self.marker["sha256"] + ".json", data)
        self.assertTrue(self.uploader.retention(finished + dt.timedelta(days=31))["issues"])
        self.assertTrue(self.archive.exists())
        receipt(self.drive, uploaded, finished + dt.timedelta(seconds=1))
        for name in list(self.drive.files["reports"]):
            if name.endswith(".md"):
                del self.drive.files["reports"][name]
        self.uploader.retention(finished + dt.timedelta(days=31))
        self.assertTrue(self.archive.exists())

    def test_backpressure_preserves_existing_bundle(self):
        self.collector.queue_bytes = self.archive.stat().st_size + 1
        with self.assertRaisesRegex(RuntimeError, "outbox_full"):
            self.collector.bundle()
        self.assertTrue(self.archive.exists())

    def test_missing_host_is_explicit(self):
        self.collector.host_dir = self.root / "missing"
        marker = self.collector.bundle()
        _, manifest, _ = read_verified_bundle(self.collector.outbox / marker["archive_name"], self.collector.outbox / (marker["bundle_id"] + ".ready.json"))
        self.assertTrue(any(i["error"] == "helper_missing_stale_or_unhealthy" for i in manifest["issues"]))

    def test_malformed_helper_status_does_not_block_docker_bundle(self):
        atomic_json(self.host / "status.json", {"ok": True})
        marker = self.collector.bundle()
        _, manifest, contents = read_verified_bundle(self.collector.outbox / marker["archive_name"], self.collector.outbox / (marker["bundle_id"] + ".ready.json"))
        self.assertTrue(any(i["error"] == "helper_missing_stale_or_unhealthy" for i in manifest["issues"]))
        self.assertTrue(any(name.startswith("logs/") for name in contents))

    def test_bundle_scheduler_denver_boundary_and_dst(self):
        from homelab_health.common import UTC
        self.assertEqual(self.collector.due_date(dt.datetime(2026, 9, 11, 11, 59, tzinfo=UTC)), "2026-09-10")
        self.assertEqual(self.collector.due_date(dt.datetime(2026, 9, 11, 12, 0, tzinfo=UTC)), "2026-09-11")
        self.assertEqual(self.collector.due_date(dt.datetime(2026, 12, 11, 12, 59, tzinfo=UTC)), "2026-12-10")
        self.assertEqual(self.collector.due_date(dt.datetime(2026, 12, 11, 13, 0, tzinfo=UTC)), "2026-12-11")


class RcloneTests(unittest.TestCase):
    def test_email_remote_is_passed_as_one_remote_path_argument(self):
        remote = Rclone({"remote": "user@example.com", "inbox_folder_id": "inbox1234", "reports_folder_id": "reports1234"})
        with patch("homelab_health.uploader.command", return_value={"ok": True, "text": "[]"}) as command:
            self.assertEqual(remote.list("inbox"), {})
        argv = command.call_args.args[0]
        self.assertEqual(argv[:3], ["rclone", "lsjson", "user@example.com:"])
        self.assertEqual(argv[argv.index("--drive-root-folder-id") + 1], "inbox1234")

    def test_remote_cannot_inject_options_paths_or_connection_strings(self):
        for name in ("", "--config", ":drive", "remote:", "remote/path", "remote\\path", "remote,scope=drive", "remote\nother", "a" * 129, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                Rclone({"remote": name, "inbox_folder_id": "inbox1234", "reports_folder_id": "reports1234"})

    def client(self):
        return Rclone({"inbox_folder_id": "inbox1234", "reports_folder_id": "reports1234"})

    def test_lowercase_md5_verifies_new_upload_and_existing_archive(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file.tar.gz"
            path.write_bytes(b"archive")
            digest = hashlib.md5(b"archive", usedforsecurity=False).hexdigest()
            listing = json.dumps([{"Name": path.name, "ID": "drive-id", "Size": 7, "Hashes": {"md5": digest}}])
            for existing in (False, True):
                with self.subTest(existing=existing):
                    client = self.client()
                    responses = [listing, listing] if existing else ["[]", "", listing]
                    with patch.object(client, "call", side_effect=responses) as call:
                        result = client.put(path, path.name, "inbox")
                    self.assertEqual(result["Hashes"]["MD5"], digest)
                    self.assertEqual(result["ID"], "drive-id")
                    copies = [c for c in call.call_args_list if c.args[0][0] == "copyto"]
                    self.assertEqual(len(copies), 0 if existing else 1)

    @unittest.skipUnless(shutil.which("rclone"), "Requires the rclone executable; also runs inside the uploader image")
    def test_packaged_rclone_hash_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            source.mkdir()
            (source / "fixture.txt").write_bytes(b"archive")
            config = root / "rclone.conf"
            config.write_text("[fixture]\ntype = alias\nremote = " + str(source) + "\n")
            client = Rclone({"remote": "fixture", "rclone_config": str(config),
                             "inbox_folder_id": "inbox1234", "reports_folder_id": "reports1234"})
            item = client.list("inbox")["fixture.txt"]
            self.assertEqual(item["Size"], 7)
            self.assertEqual(item["Hashes"]["MD5"], hashlib.md5(b"archive", usedforsecurity=False).hexdigest())

    def test_duplicate_names_fail_closed(self):
        with patch.object(Rclone, "call", return_value=json.dumps([{"Name": "same"}, {"Name": "same"}])):
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                self.client().list("inbox")

    def test_remote_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file.tar.gz"
            path.write_bytes(b"archive")
            client = self.client()
            meta = {path.name: {"Name": path.name, "ID": "id", "Size": 7, "Hashes": {"MD5": "bad"}}}
            with patch.object(client, "list", return_value=meta), patch.object(client, "call") as call:
                with self.assertRaisesRegex(ValueError, "different contents"):
                    client.put(path, path.name, "inbox")
                call.assert_not_called()

    def test_exact_delete_rechecks_identity(self):
        client = self.client()
        with patch.object(client, "list", return_value={"name.tar.gz": {"ID": "different"}}), patch.object(client, "call") as call:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                client.delete("name.tar.gz", "inbox", "expected")
            call.assert_not_called()


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class EngineHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls.append(self.path)
        path = urllib.parse.urlsplit(self.path).path
        if path == "/version":
            raw = json.dumps({"ApiVersion": "1.55", "MinAPIVersion": "1.44"}).encode()
        elif path.endswith("/containers/json"):
            raw = json.dumps([{"Id": CONTAINER, "Names": ["/fixture"]}]).encode()
        elif path.endswith("/json"):
            raw = json.dumps({"Id": CONTAINER, "Config": {"Image": "fixture", "Env": ["PRIVATE=env-secret"], "Cmd": ["command-secret"], "Labels": {"secret": "label-secret"}}, "State": {"Running": True}, "HostConfig": {}}).encode()
        elif path.endswith("/logs"):
            log = b"2026-09-10T06:00:00Z fixture\n"
            raw = struct.pack(">BBBBI", 1, 0, 0, 0, len(log)) + log
        else:
            raw = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ActualGatewayTests(unittest.TestCase):
    def test_tcp_to_unix_gateway_negotiation_and_denied_request(self):
        with tempfile.TemporaryDirectory() as root:
            socket_path = str(Path(root) / "docker.sock")
            try:
                engine = UnixHTTPServer(socket_path, EngineHandler)
            except PermissionError:
                self.skipTest("Runtime blocks local sockets; live gateway test must run on Ubuntu/CI")
            engine.calls = []
            proxy = Server(("127.0.0.1", 0), socket_path)
            threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (engine, proxy)]
            for thread in threads:
                thread.start()
            try:
                base = "http://127.0.0.1:" + str(proxy.server_address[1])
                docker = Docker(base)
                self.assertEqual(docker.containers()[0]["Id"], CONTAINER)
                self.assertEqual(docker.version, "1.55")
                snapshot = json.dumps(docker.inspect(CONTAINER))
                for secret in ("env-secret", "command-secret", "label-secret"):
                    self.assertNotIn(secret, snapshot)
                before = len(engine.calls)
                request = urllib.request.Request(base + "/containers/" + CONTAINER + "/stop", method="POST")
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
                self.assertEqual(error.exception.code, 403)
                self.assertEqual(len(engine.calls), before)
            finally:
                proxy.shutdown()
                engine.shutdown()
                proxy.server_close()
                engine.server_close()
                for thread in threads:
                    thread.join(timeout=2)
