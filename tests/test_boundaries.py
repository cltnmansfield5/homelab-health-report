import datetime as dt
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
import urllib.parse

from homelab_health.bundle import BundleWriter, read_verified_bundle, spool_window
from homelab_health.common import MIB, Redactor, Spool, atomic_json, command, digest_file, now, read_json, stamp
from homelab_health.docker import demux
from homelab_health.proxy import permitted
from homelab_health.report import counter_rate, host_trends
from tests.fixtures import AT, CONTAINER, sample


class RedactionTests(unittest.TestCase):
    def test_common_secret_forms(self):
        redactor = Redactor(["my-private-host"])
        data = {"api_key": "one", "nested": [{"password": "two"}], "message": 'GET https://user:pass@example.com/?X-Plex-Token=three Authorization: Bearer four my-private-host'}
        raw = json.dumps(redactor.clean(data))
        for secret in ("one", "two", "three", "four", "user:pass", "my-private-host"):
            self.assertNotIn(secret, raw)

    def test_private_key_and_quoted_value(self):
        raw = Redactor().text('password="a secret with spaces"\n-----BEGIN RSA PRIVATE KEY-----\nprivatebytes\n-----END RSA PRIVATE KEY-----')
        self.assertNotIn("a secret", raw)
        self.assertNotIn("privatebytes", raw)

    def test_structured_bundle_remains_json_after_redaction(self):
        with tempfile.TemporaryDirectory() as root:
            writer = BundleWriter(root, "synthetic", AT - dt.timedelta(hours=1), AT)
            writer.add("metadata.json", {"password": "private", "message": "token=private"})
            marker = writer.finish()
            _, _, files = read_verified_bundle(Path(root) / marker["archive_name"], Path(root) / (marker["bundle_id"] + ".ready.json"))
            parsed = json.loads(files["metadata.json"])
            self.assertEqual(parsed["password"], "[REDACTED]")

    def test_custom_hostname_redaction_preserves_manifest_integrity(self):
        with tempfile.TemporaryDirectory() as root:
            writer = BundleWriter(root, "private-host", AT - dt.timedelta(hours=1), AT, redactor=Redactor(["private-host"]))
            writer.add("README.txt", "private-host")
            marker = writer.finish()
            _, _, files = read_verified_bundle(Path(root) / marker["archive_name"], Path(root) / (marker["bundle_id"] + ".ready.json"))
            self.assertNotIn("private-host", marker["archive_name"])
            self.assertNotIn(b"private-host", b"\n".join(files.values()))


class ProxyPolicyTests(unittest.TestCase):
    def test_required_read_paths(self):
        self.assertTrue(permitted("GET", "/version"))
        self.assertTrue(permitted("GET", "/v1.55/containers/json?all=1"))
        self.assertTrue(permitted("GET", "/v1.55/containers/" + CONTAINER + "/json"))
        self.assertTrue(permitted("GET", "/containers/" + CONTAINER + "/stats?stream=false&one-shot=true"))
        query = urllib.parse.urlencode({"stdout": "1", "stderr": "1", "timestamps": "1", "follow": "0", "since": 100, "until": 200, "tail": 20000})
        self.assertTrue(permitted("GET", "/containers/" + CONTAINER + "/logs?" + query))
        self.assertTrue(permitted("GET", "/events?" + urllib.parse.urlencode({"since": 100, "filters": json.dumps({"type": ["container"]})})))

    def test_deny_mutations_exec_archive_and_bypass_paths(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "CONNECT"):
            self.assertFalse(permitted(method, "/containers/" + CONTAINER + "/json"))
        for target in ("/containers/create", "/containers/" + CONTAINER + "/archive?path=/etc/shadow", "/info", "/images/json", "/volumes", "/v1.55/../info", "/%76ersion", "http://elsewhere/version", "//elsewhere/version", "/version?x=1", "/version?x=", "/containers/json?all=1&all=", "/containers/json?all=1&all=0", "/containers/json?all=1&filters=anything", "/events?since=1", "/containers/" + CONTAINER + "/stats?stream=true"):
            with self.subTest(target=target):
                self.assertFalse(permitted("GET", target))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        writer = BundleWriter(self.root, "synthetic", AT - dt.timedelta(hours=1), AT)
        writer.add("README.txt", "Synthetic data")
        self.marker = writer.finish()
        self.archive = self.root / self.marker["archive_name"]
        self.ready = self.root / (self.marker["bundle_id"] + ".ready.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_and_corruption(self):
        read_verified_bundle(self.archive, self.ready)
        with self.archive.open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaises(ValueError):
            read_verified_bundle(self.archive, self.ready)

    def malicious(self, name, member_type=tarfile.REGTYPE, size=1):
        with tarfile.open(self.archive, "w:gz") as tar:
            info = tarfile.TarInfo(name)
            info.type = member_type
            info.size = size if member_type == tarfile.REGTYPE else 0
            info.linkname = "/etc/passwd" if member_type == tarfile.SYMTYPE else ""
            tar.addfile(info, io.BytesIO(b"x" * info.size))
        self.marker.update(sha256=digest_file(self.archive), archive_bytes=self.archive.stat().st_size)
        atomic_json(self.ready, self.marker)

    def test_traversal_and_links(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE), ("a/../../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), ("device", tarfile.CHRTYPE), ("a\\b", tarfile.REGTYPE)):
            self.malicious(name, kind)
            with self.subTest(name=name), self.assertRaises(ValueError):
                read_verified_bundle(self.archive, self.ready)

    def test_expansion_limit(self):
        self.malicious("too-large", size=17 * MIB)
        with self.assertRaises(ValueError):
            read_verified_bundle(self.archive, self.ready)

    def test_member_checksum_is_checked(self):
        with tarfile.open(self.archive, "r:gz") as tar:
            files = {m.name: tar.extractfile(m).read() for m in tar}
        files["README.txt"] = b"different data"
        with tarfile.open(self.archive, "w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.marker.update(sha256=digest_file(self.archive), archive_bytes=self.archive.stat().st_size)
        atomic_json(self.ready, self.marker)
        with self.assertRaises(ValueError):
            read_verified_bundle(self.archive, self.ready)


class BoundTests(unittest.TestCase):
    def test_concurrent_spool_writers_do_not_drop_events(self):
        with tempfile.TemporaryDirectory() as root:
            spool = Spool(root)
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda i: spool.append("event", {"number": i}, AT), range(100)))
            self.assertTrue(all(results))
            records = [json.loads(line) for line in (Path(root) / (AT.date().isoformat() + ".jsonl")).read_text().splitlines()]
            self.assertEqual({r["data"]["number"] for r in records}, set(range(100)))

    def test_first_record_cannot_exceed_spool_budget(self):
        with tempfile.TemporaryDirectory() as root:
            spool = Spool(root, daily_bytes=500)
            self.assertFalse(spool.append("sample", {"a": "x" * 800}, AT))
            self.assertFalse(list(Path(root).glob("*.jsonl")))

    def test_subprocess_output_and_timeout(self):
        result = command([sys.executable, "-c", "print('x' * 50000)"], limit=1024)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["text"]), 1024)
        result = command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["ok"])

    def test_spool_limit_and_partial_records_visible(self):
        with tempfile.TemporaryDirectory() as root:
            spool = Spool(root, daily_bytes=500)
            self.assertTrue(spool.append("sample", {"a": 1}, AT))
            self.assertFalse(spool.append("sample", {"a": "x" * 800}, AT))
            self.assertTrue((Path(root) / "gap.json").exists())
            with (Path(root) / (AT.date().isoformat() + ".jsonl")).open("ab") as stream:
                stream.write(b'{"unfinished":')
            _, coverage = spool_window(root, AT - dt.timedelta(minutes=1), AT + dt.timedelta(minutes=1))
            self.assertEqual(coverage["records"], 1)
            self.assertTrue(any(x["error"] == "partial_spool_record" for x in coverage["issues"]))

    def test_docker_log_demultiplexing_and_tty(self):
        raw = struct.pack(">BBBBI", 1, 0, 0, 0, 4) + b"out\n" + struct.pack(">BBBBI", 2, 0, 0, 0, 4) + b"err\n"
        self.assertEqual(demux(raw), ("out\nerr\n", False))
        self.assertTrue(demux(raw[:-1])[1])
        self.assertEqual(demux(b"tty\n", True), ("tty\n", False))

    def test_counter_resets_and_reboots_do_not_make_fake_spikes(self):
        first = sample(AT)
        second = sample(AT + dt.timedelta(seconds=60), 60)
        values = host_trends([first, second])
        self.assertAlmostEqual(values["peak_cpu_busy_percent"], 100 * 2 / 3)
        self.assertEqual(values["peak_network_bytes_per_second"]["eth0/rx_bytes"], 100)
        self.assertEqual(values["peak_disk_bytes_per_second"]["sda/read_sectors_512b"], 512)
        second["data"]["boot_id"] = "new-boot"
        self.assertEqual(host_trends([first, second])["skipped_rate_intervals"], 1)
        self.assertIsNone(counter_rate(100, 50, 60))
        self.assertIsNone(counter_rate(100, 200, 0))
