import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_health.bundle import BundleWriter, read_verified_bundle
from homelab_health.common import now, parse_time
from homelab_health.transport import INDEX_HEADING, PART_BYTES, index_name, load_index, restore
from homelab_health.uploader import Uploader
from tests.fixtures import MemoryDrive, receipt


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        at = now()
        writer = BundleWriter(self.root / "outbox", "synthetic-host", at - dt.timedelta(hours=1), at)
        writer.add("README.txt", "Synthetic transport fixture only.\n")
        # Incompressible payload forces multiple transport parts.
        writer.add("fixture.bin", os.urandom(PART_BYTES + 1024))
        self.marker = writer.finish()
        self.archive = self.root / "outbox" / self.marker["archive_name"]
        self.ready = self.archive.with_name(self.marker["bundle_id"] + ".ready.json")
        self.drive = MemoryDrive()
        self.uploader = Uploader({"outbox_dir": str(self.root / "outbox"),
                                  "state_dir": str(self.root / "state"), "text_transport": True}, self.drive)

    def download(self):
        root = self.root / "download"
        root.mkdir(exist_ok=True)
        for name, value in self.drive.files["inbox"].items():
            if name.startswith("transport-"):
                (root / name).write_bytes(value["raw"])
        return root / index_name(self.marker["sha256"])

    def test_lossless_roundtrip_and_idempotency(self):
        self.assertFalse(self.uploader.once()["failures"])
        index = self.download()
        data = load_index(index)
        self.assertGreater(len(data["parts"]), 1)
        archive_id = self.drive.files["inbox"][self.archive.name]["ID"]
        result = restore(index, self.root / "restored", archive_id)
        self.assertEqual(Path(result["archive"]).read_bytes(), self.archive.read_bytes())
        read_verified_bundle(result["archive"], result["marker"])
        restore(index, self.root / "restored", archive_id)
        self.drive.calls.clear()
        self.uploader.once()
        self.assertFalse(self.drive.calls)

    def test_failed_part_does_not_publish_index_and_retries(self):
        put = self.drive.put
        def fail(path, name, folder):
            if name.endswith("-001.md"):
                raise OSError("synthetic network failure")
            return put(path, name, folder)
        with patch.object(self.drive, "put", side_effect=fail):
            self.assertTrue(self.uploader.once()["failures"])
        self.assertNotIn(index_name(self.marker["sha256"]), self.drive.files["inbox"])
        self.assertIn(self.ready.name, self.drive.files["inbox"])
        self.assertFalse(self.uploader.once(now() + dt.timedelta(minutes=2))["failures"])
        self.assertIn(index_name(self.marker["sha256"]), self.drive.files["inbox"])

    def test_existing_uploaded_archive_gets_backfilled(self):
        self.uploader.text_transport = False
        self.uploader.once()
        self.uploader.text_transport = True
        self.uploader.once()
        self.assertIn(index_name(self.marker["sha256"]), self.drive.files["inbox"])

    def test_missing_truncated_and_changed_parts_fail_closed(self):
        self.uploader.once()
        index = self.download()
        part = index.parent / load_index(index)["parts"][0]["name"]
        original = part.read_bytes()
        for bad in (None, original[:-1], original.replace(b"base64", b"base65", 1)):
            with self.subTest(bad="missing" if bad is None else len(bad)):
                if bad is None:
                    part.unlink()
                else:
                    part.write_bytes(bad)
                with self.assertRaises(ValueError):
                    restore(index, self.root / "restored")
                self.assertFalse((self.root / "restored" / self.archive.name).exists())
                part.write_bytes(original)

    def test_reordered_parts_wrong_identity_and_traversal_rejected(self):
        self.uploader.once()
        index = self.download()
        original = index.read_bytes()
        for change in (lambda i: i["parts"].reverse(),
                       lambda i: i["parts"][0].update(name="../escape.md"),
                       lambda i: i["parts"][1].update(file_id=i["parts"][0]["file_id"])):
            obj = load_index(index)
            change(obj)
            index.write_text(INDEX_HEADING + json.dumps(obj) + "\n```\n")
            with self.assertRaises(ValueError):
                restore(index, self.root / "restored")
            index.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "archive ID"):
            restore(index, self.root / "restored", "different-drive-file")

    def test_transport_is_never_a_processing_receipt(self):
        uploaded = self.uploader.upload_one(self.ready)
        at = parse_time(self.marker["collection_finished_utc"]) + dt.timedelta(days=31)
        names = set(self.drive.files["inbox"])
        self.uploader.retention(at)
        self.assertEqual(set(self.drive.files["inbox"]), names)
        receipt(self.drive, uploaded, at - dt.timedelta(days=1))
        self.uploader.retention(at)
        self.assertFalse(self.drive.files["inbox"])
        deletes = [name for op, folder, name in self.drive.calls if op == "delete"]
        self.assertLess(deletes.index(index_name(self.marker["sha256"])),
                        deletes.index(uploaded["transport"]["parts"][0]["Name"]))

    def test_changed_remote_part_blocks_remote_cleanup(self):
        uploaded = self.uploader.upload_one(self.ready)
        at = parse_time(self.marker["collection_finished_utc"]) + dt.timedelta(days=31)
        receipt(self.drive, uploaded, at - dt.timedelta(days=1))
        part = uploaded["transport"]["parts"][0]["Name"]
        self.drive.files["inbox"][part]["ID"] = "replacement-id"
        result = self.uploader.retention(at)
        self.assertIn("remote_transport_changed_before_retention", [i["error"] for i in result["issues"]])
        self.assertIn(self.archive.name, self.drive.files["inbox"])

    def test_modified_outer_hash_and_conflicting_output_are_rejected(self):
        self.uploader.once()
        index = self.download()
        output = self.root / "restored"
        output.mkdir()
        (output / self.archive.name).write_bytes(b"preserve me")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            restore(index, output)
        self.assertEqual((output / self.archive.name).read_bytes(), b"preserve me")
        obj = load_index(index)
        # Text checks alone must not substitute for original archive verification.
        entry = obj["parts"][0]
        part = index.parent / entry["name"]
        raw = part.read_bytes().replace(b"```base64\n", b"```base64\nAAAA", 1)
        part.write_bytes(raw)
        entry["text_bytes"] = len(raw)
        entry["text_sha256"] = hashlib.sha256(raw).hexdigest()
        index.write_text(INDEX_HEADING + json.dumps(obj) + "\n```\n")
        with self.assertRaises(ValueError):
            restore(index, self.root / "other")

    def test_tampered_retention_record_cannot_target_unrelated_file(self):
        uploaded = self.uploader.upload_one(self.ready)
        at = parse_time(self.marker["collection_finished_utc"]) + dt.timedelta(days=31)
        receipt(self.drive, uploaded, at - dt.timedelta(days=1))
        unrelated = self.drive.seed("inbox", "keep-this.md", b"Unrelated user document")
        state = self.uploader.state / ("uploaded-" + self.marker["sha256"] + ".json")
        data = json.loads(state.read_bytes())
        data["transport"]["parts"][0] = {k: unrelated[k] for k in ("Name", "ID", "Size", "Hashes")}
        state.write_text(json.dumps(data))
        result = self.uploader.retention(at)
        self.assertIn("invalid_transport_retention_record", [i["error"] for i in result["issues"]])
        self.assertIn("keep-this.md", self.drive.files["inbox"])
        self.assertFalse(any(op == "delete" for op, _, _ in self.drive.calls))
