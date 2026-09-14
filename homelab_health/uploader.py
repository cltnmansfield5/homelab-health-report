"""Verified uploads and narrow, receipt-gated retention; never rclone sync/purge."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import signal
import tempfile
import threading
import time
import urllib.parse

from .bundle import DIGEST, validate_marker
from .common import MIB, Redactor, atomic_json, bounded_int, command, digest_file, lock, now, parse_time, read_json, safe_name, stamp, status

RECEIPT = re.compile(r"processed-([a-f0-9]{64})\.json\Z")


class Rclone:
    def __init__(self, config):
        self.remote = config.get("remote", "homelab")
        # Bounded ASCII remote names, including email-style names. Exclude a
        # leading dash, path separators, ':' and connection-string options.
        if not isinstance(self.remote, str) or not re.fullmatch(r"[A-Za-z0-9_.+@][A-Za-z0-9_.+@-]{0,127}", self.remote):
            raise ValueError("Invalid rclone remote name")
        self.config_file = config.get("rclone_config", "/credentials/rclone.conf")
        self.folders = {"inbox": config["inbox_folder_id"], "reports": config["reports_folder_id"]}
        if any(not re.fullmatch(r"[A-Za-z0-9_-]{8,160}", v) for v in self.folders.values()) or self.folders["inbox"] == self.folders["reports"]:
            raise ValueError("Distinct Inbox and Reports folder IDs are required")

    def call(self, args, folder, limit=8 * MIB, timeout=180):
        with tempfile.TemporaryDirectory(prefix="homelab-rclone-") as cache:
            result = command(["rclone", *args, "--config", self.config_file,
                              "--drive-root-folder-id", self.folders[folder], "--drive-use-trash=true",
                              "--retries", "2", "--low-level-retries", "3", "--contimeout", "10s",
                              "--timeout", "60s", "--cache-dir", cache, "--log-level", "ERROR"], timeout=timeout, limit=limit)
        if not result["ok"]:
            raise RuntimeError("rclone_failed: " + Redactor().text(result.get("text", result.get("error", "unknown")))[:1000])
        return result.get("text", "")

    def path(self, name=""):
        return self.remote + ":" + (safe_name(name) if name else "")

    def list(self, folder):
        raw = json.loads(self.call(["lsjson", self.path(), "--files-only", "--max-depth", "1", "--hash-type", "MD5"], folder))
        if not isinstance(raw, list):
            raise ValueError("Invalid remote listing")
        result = {}
        for item in raw:
            if item["Name"] in result:
                raise ValueError("Duplicate remote filenames require manual review")
            # rclone emits lowercase hash names; keep one canonical form for
            # upload verification, persisted records and retention checks.
            item["Hashes"] = {name.upper(): value.lower() for name, value in item.get("Hashes", {}).items()}
            result[item["Name"]] = item
        return result

    def put(self, source, name, folder):
        source = Path(source)
        safe_name(name)
        before = self.list(folder)
        md5 = hashlib.md5(usedforsecurity=False)
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(MIB), b""):
                md5.update(chunk)
        def matches(meta):
            text_part = name.startswith("transport-") and name.endswith(".md")
            readable = not text_part or meta.get("MimeType", "").split(";", 1)[0] == "text/markdown"
            return readable and meta.get("Size") == source.stat().st_size and meta.get("Hashes", {}).get("MD5", "").lower() == md5.hexdigest()
        if name in before and not matches(before[name]):
            raise ValueError("Remote filename exists with different contents or MIME type; refusing overwrite")
        if name not in before:
            self.call(["copyto", str(source), self.path(name), "--checksum", "--immutable"], folder, timeout=900)
        after = self.list(folder)
        if name not in after or not matches(after[name]) or not after[name].get("ID"):
            raise ValueError("Remote upload size/MD5/identity verification failed")
        return after[name]

    def read(self, name, folder, limit=65536):
        return json.loads(self.call(["cat", self.path(name)], folder, limit=limit))

    def delete(self, name, folder, expected_id):
        # Fresh identity check immediately before exact-name deletion; refuse duplicates.
        listing = self.list(folder)
        if name not in listing:
            return
        if listing[name].get("ID") != expected_id:
            raise ValueError("Remote file identity changed; refusing deletion")
        self.call(["deletefile", self.path(name)], folder)
        if name in self.list(folder):
            raise ValueError("Remote deletion was not confirmed")


def valid_receipt(receipt, marker, archive_id, reports, at=None):
    at = at or now()
    try:
        if (not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1 or receipt["sha256"] != marker["sha256"]
                or receipt["archive_name"] != marker["archive_name"] or receipt["archive_id"] != archive_id):
            return False
        processed = parse_time(receipt["processed_at_utc"])
        if processed > at + dt.timedelta(minutes=5) or processed < parse_time(marker["collection_finished_utc"]) - dt.timedelta(minutes=5):
            return False
        coverage = receipt["observed_coverage"]
        if not isinstance(coverage, dict) or not coverage:
            return False
        report_id = receipt["report_file_id"]
        report = next((v for v in reports.values() if v.get("ID") == report_id), None)
        if not report or not report.get("Name", "").startswith("Homelab-Health-") or not report["Name"].endswith(".md") or report.get("Size", 0) <= 0:
            return False
        url = urllib.parse.urlsplit(receipt["report_url"])
        return url.scheme == "https" and url.netloc == "drive.google.com" and url.path in ("/file/d/" + report_id + "/view", "/file/d/" + report_id)
    except (KeyError, TypeError, ValueError):
        return False


class Uploader:
    def __init__(self, config, remote=None):
        self.config = config
        self.outbox = Path(config.get("outbox_dir", "/outbox"))
        self.state = Path(config.get("state_dir", "/state"))
        self.state.mkdir(parents=True, exist_ok=True)
        self.remote = remote or Rclone(config)
        self.local_days = bounded_int(config.get("local_days", 7), 1, 365, "local_days")
        self.drive_days = bounded_int(config.get("drive_days", 30), self.local_days, 3650, "drive_days")
        self.text_transport = config.get("text_transport", False)
        if type(self.text_transport) is not bool:
            raise ValueError("text_transport must be a boolean")
        self.stop = threading.Event()

    def upload_one(self, marker_path):
        marker = validate_marker(read_json(marker_path, 65536))
        if Path(marker_path).name != marker["bundle_id"] + ".ready.json":
            raise ValueError("Marker filename and bundle identity disagree")
        archive = self.outbox / marker["archive_name"]
        if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != marker["archive_bytes"] or digest_file(archive) != marker["sha256"]:
            raise ValueError("Local archive integrity failure")
        meta = self.remote.put(archive, archive.name, "inbox")
        # Completion is published only AFTER archive upload and remote verification.
        ready = self.remote.put(marker_path, Path(marker_path).name, "inbox")
        uploaded = {"marker": marker, "archive_id": meta["ID"], "archive_md5": meta["Hashes"]["MD5"],
                    "marker_id": ready["ID"], "marker_md5": ready["Hashes"]["MD5"], "uploaded_at_utc": stamp()}
        atomic_json(self.state / ("uploaded-" + marker["sha256"] + ".json"), uploaded)
        if self.text_transport:
            from .transport import upload_transport
            def progress(done, total):
                status(self.state / "status.json", False, phase="text_transport", archive=archive.name,
                       completed_parts=done, total_parts=total, pending_uploads=1)
            uploaded["transport"] = upload_transport(self.remote, archive, marker, meta["ID"], progress)
            atomic_json(self.state / ("uploaded-" + marker["sha256"] + ".json"), uploaded)
        return uploaded

    def retention(self, at=None):
        at = at or now()
        reports = self.remote.list("reports")
        inbox = self.remote.list("inbox")
        receipt_files = {m.group(1): item for name, item in reports.items() if (m := RECEIPT.fullmatch(name))}
        issues = []
        deleted = []
        # Upload records survive local deletion and allow remote cleanup weeks later.
        for path in sorted(self.state.glob("uploaded-*.json")):
            record = read_json(path)
            marker = validate_marker(record["marker"])
            digest = marker["sha256"]
            if digest not in receipt_files:
                continue
            receipt_meta = receipt_files[digest]
            if receipt_meta.get("Size", 65537) > 65536:
                issues.append({"sha256": digest, "error": "oversized_receipt"})
                continue
            try:
                receipt = self.remote.read(receipt_meta["Name"], "reports")
            except (ValueError, TypeError):
                issues.append({"sha256": digest, "error": "invalid_receipt_json"})
                continue
            if not valid_receipt(receipt, marker, record["archive_id"], reports, at):
                issues.append({"sha256": digest, "error": "receipt_or_saved_report_not_verified"})
                continue
            age = at - parse_time(marker["collection_finished_utc"])
            archive = self.outbox / marker["archive_name"]
            ready = self.outbox / (marker["bundle_id"] + ".ready.json")
            remote_archive = inbox.get(archive.name)
            remote_ready = inbox.get(ready.name)
            if age >= dt.timedelta(days=self.local_days) and not record.get("local_deleted"):
                if not record.get("drive_deleted") and (not remote_archive or remote_archive.get("ID") != record["archive_id"]
                        or remote_archive.get("Hashes", {}).get("MD5") != record["archive_md5"]
                        or remote_archive.get("Size") != marker["archive_bytes"]
                        or not remote_ready or remote_ready.get("ID") != record["marker_id"]
                        or remote_ready.get("Hashes", {}).get("MD5") != record["marker_md5"]):
                    issues.append({"sha256": digest, "error": "remote_bundle_missing_or_changed"})
                    continue
                if archive.exists() and (archive.is_symlink() or digest_file(archive) != digest):
                    issues.append({"sha256": digest, "error": "local_file_changed"})
                    continue
                # Remove local marker first; a interrupted cleanup never leaves a false ready pair.
                ready.unlink(missing_ok=True)
                archive.unlink(missing_ok=True)
                record["local_deleted"] = stamp(at)
                atomic_json(path, record)
                deleted.append({"sha256": digest, "location": "local"})
            if age >= dt.timedelta(days=self.drive_days) and not record.get("drive_deleted"):
                # Mirrors are private evidence, governed by the SAME full-review receipt.
                # Refuse changed identities/content; remove the mirror index before parts.
                transport = record.get("transport", {})
                try:
                    from .transport import retention_files
                    mirrored = retention_files(transport, marker) if transport else []
                except (KeyError, ValueError, TypeError, AttributeError):
                    issues.append({"sha256": digest, "error": "invalid_transport_retention_record"})
                    continue
                if any(item["Name"] in inbox and (
                        inbox[item["Name"]].get("ID") != item["ID"]
                        or inbox[item["Name"]].get("Size") != item["Size"]
                        or inbox[item["Name"]].get("Hashes", {}).get("MD5") != item["Hashes"]["MD5"])
                       for item in mirrored):
                    issues.append({"sha256": digest, "error": "remote_transport_changed_before_retention"})
                    continue
                if ((remote_archive and (remote_archive.get("ID") != record["archive_id"] or remote_archive.get("Size") != marker["archive_bytes"] or remote_archive.get("Hashes", {}).get("MD5") != record["archive_md5"]))
                        or (remote_ready and (remote_ready.get("ID") != record["marker_id"] or remote_ready.get("Hashes", {}).get("MD5") != record["marker_md5"]))):
                    issues.append({"sha256": digest, "error": "remote_file_changed_before_retention"})
                    continue
                # Deletion is exact and moved to Drive trash, never a folder-wide purge.
                for item in mirrored:
                    self.remote.delete(item["Name"], "inbox", item["ID"])
                self.remote.delete(ready.name, "inbox", record["marker_id"])
                self.remote.delete(archive.name, "inbox", record["archive_id"])
                record["drive_deleted"] = stamp(at)
                atomic_json(path, record)
                deleted.append({"sha256": digest, "location": "drive"})
        return {"deleted": deleted, "issues": issues}

    def once(self, at=None):
        at = at or now()
        failures = []
        pending = 0
        for marker_path in sorted(self.outbox.glob("*.ready.json")):
            if marker_path.is_symlink():
                failures.append({"file": marker_path.name, "error": "symlink_rejected"})
                continue
            try:
                marker = validate_marker(read_json(marker_path, 65536))
                uploaded_path = self.state / ("uploaded-" + marker["sha256"] + ".json")
                if uploaded_path.exists():
                    uploaded = read_json(uploaded_path)
                    if not self.text_transport or uploaded.get("transport"):
                        continue
                pending += 1
                retry_path = self.state / ("retry-" + marker["sha256"] + ".json")
                retry = read_json(retry_path) if retry_path.exists() else {}
                if retry.get("next_attempt_epoch", 0) > at.timestamp():
                    continue
                try:
                    self.upload_one(marker_path)
                    pending -= 1
                    retry_path.unlink(missing_ok=True)
                except Exception:
                    attempts = min(int(retry.get("attempts", 0)) + 1, 20)
                    atomic_json(retry_path, {"attempts": attempts, "next_attempt_epoch": at.timestamp() + min(3600, 60 * 2 ** min(attempts - 1, 6))})
                    raise
            except Exception as exc:
                failures.append({"file": marker_path.name, "error": type(exc).__name__, "detail": str(exc)[:1000]})
        cleanup = self.retention(at)
        status(self.state / "status.json", not failures and not cleanup["issues"] and pending == 0, pending_uploads=pending, failures=failures, retention=cleanup)
        return {"pending_uploads": pending, "failures": failures, **cleanup}

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        with lock(self.state / ".uploader.lock"):
            while not self.stop.is_set():
                try:
                    self.once()
                except Exception as exc:
                    status(self.state / "status.json", False, error=type(exc).__name__, detail=str(exc)[:1000])
                self.stop.wait(300)
