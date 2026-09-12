from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import uuid

from .common import MIB, Redactor, atomic_bytes, atomic_json, digest_file, now, parse_time, read_json, safe_name, stamp

ARCHIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.tar\.gz\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def validate_marker(marker):
    if not isinstance(marker, dict) or type(marker.get("schema_version")) is not int or marker["schema_version"] != 1 or not ARCHIVE.fullmatch(marker.get("archive_name", "")):
        raise ValueError("Invalid bundle marker")
    if marker.get("bundle_id") != marker["archive_name"][:-7] or not DIGEST.fullmatch(marker.get("sha256", "")):
        raise ValueError("Invalid bundle identity")
    if type(marker.get("archive_bytes")) is not int or not 0 < marker["archive_bytes"] <= 512 * MIB:
        raise ValueError("Invalid archive size")
    if not isinstance(marker.get("hostname"), str) or not marker["hostname"]:
        raise ValueError("Missing host identity")
    start, end, finished = [parse_time(marker[k]) for k in ("requested_start_utc", "requested_end_utc", "collection_finished_utc")]
    if start > end or end > finished + dt.timedelta(minutes=5) or end - start > dt.timedelta(days=8):
        raise ValueError("Invalid bundle time window")
    return marker


class BundleWriter:
    def __init__(self, outbox, hostname, start, end, max_bytes=128 * MIB, redactor=None):
        self.outbox = Path(outbox)
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        hostname = self.redactor.text(hostname)
        hostname_slug = re.sub(r"[^A-Za-z0-9_.-]", "-", hostname)[:80].strip(".-") or "host"
        self.bundle_id = hostname_slug + "-" + end.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        self.temp = tempfile.TemporaryDirectory(prefix=".bundle-", dir=self.outbox)
        self.root = Path(self.temp.name)
        self.max_bytes = max_bytes
        self.total = 0
        self.manifest = {"schema_version": 1, "bundle_id": self.bundle_id, "hostname": hostname,
                         "requested_start_utc": stamp(start), "requested_end_utc": stamp(end),
                         "files": [], "issues": [], "metrics_start_at_installation": True}

    def add(self, name, data, **metadata):
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts or len(member.parts) > 3 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in member.parts):
            raise ValueError("Unsafe bundle member name")
        if isinstance(data, (dict, list)):
            data = json.dumps(self.redactor.clean(data), ensure_ascii=False, indent=2).encode()
        if isinstance(data, str):
            data = self.redactor.text(data).encode()
        if self.total + len(data) > self.max_bytes:
            self.manifest["issues"].append({"source": name, "error": "bundle_size_limit", "omitted_bytes": len(data)})
            return False
        path = self.root / name
        if path.exists():
            raise ValueError("Duplicate bundle member")
        atomic_bytes(path, data)
        self.total += len(data)
        self.manifest["files"].append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), **self.redactor.clean(metadata)})
        return True

    def finish(self):
        self.manifest["collection_finished_utc"] = stamp()
        # Payloads and free-form metadata are already redacted. Never alter protocol hashes.
        atomic_json(self.root / "manifest.json", self.manifest)
        archive = self.outbox / (self.bundle_id + ".tar.gz")
        temporary = self.root / "archive.partial"
        with tarfile.open(temporary, "w:gz") as tar:
            for path in sorted(self.root.rglob("*")):
                if not path.is_file() or path == temporary:
                    continue
                info = tar.gettarinfo(str(path), arcname=path.relative_to(self.root).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o640
                with path.open("rb") as stream:
                    tar.addfile(info, stream)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, archive)
        marker = {k: self.manifest[k] for k in ("schema_version", "bundle_id", "hostname", "requested_start_utc", "requested_end_utc", "collection_finished_utc")}
        marker.update({"archive_name": archive.name, "archive_bytes": archive.stat().st_size, "sha256": digest_file(archive)})
        validate_marker(marker)
        atomic_json(self.outbox / (self.bundle_id + ".ready.json"), marker)
        self.temp.cleanup()
        return marker

    def close(self):
        self.temp.cleanup()


class BoundedArchiveStream:
    """Count decoded tar bytes, including headers tarfile consumes internally."""
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size):
        raw = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(raw)
        if self.remaining < 0:
            raise ValueError("Expanded archive stream limit exceeded")
        return raw


def read_verified_bundle(archive, marker_path, max_expanded=160 * MIB):
    """Never extract to disk. Reject links, devices, duplicates and archive bombs."""
    archive = Path(archive)
    marker = validate_marker(read_json(marker_path, 65536))
    if archive.is_symlink() or archive.name != marker["archive_name"] or archive.stat().st_size != marker["archive_bytes"] or digest_file(archive) != marker["sha256"]:
        raise ValueError("Archive name, size or SHA-256 does not match completion marker")
    contents = {}
    total = 0
    # PAX/GNU metadata is processed before tarfile yields members. Bound it too.
    with gzip.open(archive, "rb") as decoded, tarfile.open(fileobj=BoundedArchiveStream(decoded, max_expanded + 2 * MIB), mode="r|") as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if (not member.isfile() or name.is_absolute() or ".." in name.parts or "\\" in member.name
                    or str(name) != member.name or member.name in contents or len(contents) >= 512
                    or member.size < 0 or member.size > 16 * MIB):
                raise ValueError("Unsafe or oversized archive member")
            total += member.size
            if total > max_expanded:
                raise ValueError("Expanded archive size limit exceeded")
            stream = tar.extractfile(member)
            raw = stream.read(member.size + 1)
            if len(raw) != member.size:
                raise ValueError("Incomplete archive member")
            contents[member.name] = raw
    manifest = json.loads(contents["manifest.json"])
    for key in ("schema_version", "bundle_id", "hostname", "requested_start_utc", "requested_end_utc", "collection_finished_utc"):
        if manifest.get(key) != marker[key]:
            raise ValueError("Manifest and marker disagree")
    listed = set()
    for item in manifest["files"]:
        name = item["name"]
        if name in listed or name == "manifest.json":
            raise ValueError("Duplicate manifest entry")
        listed.add(name)
        raw = contents[name]
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("Member integrity failure")
    if listed != set(contents) - {"manifest.json"}:
        raise ValueError("Unlisted archive member")
    return marker, manifest, contents


def spool_window(directory, start, end, limit=8 * MIB):
    """Keep complete records only; annotate dropped records and absent periods."""
    output = bytearray()
    first = last = None
    issues = []
    count = 0
    directory = Path(directory)
    for path in sorted(directory.glob("????-??-??.jsonl")):
        if path.is_symlink() or not path.is_file() or not start.date().isoformat() <= path.stem <= end.date().isoformat():
            continue
        with path.open("rb") as stream:
            while True:
                line = stream.readline(2 * MIB + 1)
                if not line:
                    break
                if len(line) > 2 * MIB:
                    issues.append({"file": path.name, "error": "oversized_spool_record"})
                    break
                if not line.endswith(b"\n"):
                    issues.append({"file": path.name, "error": "partial_spool_record"})
                    break
                try:
                    record = json.loads(line)
                    at = parse_time(record["at"])
                except (ValueError, KeyError, TypeError):
                    issues.append({"file": path.name, "error": "invalid_spool_record"})
                    continue
                if not start <= at <= end:
                    continue
                if len(output) + len(line) > limit:
                    issues.append({"error": "source_byte_limit", "omitted_from_utc": stamp(at)})
                    return bytes(output), {"records": count, "first_record_utc": first, "last_record_utc": last, "issues": issues}
                output.extend(line)
                count += 1
                first = first or stamp(at)
                last = stamp(at)
    if count == 0:
        issues.append({"error": "no_records_in_requested_window"})
    return bytes(output), {"records": count, "first_record_utc": first, "last_record_utc": last, "issues": issues}
