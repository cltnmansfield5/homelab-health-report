"""Optional, lossless text transport for connectors that cannot download binaries.

This is an encoding of the original archive, never a summary or processing receipt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .bundle import DIGEST, read_verified_bundle, validate_marker
from .common import atomic_bytes, atomic_json, digest_file, read_json

PART_BYTES = 384 * 1024
MAX_PARTS = 512
MAX_TEXT_BYTES = 600 * 1024
MAX_INDEX_BYTES = 512 * 1024
PART_HEADING = "# Homelab archive transport part\n\n```json\n"
INDEX_HEADING = "# Homelab archive transport\n\n```json\n"
DRIVE_ID = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")


def part_name(digest, number):
    return f"transport-{digest}-{number:03}.md"


def index_name(digest):
    return f"transport-{digest}.ready.md"


def retention_files(transport, marker):
    """Local bookkeeping may only identify this archive's canonical mirror files."""
    count = (marker["archive_bytes"] + PART_BYTES - 1) // PART_BYTES
    if (transport.get("schema_version") != 1 or not 0 < count <= MAX_PARTS
            or not isinstance(transport.get("parts"), list) or len(transport["parts"]) != count):
        raise ValueError("Invalid transport retention record")
    files = [transport["ready"], *transport["parts"]]
    names = [index_name(marker["sha256"]), *(part_name(marker["sha256"], n) for n in range(count))]
    for item, name in zip(files, names):
        if (item.get("Name") != name or not DRIVE_ID.fullmatch(item.get("ID", ""))
                or type(item.get("Size")) is not int or not 0 < item["Size"] <= MAX_TEXT_BYTES
                or not re.fullmatch(r"[a-f0-9]{32}", item.get("Hashes", {}).get("MD5", ""))):
            raise ValueError("Invalid transport retention file")
    return files


def encode_part(raw, digest, number):
    header = {"schema_version": 1, "archive_sha256": digest, "part_index": number,
              "decoded_bytes": len(raw), "decoded_sha256": hashlib.sha256(raw).hexdigest()}
    text = (PART_HEADING + json.dumps(header, sort_keys=True) + "\n```\n\n```base64\n"
            + base64.encodebytes(raw).decode("ascii") + "```\n").encode("ascii")
    entry = {"name": part_name(digest, number), "part_index": number,
             "decoded_bytes": len(raw), "decoded_sha256": header["decoded_sha256"],
             "text_bytes": len(text), "text_sha256": hashlib.sha256(text).hexdigest()}
    return text, entry


def upload_transport(remote, archive, marker, archive_id, progress=None):
    """Upload one bounded temporary part at a time; publish the index last.

    Rclone.put verifies remote size/MD5/ID and refuses conflicting filenames.
    The caller has verified the original archive and uploaded its ready marker.
    """
    marker = validate_marker(marker)
    count = (marker["archive_bytes"] + PART_BYTES - 1) // PART_BYTES
    if count > MAX_PARTS:
        raise ValueError("Archive exceeds text transport limit")
    index = {"schema_version": 1, "encoding": "base64", "part_bytes": PART_BYTES,
             "marker": marker, "archive_id": archive_id, "parts": []}
    uploaded = []
    digest = hashlib.sha256()
    total = 0
    with tempfile.TemporaryDirectory(prefix="homelab-transport-") as tmp, Path(archive).open("rb") as source:
        path = Path(tmp) / "part.md"
        for number in range(count):
            raw = source.read(PART_BYTES)
            if not raw:
                raise ValueError("Archive changed during text upload")
            total += len(raw)
            digest.update(raw)
            text, entry = encode_part(raw, marker["sha256"], number)
            atomic_bytes(path, text)
            meta = remote.put(path, entry["name"], "inbox")
            entry["file_id"] = meta["ID"]
            index["parts"].append(entry)
            uploaded.append({key: meta[key] for key in ("Name", "ID", "Size", "Hashes")})
            if progress:
                progress(number + 1, count)
        if source.read(1) or total != marker["archive_bytes"] or digest.hexdigest() != marker["sha256"]:
            raise ValueError("Archive changed during text upload")
        text = (INDEX_HEADING + json.dumps(index, sort_keys=True, indent=2) + "\n```\n").encode("ascii")
        if len(text) > MAX_INDEX_BYTES:
            raise ValueError("Transport index exceeds size limit")
        atomic_bytes(path, text)
        ready = remote.put(path, index_name(marker["sha256"]), "inbox")
    return {"schema_version": 1, "ready": {key: ready[key] for key in ("Name", "ID", "Size", "Hashes")}, "parts": uploaded}


def load_index(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_INDEX_BYTES:
        raise ValueError("Unsafe or oversized transport index")
    text = path.read_text(encoding="ascii")
    if not text.startswith(INDEX_HEADING) or not text.endswith("\n```\n"):
        raise ValueError("Invalid transport index document")
    index = json.loads(text[len(INDEX_HEADING):-5])
    marker = validate_marker(index["marker"])
    if (type(index.get("schema_version")) is not int or index["schema_version"] != 1
            or index.get("encoding") != "base64" or index.get("part_bytes") != PART_BYTES
            or path.name != index_name(marker["sha256"])
            or not isinstance(index.get("archive_id"), str) or not DRIVE_ID.fullmatch(index["archive_id"])):
        raise ValueError("Invalid transport identity")
    parts = index["parts"]
    count = (marker["archive_bytes"] + PART_BYTES - 1) // PART_BYTES
    if not isinstance(parts, list) or not 0 < len(parts) == count <= MAX_PARTS:
        raise ValueError("Invalid transport part count")
    ids = set()
    for number, entry in enumerate(parts):
        expected = min(PART_BYTES, marker["archive_bytes"] - number * PART_BYTES)
        if (entry.get("name") != part_name(marker["sha256"], number)
                or type(entry.get("part_index")) is not int or entry["part_index"] != number
                or type(entry.get("decoded_bytes")) is not int or entry["decoded_bytes"] != expected
                or type(entry.get("text_bytes")) is not int or not 0 < entry["text_bytes"] <= MAX_TEXT_BYTES
                or not isinstance(entry.get("file_id"), str) or not DRIVE_ID.fullmatch(entry["file_id"])
                or entry["file_id"] in ids
                or not isinstance(entry.get("text_sha256"), str) or not DIGEST.fullmatch(entry["text_sha256"])
                or not isinstance(entry.get("decoded_sha256"), str) or not DIGEST.fullmatch(entry["decoded_sha256"])):
            raise ValueError("Invalid or duplicate transport part")
        ids.add(entry["file_id"])
    return index


def restore(index_path, destination, expected_archive_id=None):
    """Reconstruct locally fetched text parts, then run the full archive verifier.

    This does not connect to Drive, execute bundled code, or issue a receipt.
    """
    index_path = Path(index_path)
    index = load_index(index_path)
    if expected_archive_id is not None and index["archive_id"] != expected_archive_id:
        raise ValueError("Transport archive ID differs from confirmed Drive metadata")
    marker = index["marker"]
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".restore-", dir=destination) as tmp:
        archive = Path(tmp) / marker["archive_name"]
        with archive.open("wb") as stream:
            for entry in index["parts"]:
                path = index_path.parent / entry["name"]
                if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["text_bytes"]:
                    raise ValueError("Missing, unsafe or truncated transport part")
                text = path.read_bytes()
                if hashlib.sha256(text).hexdigest() != entry["text_sha256"]:
                    raise ValueError("Transport text hash mismatch")
                if not text.startswith(PART_HEADING.encode()) or not text.endswith(b"```\n"):
                    raise ValueError("Invalid transport part document")
                head, payload = text[len(PART_HEADING):-4].split(b"\n```\n\n```base64\n", 1)
                expected = {"schema_version": 1, "archive_sha256": marker["sha256"],
                            "part_index": entry["part_index"], "decoded_bytes": entry["decoded_bytes"],
                            "decoded_sha256": entry["decoded_sha256"]}
                if json.loads(head) != expected:
                    raise ValueError("Transport part identity mismatch")
                raw = base64.b64decode(b"".join(payload.splitlines()), validate=True)
                if len(raw) != entry["decoded_bytes"] or hashlib.sha256(raw).hexdigest() != entry["decoded_sha256"]:
                    raise ValueError("Transport decoded hash/size mismatch")
                stream.write(raw)
        ready = Path(tmp) / (marker["bundle_id"] + ".ready.json")
        atomic_json(ready, marker)
        # Outer byte count/SHA and the original manifest/member safety rules apply.
        read_verified_bundle(archive, ready)
        for source in (archive, ready):
            target = destination / source.name
            if target.is_symlink():
                raise ValueError("Refusing to replace symlink")
            if target.exists():
                matches = (digest_file(target) == marker["sha256"] if source == archive
                           else read_json(target, 65536) == marker)
                if not matches:
                    raise ValueError("Refusing to overwrite different destination contents")
        for source in (archive, ready):
            target = destination / source.name
            if not target.exists():
                os.replace(source, target)
    return {"archive": str(destination / marker["archive_name"]),
            "marker": str(destination / ready.name), "sha256": marker["sha256"],
            "archive_id": index["archive_id"], "verified": True}
