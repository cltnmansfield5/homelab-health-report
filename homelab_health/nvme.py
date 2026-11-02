"""Fixed NVMe SMART probe and unprivileged, freshness-checked cache reader.

The privileged entry point accepts no configuration, commands or output paths.
Only the dedicated systemd service grants CAP_SYS_ADMIN to this code.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

from .common import atomic_json, command, now, parse_time, stamp

CACHE = Path("/var/lib/homelab-health/nvme/smart.json")
SYSFS = Path("/sys/class/nvme")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SMARTCTL = "/usr/sbin/smartctl"
MAX_DEVICES = 16
MAX_OUTPUT = 128 * 1024
MAX_CACHE = 1024 * 1024
MAX_AGE = 7 * 3600
CONTROLLER = re.compile(r"nvme[0-9]+\Z")
NAMESPACE = re.compile(r"(nvme[0-9]+)n[0-9]+\Z")
IDENTIFIERS = {"serial", "serialnumber", "wwn", "eui64", "nguid", "ieeeeui64"}


class CacheError(ValueError):
    """A stable, nonsensitive coverage-gap code."""


def _text(path, limit=1024):
    with open(path, encoding="utf-8") as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise ValueError("nvme_identity_limit")
    return text.strip()


def _boot_id():
    value = _text(BOOT_ID)
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        raise ValueError("nvme_boot_identity_invalid")
    return value


def discover_controllers():
    """Enumerate controller names, never arbitrary /dev paths or shell input."""
    try:
        return sorted(path.name for path in SYSFS.iterdir() if CONTROLLER.fullmatch(path.name))
    except FileNotFoundError:
        return []  # The NVMe class need not exist on hosts without NVMe.


def controller_for_device(device):
    if device.startswith("/dev/disk/by-id/"):
        device = os.path.realpath(device)
    name = device.removeprefix("/dev/") if device.startswith("/dev/") else ""
    match = NAMESPACE.fullmatch(name)
    return match.group(1) if match else name if CONTROLLER.fullmatch(name) else None


def controller_identity(name, boot_id):
    if not CONTROLLER.fullmatch(name):
        raise ValueError("nvme_device_invalid")
    root = SYSFS / name
    # Boot-salted digest binds cached data to the current physical controller
    # without storing its serial number or a reusable serial-number hash.
    values = [boot_id, str(root.resolve(strict=True)), *(_text(root / key) for key in ("serial", "model", "firmware_rev"))]
    digest = hashlib.sha256("\0".join(values).encode()).hexdigest()
    namespaces = sorted(path.name for path in root.iterdir()
                        if (match := NAMESPACE.fullmatch(path.name)) and match.group(1) == name)
    return digest, namespaces


def _sanitize(value, depth=0):
    if depth > 32:
        raise ValueError("nvme_json_depth_limit")
    if isinstance(value, dict):
        return {key: _sanitize(child, depth + 1) for key, child in value.items()
                if re.sub(r"[^a-z0-9]", "", key.lower()) not in IDENTIFIERS}
    if isinstance(value, list):
        return [_sanitize(child, depth + 1) for child in value]
    return value


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("nvme_duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("nvme_nonfinite_json")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def _health_shape(data):
    return (isinstance(data, dict) and isinstance(data.get("smart_status"), dict)
            and type(data["smart_status"].get("passed")) is bool
            and isinstance(data.get("nvme_smart_health_information_log"), dict)
            and type(data["nvme_smart_health_information_log"].get("critical_warning")) is int)


def capture():
    started = stamp()
    payload = {"schema_version": 1, "hostname": socket.gethostname(), "boot_id": None,
               "started_at_utc": started, "observed_at_utc": started,
               "ok": False, "devices": [], "issues": []}
    try:
        payload["boot_id"] = _boot_id()
        names = discover_controllers()
    except (OSError, ValueError):
        payload["issues"].append("nvme_identity_or_discovery_failed")
        return payload
    if len(names) > MAX_DEVICES:
        payload["issues"].append("nvme_device_limit")
    for name in names[:MAX_DEVICES]:
        row = {"device": "/dev/" + name, "started_at_utc": stamp(),
               "ok": False, "collection_complete": False, "exit_status_is_bitmask": True}
        try:
            identity, namespaces = controller_identity(name, payload["boot_id"])
            row.update(identity_sha256=identity, namespaces=namespaces)
            tick = time.monotonic()
            result = command([SMARTCTL, "--json", "--all", "--quietmode=noserial",
                              "--device=nvme", "/dev/" + name], timeout=10, limit=MAX_OUTPUT)
            row.update(elapsed_ms=round((time.monotonic() - tick) * 1000),
                       **{key: value for key, value in result.items() if key != "text"})
            if result.get("timed_out") or result.get("truncated") or "returncode" not in result:
                row["error"] = "nvme_probe_incomplete"
            else:
                parsed = _sanitize(_json(result.get("text", "")))
                if not _health_shape(parsed):
                    row["error"] = "nvme_health_data_missing"
                    if isinstance(parsed, dict):
                        row["diagnostic"] = parsed
                else:
                    row["data"] = parsed
                    code = result["returncode"]
                    # Bits 0..2 are command/collection failures. Health flags
                    # (bits 3..7) must survive as observations, not vanish as gaps.
                    row["collection_complete"] = type(code) is int and 0 <= code <= 255 and not code & 7
                    if not row["collection_complete"]:
                        row["error"] = "nvme_smart_command_failed"
            if controller_identity(name, payload["boot_id"]) != (identity, namespaces):
                row.pop("data", None)
                row.update(ok=False, collection_complete=False, error="nvme_identity_changed_during_read")
        except (OSError, ValueError, RecursionError):
            row.pop("data", None)
            row.update(ok=False, collection_complete=False, error="nvme_probe_invalid_or_unavailable")
        row["ok"] = row["collection_complete"] and row.get("returncode") == 0
        row["observed_at_utc"] = stamp()
        payload["devices"].append(row)
    payload["observed_at_utc"] = stamp()
    payload["ok"] = not payload["issues"] and all(row["collection_complete"] for row in payload["devices"])
    return payload


def _read_file(path, owner_uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
            raise CacheError("nvme_cache_permissions_invalid")
        raw = stream.read(MAX_CACHE + 1)
    if len(raw) > MAX_CACHE:
        raise CacheError("nvme_cache_size_limit")
    return _json(raw)


def read_cache():
    """Validate the original source age, host, boot, shape and device identities."""
    try:
        payload = _read_file(CACHE)
        boot_id = _boot_id()
        if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
            raise CacheError("nvme_cache_schema_invalid")
        if payload.get("hostname") != socket.gethostname() or payload.get("boot_id") != boot_id:
            raise CacheError("nvme_cache_host_or_boot_mismatch")
        captured = parse_time(payload["observed_at_utc"])
        current = now()
        if not -30 <= (current - captured).total_seconds() <= MAX_AGE:
            raise CacheError("nvme_cache_stale_or_future")
        rows = payload.get("devices")
        if (not isinstance(rows, list) or len(rows) > MAX_DEVICES
                or not isinstance(payload.get("issues"), list) or len(payload["issues"]) > 32
                or any(not isinstance(issue, str) or len(issue) > 128 for issue in payload["issues"])
                or type(payload.get("ok")) is not bool):
            raise CacheError("nvme_cache_schema_invalid")
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                raise CacheError("nvme_cache_schema_invalid")
            name = row.get("device", "").removeprefix("/dev/")
            if not CONTROLLER.fullmatch(name) or row["device"] != "/dev/" + name or name in seen:
                raise CacheError("nvme_cache_device_invalid")
            seen.add(name)
            observed = parse_time(row["observed_at_utc"])
            if not -30 <= (current - observed).total_seconds() <= MAX_AGE or observed > captured:
                raise CacheError("nvme_cache_stale_or_future")
            if type(row.get("collection_complete")) is not bool or type(row.get("ok")) is not bool:
                raise CacheError("nvme_cache_schema_invalid")
            if parse_time(row["started_at_utc"]) > observed:
                raise CacheError("nvme_cache_source_period_invalid")
            if "data" in row and not _health_shape(row["data"]):
                raise CacheError("nvme_cache_result_invalid")
            if "diagnostic" in row and not isinstance(row["diagnostic"], dict):
                raise CacheError("nvme_cache_result_invalid")
            if row["collection_complete"]:
                code = row.get("returncode")
                if (type(code) is not int or not 0 <= code <= 255 or code & 7
                        or not _health_shape(row.get("data")) or row["ok"] != (code == 0)):
                    raise CacheError("nvme_cache_result_invalid")
            if "identity_sha256" in row:
                identity, namespaces = controller_identity(name, boot_id)
                if row["identity_sha256"] != identity or row.get("namespaces") != namespaces:
                    raise CacheError("nvme_cache_device_identity_mismatch")
            elif row["collection_complete"]:
                raise CacheError("nvme_cache_device_identity_missing")
        if parse_time(payload["started_at_utc"]) > captured or payload["ok"] != (not payload["issues"] and all(row["collection_complete"] for row in rows)):
            raise CacheError("nvme_cache_result_invalid")
        return payload
    except CacheError:
        raise
    except FileNotFoundError as exc:
        raise CacheError("nvme_cache_missing") from exc
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise CacheError("nvme_cache_unreadable_or_invalid") from exc


def main():
    if len(sys.argv) != 1:
        print("This probe accepts no arguments.", file=sys.stderr)
        return 2
    payload = capture()
    raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > MAX_CACHE:
        payload.update(ok=False, devices=[], issues=["nvme_cache_size_limit"])
    atomic_json(CACHE, payload)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
