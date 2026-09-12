from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
import tomllib

UTC = dt.timezone.utc
MIB = 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\Z")
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential|x-plex-token)")


def now():
    return dt.datetime.now(UTC)


def stamp(value=None):
    return (value or now()).astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timezone required")
    return result.astimezone(UTC)


def safe_name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("Invalid filename")
    return value


def read_json(path, limit=2 * MIB):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("JSON size limit exceeded")
    return json.loads(data)


def atomic_bytes(path, data, mode=0o640):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def atomic_json(path, data):
    atomic_bytes(path, (json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n").encode())


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.contextmanager
def lock(path, blocking=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield


class Redactor:
    def __init__(self, literals=()):
        self.literals = sorted((x for x in literals if x), key=len, reverse=True)

    def text(self, text):
        text = re.sub(r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)", "[REDACTED PRIVATE KEY]", str(text), flags=re.S)
        for value in self.literals:
            text = text.replace(value, "[REDACTED]")
        text = re.sub(r"(?im)(\b(?:set-cookie|cookie)\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=._~-]+", r"\1 [REDACTED]", text)
        text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
        text = re.sub(r'''(?ix)(["']?(?:password|passwd|secret|[\w-]*token|api[_-]?key|authorization|cookie|credential)["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s&,;]+)''', r"\1[REDACTED]", text)
        text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", "[REDACTED]", text)
        return text

    def clean(self, value):
        if isinstance(value, dict):
            return {str(k): "[REDACTED]" if SECRET_KEY.search(str(k)) else self.clean(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [self.clean(v) for v in value]
        return self.text(value) if isinstance(value, str) else value


def redactor_from(config):
    values = list(config.get("redact_literals", []))
    if config.get("redaction_file"):
        with open(config["redaction_file"], encoding="utf-8") as stream:
            text = stream.read(65537)
        if len(text) > 65536:
            raise ValueError("Private redaction file exceeds 64 KiB")
        values.extend(line for line in text.splitlines() if line)
    if len(values) > 128 or any(not isinstance(value, str) or len(value) < 4 for value in values):
        raise ValueError("Use at most 128 literal redactions, each at least four characters")
    return Redactor(values)


def command(argv, timeout=15, limit=512 * 1024):
    """Fixed argv only; bound output, wall time, and subprocess descendants."""
    started = time.monotonic()
    output = bytearray()
    truncated = timed_out = False
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"})
    except FileNotFoundError:
        return {"ok": False, "error": "command_unavailable", "command": argv[0]}
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk[:max(0, limit - len(output))])
                if len(output) >= limit:
                    truncated = True
                    break
            if truncated:
                break
    # Descendants may still hold stdout after the original process has exited.
    if truncated or timed_out:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    if proc.poll() is None:
        try:
            proc.wait(timeout=max(0.1, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    proc.stdout.close()
    return {"ok": proc.returncode == 0 and not truncated and not timed_out,
            "returncode": proc.returncode, "truncated": truncated, "timed_out": timed_out,
            "text": output.decode("utf-8", "replace")}


class Spool:
    """A bounded daily evidence buffer, distinct from immutable report bundles."""
    def __init__(self, directory, redactor=None, daily_bytes=64 * MIB, days=7):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        self.daily_bytes = daily_bytes
        self.days = days

    def append(self, kind, value, at=None):
        at = at or now()
        record = self.redactor.clean({"schema_version": 1, "kind": kind, "at": stamp(at), "data": value})
        raw = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        if len(raw) > 2 * MIB:
            record["data"] = {"error": "record_size_limit", "original_bytes": len(raw)}
            raw = (json.dumps(record) + "\n").encode()
        path = self.directory / (at.strftime("%Y-%m-%d") + ".jsonl")
        with lock(self.directory / ".append.lock", blocking=True):
            if (path.stat().st_size if path.exists() else 0) + len(raw) > self.daily_bytes:
                atomic_json(self.directory / "gap.json", {"at": stamp(at), "error": "daily_spool_limit", "day": path.stem})
                return False
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            with os.fdopen(fd, "ab") as stream:
                stream.write(raw)
            cutoff = (at - dt.timedelta(days=self.days)).date()
            for old in self.directory.glob("????-??-??.jsonl"):
                if old.is_file() and not old.is_symlink() and old.stem < cutoff.isoformat():
                    old.unlink()
                    atomic_json(self.directory / "pruned.json", {"at": stamp(at), "oldest_retained_date": cutoff.isoformat(), "reason": "rolling_evidence_buffer"})
        return True


def load_config(path, overrides=None):
    with open(path, "rb") as stream:
        config = tomllib.load(stream)
    for key, variable in (overrides or {}).items():
        if variable in os.environ:
            config[key] = os.environ[variable]
    return config


def bounded_int(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in {low}..{high}")
    return value


def status(path, ok, **details):
    atomic_json(path, {"at": stamp(), "ok": ok, **Redactor().clean(details)})
