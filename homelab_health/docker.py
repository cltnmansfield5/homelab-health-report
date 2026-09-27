from __future__ import annotations

import contextlib
from collections import OrderedDict
import fnmatch
import hashlib
import json
import re
import struct
import threading
import time
import urllib.parse
import urllib.request

from .common import MIB, atomic_json, now, read_json
from .noise import compact_exec, routine_exec


class Docker:
    def __init__(self, base="http://docker-api:2375", timeout=15):
        url = urllib.parse.urlsplit(base)
        if url.scheme != "http" or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("Use an internal HTTP Docker gateway URL")
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.version = None

    def url(self, path, params=None):
        return self.base + path + (("?" + urllib.parse.urlencode(params)) if params else "")

    def get(self, path, params=None, limit=8 * MIB):
        with self.opener.open(self.url(path, params), timeout=self.timeout) as response:
            data = response.read(limit + 1)
        return data[:limit], len(data) > limit

    def api_path(self, path):
        if self.version is None:
            data = self.json("/version", versioned=False)
            version = data.get("ApiVersion", "")
            if not re.fullmatch(r"1\.[0-9]{2,3}", version) or int(version.split(".")[1]) < 41:
                raise ValueError("Docker API 1.41 or newer is required")
            self.version = version
        return "/v" + self.version + path

    def json(self, path, params=None, versioned=True):
        raw, truncated = self.get(self.api_path(path) if versioned else path, params)
        if truncated:
            raise ValueError("Docker JSON response exceeded limit")
        return json.loads(raw)

    def containers(self):
        return self.json("/containers/json", {"all": "1"})

    def inspect(self, container):
        raw = self.json("/containers/" + container + "/json")
        config = raw.get("Config") or {}
        state = raw.get("State") or {}
        health = state.get("Health") or {}
        labels = config.get("Labels") or {}
        # Deliberately omit Env, command arguments, arbitrary labels, mounts and healthcheck commands.
        return {"id": raw["Id"], "name": raw.get("Name", "").lstrip("/"), "created": raw.get("Created"),
                "image": config.get("Image"), "image_id": raw.get("Image"), "tty": bool(config.get("Tty")),
                "compose_project": labels.get("com.docker.compose.project"),
                "compose_service": labels.get("com.docker.compose.service"),
                "restart_count_snapshot": raw.get("RestartCount"),
                "state": {k: state.get(k) for k in ("Status", "Running", "OOMKilled", "Dead", "ExitCode", "Error", "StartedAt", "FinishedAt")},
                "health": {"status": health.get("Status"), "failing_streak": health.get("FailingStreak"), "log": (health.get("Log") or [])[-5:]},
                "log_driver": ((raw.get("HostConfig") or {}).get("LogConfig") or {}).get("Type")}

    def stats(self, container):
        raw = self.json("/containers/" + container + "/stats", {"stream": "false", "one-shot": "true"})
        result = {k: raw[k] for k in ("id", "name", "read", "pids_stats", "networks") if k in raw}
        cpu = raw.get("cpu_stats", {})
        result["cpu_stats"] = {"total_usage": cpu.get("cpu_usage", {}).get("total_usage"),
                               "system_cpu_usage": cpu.get("system_cpu_usage"),
                               "online_cpus": cpu.get("online_cpus"), "throttling_data": cpu.get("throttling_data", {})}
        memory = raw.get("memory_stats", {})
        result["memory_stats"] = {k: memory[k] for k in ("usage", "limit", "max_usage", "failcnt") if k in memory}
        result["memory_stats"]["stats"] = {k: v for k, v in memory.get("stats", {}).items() if k in ("cache", "rss", "inactive_file", "total_inactive_file", "pgmajfault")}
        result["blkio_stats"] = {k: v for k, v in raw.get("blkio_stats", {}).items() if k in ("io_service_bytes_recursive", "io_serviced_recursive")}
        return result

    def logs(self, container, start, end, tty, tail=20000, limit=8 * MIB):
        raw, truncated = self.get(self.api_path("/containers/" + container + "/logs"),
                                  {"stdout": "1", "stderr": "1", "timestamps": "1", "follow": "0", "since": int(start.timestamp()), "until": int(end.timestamp()), "tail": tail}, limit)
        text, damaged = demux(raw, tty)
        return text, {"byte_limit_reached": truncated, "incomplete_frame": damaged, "line_limit_may_be_reached": len(text.splitlines()) >= tail}


def demux(raw, tty=False):
    if tty:
        return raw.decode("utf-8", "replace"), False
    pos = 0
    output = bytearray()
    while pos < len(raw):
        if len(raw) - pos < 8:
            return output.decode("utf-8", "replace"), True
        stream, zero1, zero2, zero3, size = struct.unpack(">BBBBI", raw[pos:pos + 8])
        if stream not in (0, 1, 2) or any((zero1, zero2, zero3)) or pos + 8 + size > len(raw):
            return output.decode("utf-8", "replace"), True
        output.extend(raw[pos + 8:pos + 8 + size])
        pos += size + 8
    return output.decode("utf-8", "replace"), False


def selected_event(raw):
    actor = raw.get("Actor", {})
    attrs = actor.get("Attributes", {})
    action = raw.get("Action", raw.get("status"))
    # Docker embeds argv in exec_create/start Action strings, not only attributes.
    # Positional secrets cannot be reliably redacted; never persist those arguments.
    if isinstance(action, str) and re.match(r"^exec_(?:create|start)(?::|$)", action):
        action = action.split(":", 1)[0]
    return {"type": raw.get("Type"), "action": action,
            "id": actor.get("ID", raw.get("id")), "time": raw.get("time"), "timeNano": raw.get("timeNano"),
            "attributes": {k: attrs[k] for k in ("name", "image", "exitCode", "signal", "com.docker.compose.project", "com.docker.compose.service") if k in attrs}}


class EventPump(threading.Thread):
    def __init__(self, docker, spool, state_path, stop, config=None):
        super().__init__(daemon=True, name="docker-events")
        self.docker, self.spool, self.state_path, self.stop = docker, spool, state_path, stop
        self.config = config or {}
        self.pending_exec = []
        self.seen = OrderedDict()
        self.cursor = int(time.time()) - 120
        self.last_flush = time.monotonic()

    def checkpoint(self):
        # Pending batches and replay identities advance atomically with the cursor.
        atomic_json(self.state_path, {"epoch": self.cursor, "at": now().isoformat(),
                                     "pending_exec": self.pending_exec, "seen": list(self.seen)})

    def restore(self):
        try:
            state = read_json(self.state_path)
        except FileNotFoundError:
            return
        self.cursor = state.get("epoch", self.cursor)
        self.pending_exec = state.get("pending_exec", [])
        self.seen = OrderedDict.fromkeys(state.get("seen", [])[-512:])

    def flush_exec(self):
        if not self.pending_exec:
            self.last_flush = time.monotonic()
            return True
        # A crash between append and checkpoint can replay a batch. Each entry's
        # container/action/timeNano identity survives, so readers can deduplicate.
        remaining = []
        accepted = True
        for group in compact_exec(self.pending_exec):
            if not self.spool.append("docker_exec_summary", group):
                accepted = False
                remaining.extend(e for e in self.pending_exec if e["id"] == group["id"])
        self.pending_exec = remaining
        self.checkpoint()
        self.last_flush = time.monotonic()
        return accepted

    def record_event(self, raw):
        event = selected_event(raw)
        key = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        if key not in self.seen and self.include(raw):
            action = routine_exec(event) if self.config.get("compact_exec_events", True) else None
            if action:
                # exec_create/start Action may embed arguments. Never persist those.
                event["action"] = action
                compacted = self.spool.redactor.clean(event)
                # Keep the checkpoint below the reader's 2 MiB bound even when
                # labels or exact-string redaction expand a selected event.
                if len(json.dumps(compacted).encode()) > 4096:
                    action = None
            if action and len(self.pending_exec) >= 256:
                self.flush_exec()
            if action and len(self.pending_exec) < 256:
                self.pending_exec.append(compacted)
            elif not self.spool.append("docker_event", event):
                # The spool records its own cap notice. Do not retain unbounded
                # backlog or claim that this individual event was captured.
                pass
            self.seen[key] = None
            if len(self.seen) > 512:
                self.seen.popitem(last=False)
        self.cursor = max(self.cursor, int(event.get("time") or self.cursor))
        self.checkpoint()
        if time.monotonic() - self.last_flush >= 60 or len(self.pending_exec) >= 256:
            self.flush_exec()

    def include(self, raw):
        attrs = raw.get("Actor", {}).get("Attributes", {})
        name = attrs.get("name", "").lstrip("/")
        include = self.config.get("include_containers", [])
        return (attrs.get("homelab-health.exclude") != "true"
                and not any(fnmatch.fnmatch(name, p) for p in self.config.get("exclude_containers", []))
                and (not include or any(fnmatch.fnmatch(name, p) for p in include)))

    def run(self):
        try:
            self.restore()
            self.flush_exec()
        except (OSError, ValueError, TypeError, KeyError):
            self.spool.append("event_connection_gap", {"error": "event_checkpoint_unavailable", "replay_may_be_incomplete": True})
            return
        self.spool.append("event_coverage", {"note": "Live collection begins here. Reconnect replay is limited by Docker's retained event buffer (last 256 events); gaps cannot be ruled out. Routine exec activity may be compacted with original identities and nanosecond timestamps.", "requested_since_epoch": self.cursor})
        while not self.stop.is_set():
            try:
                url = self.docker.url(self.docker.api_path("/events"), {"since": int(self.cursor) - 1, "filters": json.dumps({"type": ["container"]})})
                with self.docker.opener.open(url, timeout=70) as response:
                    while not self.stop.is_set():
                        line = response.readline(65537)
                        if not line:
                            break
                        if len(line) > 65536:
                            raise ValueError("Event line limit exceeded")
                        raw = json.loads(line)
                        self.record_event(raw)
            except Exception as exc:
                self.spool.append("event_connection_gap", {"error": type(exc).__name__, "replay_may_be_incomplete": True})
            self.flush_exec()
            self.stop.wait(2)
        self.flush_exec()

