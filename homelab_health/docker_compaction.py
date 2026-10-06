"""Lossless Docker field encodings, used only in refs-v2 exported records.

The exporter calls these after redaction. No counters are averaged, no events
are sampled, and the persistent spool and final inspect files are unchanged.
"""
from __future__ import annotations

import json

EXEC_ENCODING = "exec-ns-delta-v1"
IO_ENCODING = "io-rows-v1"
EXEC_ACTIONS = ("exec_create", "exec_start", "exec_die")
IO_KEYS = ("major", "minor", "op", "value")
IO_PATHS = (["blkio_stats", "io_service_bytes_recursive"],
            ["blkio_stats", "io_serviced_recursive"])
METADATA_KEYS = ("id", "name", "created", "image", "image_id", "tty",
                 "compose_project", "compose_service", "log_driver")
MAX_EXEC_PAIRS = 32768
MAX_IO_ROWS = 128


def _bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def eligible(record):
    data = record.get("data")
    if not isinstance(data, dict):
        return False
    kind = record.get("kind")
    if kind == "docker_exec_summary":
        return isinstance(data.get("events"), list)
    if kind == "docker_state":
        # Never repurpose a future/literal field with the same spelling.
        return "_metadata" not in data
    return kind == "docker_stats_table" and data.get("encoding") == "dict-columns-v1"


def pack_exec(pairs):
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_EXEC_PAIRS:
        return pairs
    if any(not isinstance(pair, (list, tuple)) or len(pair) != 2
           or pair[0] not in EXEC_ACTIONS or type(pair[1]) is not int
           or not 0 < pair[1] < 2**64 for pair in pairs):
        return pairs
    base = pairs[0][1]
    result = {"encoding": EXEC_ENCODING, "base": base,
              "pairs": [[EXEC_ACTIONS.index(action), at - base] for action, at in pairs]}
    return result if len(_bytes(result)) < len(_bytes(pairs)) else pairs


def _unpack_exec(value, max_bytes):
    if (not isinstance(value, dict) or set(value) != {"encoding", "base", "pairs"}
            or value["encoding"] != EXEC_ENCODING or type(value["base"]) is not int
            or not 0 < value["base"] < 2**64 or not isinstance(value["pairs"], list)
            or not 1 <= len(value["pairs"]) <= MAX_EXEC_PAIRS):
        raise ValueError("Invalid exec delta encoding")
    size = 2
    for pair in value["pairs"]:
        if (not isinstance(pair, list) or len(pair) != 2 or type(pair[0]) is not int
                or not 0 <= pair[0] < len(EXEC_ACTIONS) or type(pair[1]) is not int
                or not 0 < value["base"] + pair[1] < 2**64):
            raise ValueError("Invalid exec delta pair")
        size += len(_bytes([EXEC_ACTIONS[pair[0]], value["base"] + pair[1]])) + (size > 2)
        if size > max_bytes:
            raise ValueError("Decoded exec byte limit")
    return [[EXEC_ACTIONS[action], value["base"] + offset] for action, offset in value["pairs"]]


def _pack_io(value):
    if isinstance(value, dict):
        # A future/literal dictionary must not resemble our encoded wrapper.
        return {"literal": value}
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_IO_ROWS
            or any(not isinstance(row, dict) or set(row) != set(IO_KEYS) for row in value)):
        return value
    result = {"encoding": IO_ENCODING, "rows": [[row[k] for k in IO_KEYS] for row in value]}
    return result if len(_bytes(result)) < len(_bytes(value)) else value


def _unpack_io(value, max_bytes):
    if isinstance(value, dict) and set(value) == {"literal"}:
        if not isinstance(value["literal"], dict) or len(_bytes(value["literal"])) > max_bytes:
            raise ValueError("Invalid literal I/O dictionary")
        return value["literal"]
    if (not isinstance(value, dict) or set(value) != {"encoding", "rows"}
            or value["encoding"] != IO_ENCODING or not isinstance(value["rows"], list)
            or not 1 <= len(value["rows"]) <= MAX_IO_ROWS):
        raise ValueError("Invalid I/O row encoding")
    size = 2
    for row in value["rows"]:
        if not isinstance(row, list) or len(row) != len(IO_KEYS):
            raise ValueError("Invalid I/O row width")
        size += len(_bytes(dict(zip(IO_KEYS, row)))) + (size > 2)
        if size > max_bytes:
            raise ValueError("Decoded I/O byte limit")
    return [dict(zip(IO_KEYS, row)) for row in value["rows"]]


def _io_cells(data):
    tables = data.get("tables")
    if not isinstance(tables, list) or not 1 <= len(tables) <= 128:
        raise ValueError("Invalid Docker table groups")
    for table in tables:
        if not isinstance(table, dict):
            raise ValueError("Invalid Docker table")
        columns, rows = table.get("columns"), table.get("rows")
        if (not isinstance(columns, list) or not 1 <= len(columns) <= 128
                or not isinstance(rows, list) or not 1 <= len(rows) <= 128
                or any(not isinstance(row, list) or len(row) != len(columns) for row in rows)):
            raise ValueError("Invalid Docker table rows")
        for index, path in enumerate(columns):
            if path in IO_PATHS:
                for row in rows:
                    yield row, index


def pack_fields(record):
    """Mutate the caller's private copy; report whether any fields changed."""
    data, kind = record["data"], record["kind"]
    changed = False
    if kind == "docker_exec_summary":
        pairs = data["events"]
        packed = pack_exec(pairs)
        if packed is not pairs:
            data["events"] = packed
            changed = True
    elif kind == "docker_stats_table":
        for parent, key in _io_cells(data):
            value = parent[key]
            packed = _pack_io(value)
            if packed is not value:
                parent[key] = packed
                changed = True
    elif kind == "docker_state":
        metadata = {key: data[key] for key in METADATA_KEYS if key in data}
        if len(_bytes(metadata)) >= 128:
            for key in metadata:
                del data[key]
            data["_metadata"] = metadata
            changed = True
    return changed


def unpack_fields(record, budget):
    """Expand only v2's explicit fields, checking growth before allocation."""
    data, kind = record.get("data"), record.get("kind")
    if not isinstance(data, dict):
        return False
    size = len(_bytes(record)) + 1
    changed = False
    def replace(parent, key, unpack):
        nonlocal size, changed
        old_size = len(_bytes(parent[key]))
        restored = unpack(parent[key], budget - size + old_size)
        size += len(_bytes(restored)) - old_size
        parent[key] = restored
        changed = True
    if kind == "docker_exec_summary" and isinstance(data.get("events"), dict):
        replace(data, "events", _unpack_exec)
    elif kind == "docker_stats_table" and data.get("encoding") == "dict-columns-v1":
        for parent, key in _io_cells(data):
            if isinstance(parent[key], dict):
                replace(parent, key, _unpack_io)
    elif kind == "docker_state" and "_metadata" in data:
        metadata = data["_metadata"]
        if (not isinstance(metadata, dict) or not metadata
                or any(key not in METADATA_KEYS or key in data for key in metadata)):
            raise ValueError("Invalid Docker state metadata")
        del data["_metadata"]
        data.update(metadata)
        changed = True
    return changed
