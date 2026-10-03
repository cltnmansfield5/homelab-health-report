"""Self-contained, lossless tables for one Docker sampling cycle.

Only dictionary keys are factored out. Values (including signs, units, lists,
empty objects, nulls and original Docker read timestamps) are unchanged.
"""
from __future__ import annotations

import json

MAX_ROWS = 128
MAX_COLUMNS = 128
MAX_DEPTH = 8
MAX_BYTES = 1024 * 1024


def _leaves(value, path=()):
    if isinstance(value, dict) and value:
        for key, child in sorted(value.items()):
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("Unsupported table key")
            if len(path) >= MAX_DEPTH:
                raise ValueError("Table nesting limit")
            yield from _leaves(child, path + (key,))
    else:
        yield path, value


def pack_stats(samples):
    if not 1 <= len(samples) <= MAX_ROWS:
        raise ValueError("Table row limit")
    tables = []
    groups = {}
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or not sample:
            raise ValueError("Expected nonempty stats object")
        leaves = list(_leaves(sample))
        columns = [list(path) for path, _ in leaves]
        if len(columns) > MAX_COLUMNS:
            raise ValueError("Table column limit")
        key = tuple(tuple(path) for path in columns)
        if key not in groups:
            groups[key] = {"columns": columns, "rows": [], "indexes": []}
            tables.append(groups[key])
        groups[key]["rows"].append([value for _, value in leaves])
        groups[key]["indexes"].append(index)
    result = {"encoding": "dict-columns-v1", "samples": len(samples), "tables": tables}
    if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_BYTES:
        raise ValueError("Table byte limit")
    return result


def unpack_stats(data):
    """Reject malformed/oversized tables; never guess missing values or counts."""
    if not isinstance(data, dict) or data.get("encoding") != "dict-columns-v1":
        raise ValueError("Unsupported stats encoding")
    count = data.get("samples")
    if type(count) is not int or not 1 <= count <= MAX_ROWS:
        raise ValueError("Table row limit")
    tables = data.get("tables")
    if not isinstance(tables, list) or not 1 <= len(tables) <= MAX_ROWS:
        raise ValueError("Table group limit")
    if len(json.dumps(data, ensure_ascii=False).encode()) > MAX_BYTES:
        raise ValueError("Table byte limit")
    samples = {}
    for table in tables:
        if not isinstance(table, dict):
            raise ValueError("Invalid table")
        columns, rows = table.get("columns"), table.get("rows")
        if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS:
            raise ValueError("Table column limit")
        paths = set()
        for path in columns:
            if (not isinstance(path, list) or not 1 <= len(path) <= MAX_DEPTH
                    or any(not isinstance(k, str) or not k or len(k) > 128 for k in path)):
                raise ValueError("Invalid table path")
            key = tuple(path)
            if key in paths:
                raise ValueError("Duplicate table path")
            paths.add(key)
        if any(path[:n] in paths for path in paths for n in range(1, len(path))):
            raise ValueError("Conflicting table paths")
        if not isinstance(rows, list) or not rows or len(samples) + len(rows) > count:
            raise ValueError("Table count mismatch")
        indexes = table.get("indexes")
        if (not isinstance(indexes, list) or len(indexes) != len(rows)
                or any(type(i) is not int or not 0 <= i < count for i in indexes)):
            raise ValueError("Invalid row indexes")
        for index, row in zip(indexes, rows):
            if index in samples:
                raise ValueError("Duplicate row index")
            if not isinstance(row, list) or len(row) != len(columns):
                raise ValueError("Table row width mismatch")
            result = {}
            for path, value in zip(columns, row):
                parent = result
                for key in path[:-1]:
                    parent = parent.setdefault(key, {})
                parent[path[-1]] = value
            samples[index] = result
    if len(samples) != count:
        raise ValueError("Table count mismatch")
    return [samples[i] for i in range(count)]
