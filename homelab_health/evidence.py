"""Lossless export-only encoding. References never cross evidence member boundaries.

Raw spools remain unchanged. Use a new encoder/decoder for each JSONL member;
never seed either with state from another bundle. Decode only trusted project
code, not executable content from an archive.
"""
from __future__ import annotations

import base64
import copy
import json
import re

from .common import MIB

ENCODING = "refs-v1"
OCCURRENCES = "sha256-b64-us-delta-v1"
MAX_RECORD_BYTES = 2 * MIB
MAX_DICTIONARY_BYTES = 8 * MIB
MAX_DEFINITIONS = 4096
MAX_OCCURRENCES = 32768
MAX_DECODED_MEMBER_BYTES = 64 * MIB
MAX_DECODED_SOURCE_BYTES = 128 * MIB
MAX_DECODED_BUNDLE_BYTES = 2 * MAX_DECODED_SOURCE_BYTES


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _pack_occurrences(pairs):
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_OCCURRENCES:
        return pairs
    for pair in pairs:
        if (not isinstance(pair, list) or len(pair) != 2
                or not isinstance(pair[0], str) or not re.fullmatch(r"[0-9a-f]{64}", pair[0])
                or not isinstance(pair[1], str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", pair[1])
                or int(pair[1]) >= 2**64):
            return pairs
    base = int(pairs[0][1])
    result = {"encoding": OCCURRENCES, "base": pairs[0][1],
              "pairs": [[base64.b64encode(bytes.fromhex(identity)).decode("ascii"), int(at) - base]
                        for identity, at in pairs]}
    return result if len(json_bytes(result)) < len(json_bytes(pairs)) else pairs


def _unpack_occurrences(value, max_bytes=MAX_RECORD_BYTES):
    if isinstance(value, list):
        return value
    if (not isinstance(value, dict) or set(value) != {"encoding", "base", "pairs"}
            or value["encoding"] != OCCURRENCES
            or not isinstance(value["base"], str)
            or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value["base"])
            or int(value["base"]) >= 2**64
            or not isinstance(value["pairs"], list) or not 1 <= len(value["pairs"]) <= MAX_OCCURRENCES):
        raise ValueError("Invalid occurrence encoding")
    base = int(value["base"])
    result = []
    size = 2
    for pair in value["pairs"]:
        if (not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str)
                or len(pair[0]) != 44 or type(pair[1]) is not int or not 0 <= base + pair[1] < 2**64):
            raise ValueError("Invalid occurrence pair")
        try:
            identity = base64.b64decode(pair[0], validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid occurrence identity") from exc
        if len(identity) != 32 or base64.b64encode(identity).decode("ascii") != pair[0]:
            raise ValueError("Noncanonical occurrence identity")
        timestamp = str(base + pair[1])
        size += 71 + len(timestamp) + bool(result)
        if size > max_bytes:
            raise ValueError("Decoded occurrence byte limit")
        result.append([identity.hex(), timestamp])
    return result


def _slots(record):
    """Only explicit known fields are eligible; never interpret arbitrary data."""
    kind, data = record.get("kind"), record.get("data")
    if not isinstance(data, dict):
        return []
    if kind in ("mounts", "dns_state", "routes") and "text" in data:
        return [(kind + ".text", data, "text", str)]
    if kind == "docker_exec_summary" and "attributes" in data:
        return [("exec.attributes", data, "attributes", dict)]
    if (kind == "docker_stats_table" and data.get("encoding") == "dict-columns-v1"
            and isinstance(data.get("tables"), list)):
        return [("stats.columns", table, "columns", list) for table in data["tables"]
                if isinstance(table, dict) and "columns" in table]
    return []


class EvidenceEncoder:
    def __init__(self):
        self.values = {}
        self.bytes = 0

    def encode(self, record):
        if "export_encoding" in record:
            raise ValueError("Already encoded evidence cannot be re-encoded as raw spool data")
        result = copy.deepcopy(record)
        changed = False
        pending = {}
        pending_bytes = 0
        # Validate the complete candidate before creating any definitions.
        slots = _slots(result)
        if any(not isinstance(parent[key], kind) for _, parent, key, kind in slots):
            return record
        for namespace, parent, key, _ in slots:
            value = parent[key]
            raw = json_bytes(value)
            identity = (namespace, raw)
            if identity in self.values or identity in pending:
                parent[key] = {"ref": self.values.get(identity, pending.get(identity))}
                changed = True
            elif (len(raw) >= 128 and len(self.values) + len(pending) < MAX_DEFINITIONS
                  and self.bytes + pending_bytes + len(raw) <= MAX_DICTIONARY_BYTES):
                index = len(self.values) + len(pending)
                pending[identity] = index
                pending_bytes += len(raw)
                parent[key] = {"define": index, "value": value}
                changed = True
        if result.get("kind") in ("journal_warnings", "kernel_journal", "unit_journal"):
            data = result.get("data")
            if isinstance(data, dict) and isinstance(data.get("summaries"), list):
                for summary in data["summaries"]:
                    if isinstance(summary, dict) and "occurrences" in summary:
                        pairs = summary["occurrences"]
                        packed = _pack_occurrences(pairs)
                        if packed is not pairs:
                            summary["occurrences"] = packed
                            changed = True
        if changed:
            result["export_encoding"] = ENCODING
            if len(json_bytes(result)) + 1 > MAX_RECORD_BYTES:
                return record
            self.values.update(pending)
            self.bytes += pending_bytes
        return result


class EvidenceDecoder:
    def __init__(self, max_decoded_bytes=MAX_DECODED_MEMBER_BYTES):
        self.values = {}
        self.dictionary_bytes = 0
        self.decoded_bytes = 0
        self.max_decoded_bytes = max_decoded_bytes
        self.failed = False

    def decode(self, record):
        """Reject malformed encoded members without retaining partial definitions.

        After an encoded record is invalid, later encoded records in this member
        are rejected too: a missing definition must not silently change meaning.
        Legacy records remain independently readable; the next member resets state.
        """
        if not isinstance(record, dict):
            raise ValueError("Evidence record must be an object")
        encoded = "export_encoding" in record
        try:
            record_bytes = len(json_bytes(record))
            if record_bytes + 1 > MAX_RECORD_BYTES:
                raise ValueError("Encoded record byte limit")
            if not encoded:
                result = record
            else:
                if self.failed:
                    raise ValueError("Encoded member is incomplete")
                if record["export_encoding"] != ENCODING:
                    raise ValueError("Unsupported evidence encoding")
                result = copy.deepcopy(record)
                del result["export_encoding"]
                pending = {}
                pending_bytes = 0
                changed = False
                projected = len(json_bytes(result)) + 1
                budget = min(MAX_RECORD_BYTES, self.max_decoded_bytes - self.decoded_bytes)
                if (result.get("kind") == "docker_stats_table"
                        and isinstance(result.get("data"), dict)
                        and isinstance(result["data"].get("tables"), list)
                        and len(result["data"]["tables"]) > 128):
                    raise ValueError("Encoded table group limit")
                replacements = []
                for namespace, parent, key, expected in _slots(result):
                    value = parent[key]
                    # Lists/strings remain literal if too small or dictionary is full.
                    if expected is not dict and isinstance(value, expected):
                        continue
                    # Exec attributes in an encoded exec record are always a reference.
                    if not isinstance(value, dict):
                        raise ValueError("Invalid value reference")
                    if set(value) == {"define", "value"}:
                        index = value["define"]
                        literal = value["value"]
                        if (type(index) is not int or index != len(self.values) + len(pending)
                                or index >= MAX_DEFINITIONS or not isinstance(literal, expected)):
                            raise ValueError("Invalid reference definition")
                        size = len(json_bytes(literal))
                        pending_bytes += size
                        if self.dictionary_bytes + pending_bytes > MAX_DICTIONARY_BYTES:
                            raise ValueError("Reference dictionary byte limit")
                        pending[index] = (namespace, literal)
                    elif set(value) == {"ref"} and type(value["ref"]) is int:
                        found = pending.get(value["ref"], self.values.get(value["ref"]))
                        if found is None or found[0] != namespace:
                            raise ValueError("Missing or wrong-namespace reference")
                        literal = found[1]
                    else:
                        raise ValueError("Invalid value reference")
                    # Size all replacements first: later definitions remove wrapper
                    # bytes that can offset an earlier reference at an exact limit.
                    projected += len(json_bytes(literal)) - len(json_bytes(value))
                    replacements.append((parent, key, literal))
                    changed = True
                if projected > budget:
                    raise ValueError("Decoded evidence byte limit")
                for parent, key, literal in replacements:
                    parent[key] = copy.deepcopy(literal)
                if result.get("kind") in ("journal_warnings", "kernel_journal", "unit_journal"):
                    data = result.get("data")
                    if isinstance(data, dict) and isinstance(data.get("summaries"), list):
                        for summary in data["summaries"]:
                            if isinstance(summary, dict) and "occurrences" in summary:
                                value = summary["occurrences"]
                                if not isinstance(value, list):
                                    available = budget - projected + len(json_bytes(value))
                                    pairs = _unpack_occurrences(value, max_bytes=available)
                                    projected += len(json_bytes(pairs)) - len(json_bytes(value))
                                    if projected > budget:
                                        raise ValueError("Decoded evidence byte limit")
                                    summary["occurrences"] = pairs
                                    changed = True
                if not changed:
                    raise ValueError("Encoded record has no encoded fields")
            size = len(json_bytes(result)) + 1
            if size > MAX_RECORD_BYTES or self.decoded_bytes + size > self.max_decoded_bytes:
                raise ValueError("Decoded evidence byte limit")
            if encoded:
                self.values.update(pending)
                self.dictionary_bytes += pending_bytes
            self.decoded_bytes += size
            return result
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            if encoded:
                self.failed = True
            raise
