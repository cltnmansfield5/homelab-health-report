"""Compact only known repetition, retaining identities and original timestamps."""
from __future__ import annotations

import hashlib
import json
import re


def journal_identity(row):
    # A cursor is globally unique. The fallback includes the original message and boot.
    value = row.get("__CURSOR") or [row.get("_BOOT_ID"), row.get("__REALTIME_TIMESTAMP"),
                                    row.get("_SYSTEMD_UNIT"), row.get("MESSAGE")]
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def compact_journal(rows):
    """Only the known docker-default/tokio ptrace-read denial is summarized.

    Occurrences retain [identity hash, original microsecond timestamp]. This lets
    consumers count a union across overlapping exports, rather than sum counts.
    PID stays in the signature so separate emitting processes are not conflated.
    """
    kept, groups, seen = [], {}, set()
    duplicates = 0
    for row in rows:
        identity = journal_identity(row)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        message = row.get("MESSAGE", "")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', message)) if isinstance(message, str) else {}
        expected = {"apparmor": "DENIED", "operation": "ptrace", "profile": "docker-default",
                    "comm": "tokio-rt-worker", "requested_mask": "read", "denied_mask": "read",
                    "peer": "unconfined"}
        if (not all(fields.get(k) == v for k, v in expected.items())
                or str(row.get("PRIORITY", "6")) not in ("4", "5", "6", "7")
                or not row.get("_BOOT_ID") or not str(row.get("__REALTIME_TIMESTAMP", "")).isdigit()):
            kept.append(row)
            continue
        # Preserve all remaining message content in the signature: new fields,
        # access masks, targets or errors must never be folded into another group.
        signature = re.sub(r'audit\([0-9.]+:[0-9]+\)', 'audit(<sequence>)', message)
        key = (row["_BOOT_ID"], row.get("PRIORITY"), signature)
        if key not in groups:
            if len(groups) >= 128:
                kept.append(row)
                continue
            groups[key] = {"kind": "apparmor_ptrace_read", "signature": signature,
                           "example": row, "occurrences": []}
        groups[key]["occurrences"].append([identity, row["__REALTIME_TIMESTAMP"]])
    summaries = []
    for group in groups.values():
        if len(group["occurrences"]) == 1:
            kept.append(group["example"])
            continue
        group["occurrences"].sort(key=lambda pair: (int(pair[1]), pair[0]))
        group["count"] = len(group["occurrences"])
        group["first_realtime_timestamp"] = group["occurrences"][0][1]
        group["last_realtime_timestamp"] = group["occurrences"][-1][1]
        summaries.append(group)
    return kept, summaries, duplicates


def routine_exec(event):
    action = str(event.get("action", "")).split(":", 1)[0]
    # Missing/unknown/nonzero exit status is always retained as an individual event.
    safe = action in ("exec_create", "exec_start") or (
        action == "exec_die" and str(event.get("attributes", {}).get("exitCode")) == "0")
    return (action if safe and event.get("id") and type(event.get("timeNano")) is int
            and event["timeNano"] > 0 else None)


def compact_exec(events):
    """Group routine events by container; retain every action/timeNano pair."""
    groups = {}
    for event in events:
        group = groups.setdefault(event["id"], {"id": event["id"],
            "attributes": {k: v for k, v in event.get("attributes", {}).items() if k != "exitCode"},
            "events": []})
        group["events"].append([event["action"], event["timeNano"]])
    for group in groups.values():
        group["events"] = sorted(set(map(tuple, group["events"])), key=lambda pair: (pair[1], pair[0]))
        group["count"] = len(group["events"])
        group["first_time_nano"] = group["events"][0][1]
        group["last_time_nano"] = group["events"][-1][1]
    return list(groups.values())
