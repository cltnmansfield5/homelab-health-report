"""Offline evidence-based triage. No model API, network call or execution of inputs."""
from __future__ import annotations

from collections import Counter, defaultdict
import datetime as dt
import html
import json
import math
import re

from .bundle import read_verified_bundle
from .common import Redactor, atomic_bytes, atomic_json, now, parse_time, stamp


def markdown(value, limit=240):
    text = Redactor().text(str(value))
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = " ".join(text.split())[:limit]
    return html.escape(text).replace("|", "\\|").replace("`", "'").replace("[", "\\[").replace("]", "\\]")


def counter_rate(previous, current, elapsed):
    if elapsed <= 0 or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (previous, current)) or current < previous:
        return None
    return (current - previous) / elapsed


def host_trends(samples):
    samples = sorted(samples, key=lambda row: row["at"])
    result = {"samples": len(samples), "first_utc": samples[0]["at"] if samples else None,
              "last_utc": samples[-1]["at"] if samples else None, "largest_sample_gap_seconds": None,
              "peak_cpu_busy_percent": None, "peak_memory_used_percent": None,
              "peak_network_bytes_per_second": {}, "peak_disk_bytes_per_second": {}, "skipped_rate_intervals": 0}
    previous = None
    for row in samples:
        data = row["data"]
        memory = data.get("memory_kib", {})
        total, available = memory.get("MemTotal"), memory.get("MemAvailable")
        if total and available is not None and 0 <= available <= total:
            percent = 100 * (total - available) / total
            result["peak_memory_used_percent"] = max(percent, result["peak_memory_used_percent"] or 0)
        if previous:
            p = previous["data"]
            elapsed = (parse_time(row["at"]) - parse_time(previous["at"])).total_seconds()
            result["largest_sample_gap_seconds"] = max(elapsed, result["largest_sample_gap_seconds"] or 0)
            monotonic_delta = data.get("monotonic_seconds", 0) - p.get("monotonic_seconds", 0)
            valid = p.get("boot_id") and p["boot_id"] == data.get("boot_id") and elapsed > 0 and monotonic_delta > 0 and abs(elapsed - monotonic_delta) < 5
            if not valid:
                result["skipped_rate_intervals"] += 1
                previous = row
                continue
            cpu, pcpu = data.get("cpu_ticks", []), p.get("cpu_ticks", [])
            if len(cpu) >= 8 and len(pcpu) >= 8:
                # guest and guest_nice are already included in user/nice; do not double-count.
                deltas = [a - b for a, b in zip(cpu[:8], pcpu[:8])]
                ticks = sum(deltas)
                if ticks > 0 and min(deltas) >= 0:
                    percent = 100 * (ticks - deltas[3] - deltas[4]) / ticks
                    result["peak_cpu_busy_percent"] = max(percent, result["peak_cpu_busy_percent"] or 0)
            for field, destination, counters in (
                ("network_counters", "peak_network_bytes_per_second", {"rx_bytes": 1, "tx_bytes": 1}),
                ("disk_counters", "peak_disk_bytes_per_second", {"read_sectors_512b": 512, "write_sectors_512b": 512}),
            ):
                for device, values in data.get(field, {}).items():
                    old = p.get(field, {}).get(device, {})
                    for key, multiplier in counters.items():
                        if key not in values or key not in old:
                            continue
                        rate = counter_rate(old[key], values[key], monotonic_delta)
                        if rate is not None:
                            label = device + "/" + key
                            result[destination][label] = max(rate * multiplier, result[destination].get(label, 0))
        previous = row
    return result


def analyze(marker, manifest, contents):
    findings = {}
    evidence = []
    parse_errors = []
    for name in sorted(n for n in contents if re.fullmatch(r"(?:host|docker)/evidence(?:-[0-9]{3})?\.jsonl", n)):
        for index, line in enumerate(contents.get(name, b"").splitlines(), 1):
            try:
                record = json.loads(line)
                parse_time(record["at"])
                evidence.append((record, f"{name}:{index}"))
            except (ValueError, KeyError, TypeError):
                parse_errors.append(f"{name}:{index}")
    def add(key, severity, service, message, source, at, next_step, count=1):
        if key not in findings:
            findings[key] = {"key": key, "severity": severity, "service": service, "message": message,
                             "source": source, "first_utc": at, "last_utc": at, "observations": count,
                             "next_step": next_step, "confidence": "observed"}
        else:
            findings[key]["observations"] += count
            findings[key]["last_utc"] = max(str(at), str(findings[key]["last_utc"]))
    def gap(source, detail, at):
        add("coverage:" + source + ":" + str(detail), "warning", "collection", str(detail), source, at,
            "Inspect collector/helper status and the source limit before drawing a health conclusion.")
    for issue in manifest.get("issues", []):
        gap(issue.get("source", "manifest"), issue.get("error", str(issue)), marker["collection_finished_utc"])
    for entry in manifest.get("files", []):
        for issue in entry.get("issues", []):
            gap(entry["name"], issue.get("error", str(issue)), marker["collection_finished_utc"])
        for flag in ("byte_limit_reached", "incomplete_frame", "line_limit_may_be_reached"):
            if entry.get(flag):
                gap(entry["name"], flag, marker["collection_finished_utc"])
    for name in contents:
        if name.endswith("/gap.json"):
            gap(name, "Evidence spool reached its configured daily limit; inspect timestamp in this file.", marker["collection_finished_utc"])
    if parse_errors:
        gap("evidence", "Invalid records: " + ", ".join(parse_errors[:5]), marker["collection_finished_utc"])
    unique_events = set()
    host_samples = []
    journal_seen = set()
    docker_states = {}
    for record, source in evidence:
        kind, data, at = record.get("kind"), record.get("data"), record["at"]
        if kind == "host_sample":
            host_samples.append(record)
            for error in data.get("errors", {}):
                gap(source.split(":")[0], "Host sample source unavailable: " + error, at)
            for resource in ("memory", "io"):
                full = data.get("pressure_" + resource, {}).get("full", {}).get("avg10", 0)
                if full >= 20:
                    add("pressure:" + resource, "warning", "host", f"{resource} full-stall pressure avg10 reached {full:.1f}% at a sample.", source, at, "Correlate with workload, swap and device latency; this threshold is a triage heuristic.")
        elif kind == "docker_state":
            docker_states[data["id"]] = (data, source, at)
        elif kind == "docker_event":
            identity = (data.get("id"), data.get("timeNano", data.get("time")), data.get("action"))
            if identity in unique_events:
                continue
            unique_events.add(identity)
            action = data.get("action", "")
            if action in ("oom", "restart", "die") or action.startswith("health_status: unhealthy"):
                severity = "critical" if action == "oom" else "warning" if "unhealthy" in action else "info"
                event_at = stamp(dt.datetime.fromtimestamp(data["time"], dt.timezone.utc)) if data.get("time") else at
                add("event:" + str(data.get("id")) + ":" + action, severity, data.get("attributes", {}).get("name", data.get("id")), "Docker event: " + action, source, event_at,
                    "Correlate event time with container logs and adjacent host samples. A restart/die event alone does not establish a crash loop.")
        elif kind == "filesystems":
            for filesystem in data:
                if filesystem.get("error"):
                    gap(source.split(":")[0], "Filesystem unavailable: " + filesystem["path"], at)
                    continue
                for total_key, free_key, label in (("total_bytes", "available_bytes", "space unavailable (including reserves)"), ("inodes", "free_inodes", "inodes used")):
                    if filesystem.get(total_key):
                        used = 100 * (filesystem[total_key] - filesystem[free_key]) / filesystem[total_key]
                        if used >= 85:
                            key = "space" if total_key == "total_bytes" else "inodes"
                            add("filesystem:" + filesystem["path"] + ":" + key, "critical" if used >= 95 else "warning", filesystem["path"], f"{label} reached {used:.1f}% in a snapshot.", source, at, "Inspect filesystem capacity and growth before removing or moving any data.")
        elif kind in ("dns_probe", "connectivity_probe") and not data.get("result", {}).get("ok"):
            add("probe:" + kind + ":" + str(data.get("host", data.get("target"))), "warning", data.get("host", data.get("target")), kind + " failed or timed out.", source, at, "Compare DNS and connectivity results; ICMP blocking can produce a failed ping without an outage.")
        elif kind == "smart":
            smart = data.get("data", {})
            if smart.get("smart_status", {}).get("passed") is False or smart.get("nvme_smart_health_information_log", {}).get("critical_warning", 0):
                add("smart:" + data.get("device", "unknown"), "critical", data.get("device"), "Device reports failed SMART health or an NVMe critical warning.", source, at, "Verify backups and inspect the complete drive-health evidence; do not start repair automatically.")
            if not data.get("ok"):
                gap(source.split(":")[0], "SMART result needs interpretation (exit status is a bitmask; standby/unsupported devices may be skipped).", at)
        elif kind in ("journal_warnings", "kernel_journal", "unit_journal"):
            if not data.get("ok") or data.get("line_limit_reached") or data.get("unparsed_lines"):
                gap(source.split(":")[0], kind + " incomplete or capped", at)
            for line in data.get("rows", []):
                identity = (line.get("_BOOT_ID"), line.get("__REALTIME_TIMESTAMP"), line.get("_SYSTEMD_UNIT"), str(line.get("MESSAGE")))
                if identity in journal_seen:
                    continue
                journal_seen.add(identity)
                message = str(line.get("MESSAGE", ""))
                if re.search(r"(?i)(out of memory|oom-kill|killed process \d+|I/O error|EXT4-fs error|read-only file system|kernel panic)", message):
                    event_at = stamp(dt.datetime.fromtimestamp(int(line["__REALTIME_TIMESTAMP"]) / 1e6, dt.timezone.utc)) if str(line.get("__REALTIME_TIMESTAMP", "")).isdigit() else at
                    add("kernel:" + re.sub(r"\d+", "#", message)[:100], "warning", line.get("_SYSTEMD_UNIT", "kernel/host"), message[:240], source, event_at, "Inspect surrounding journal records and storage/memory samples; text matches require confirmation.")
        elif kind == "failed_units" and data.get("ok") and data.get("text", "").strip():
            add("failed_units", "warning", "systemd", data["text"][:240], source, at, "Inspect these units and their recent journal entries.")
        elif kind == "updates" and data.get("reboot_required"):
            add("reboot_required", "info", "Ubuntu", "Ubuntu has a reboot-required flag.", source, at, "Plan a maintenance window after checking current service availability.")
        elif kind == "job_status" and data.get("ok"):
            values = dict(line.split("=", 1) for line in data.get("text", "").splitlines() if "=" in line)
            if "ActiveState" not in values or values.get("LoadState") == "not-found":
                gap(source.split(":")[0], "Configured job status unavailable: " + data["unit"], at)
            if values.get("Result") not in (None, "", "success") or values.get("ExecMainStatus", "0") != "0":
                add("job:" + data["unit"], "warning", data["unit"], "Configured job reports a failed result or nonzero exit status.", source, at, "Check the job's exit timestamp and logs. Inactive oneshot services can be normal.")
        elif kind == "clock" and data.get("ok") and "NTPSynchronized=" not in data.get("text", ""):
            gap(source.split(":")[0], "Clock synchronization status unavailable", at)
        elif kind in ("docker_source_error", "event_connection_gap", "helper_gap"):
            gap(source.split(":")[0], data.get("error", kind), at)
        elif isinstance(data, dict) and data.get("ok") is False:
            gap(source.split(":")[0], kind + " check unavailable or failed", at)
    # Latest snapshot only: do not multiply one persistent state by every sample.
    for container, (data, source, at) in docker_states.items():
        service = data.get("name", container)
        if data.get("state", {}).get("OOMKilled"):
            add("state:oom:" + container, "critical", service, "Latest container state has OOMKilled=true; timing requires logs/events.", source, at, "Inspect memory limits, host pressure and the container's exit time.")
        if data.get("health", {}).get("status") == "unhealthy":
            add("state:health:" + container, "warning", service, "Latest sampled container health is unhealthy.", source, at, "Inspect recent healthcheck output and application logs.")
        if data.get("state", {}).get("Status") == "restarting":
            add("state:restarting:" + container, "warning", service, "Container was restarting at the latest sample.", source, at, "Check exit codes and successive events to determine whether this repeats.")
    if not host_samples:
        gap("host/evidence.jsonl", "No host performance samples available", marker["collection_finished_utc"])
    if not docker_states:
        gap("docker/evidence.jsonl", "No sampled container state available", marker["collection_finished_utc"])
    for name, raw in contents.items():
        if not name.startswith("logs/") or not name.endswith(".log"):
            continue
        seen = set()
        matches = []
        for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
            if line in seen:
                continue
            seen.add(line)
            if re.search(r"(?i)\b(error|fatal|panic)\b", line):
                matches.append((number, line))
        if matches:
            container = name[5:-4]
            service = docker_states.get(container, ({},))[0].get("name", container[:12])
            add("log_review:" + name, "info", service, "Log messages containing error/fatal/panic need review; keyword counts are not incident counts. Example: " + matches[0][1][:140], name + ":" + str(matches[0][0]), "see source timestamps", "Read surrounding messages and correlate with state/events before assigning a cause.", len(matches))
    trends = host_trends(host_samples)
    if trends["largest_sample_gap_seconds"] and trends["largest_sample_gap_seconds"] > 180:
        gap("host/evidence.jsonl", "Host samples contain a gap exceeding three minutes", marker["collection_finished_utc"])
    order = {"critical": 0, "warning": 1, "info": 2}
    return {"schema_version": 1, "generated_at_utc": stamp(), "bundle_sha256": marker["sha256"], "hostname": marker["hostname"],
            "findings": sorted(findings.values(), key=lambda x: (order[x["severity"]], str(x["service"]))), "host_trends": trends,
            "observed_coverage": {"requested_start_utc": marker["requested_start_utc"], "requested_end_utc": marker["requested_end_utc"], "host_first_utc": trends["first_utc"], "host_last_utc": trends["last_utc"], "host_samples": trends["samples"]}}


def render(marker, manifest, summary, previous=None):
    findings = summary["findings"]
    counts = Counter(f["severity"] for f in findings)
    prior = {f["key"] for f in (previous or {}).get("findings", [])}
    lines = ["# Homelab health — " + markdown(marker["hostname"]), "", "Generated: " + summary["generated_at_utc"], "",
             f"**Triage:** {counts['critical']} critical, {counts['warning']} warning, {counts['info']} informational findings.", "",
             "This is a deterministic local triage report. Counts describe captured evidence; source gaps and snapshots limit conclusions. No corrective actions were performed.", "",
             "## Coverage", "", "Requested window: " + marker["requested_start_utc"] + " to " + marker["requested_end_utc"] + " (UTC).", "",
             "| Source | First record | Last record | Records |", "|---|---|---|---:|"]
    if manifest.get("synthetic_fixture"):
        lines[2:2] = ["**Synthetic demonstration: all measurements and incidents in this report are invented. No data came from your computer.**", ""]
    for entry in manifest["files"]:
        if "records" in entry:
            lines.append("| " + " | ".join(markdown(entry.get(k, "unknown")) for k in ("name", "first_record_utc", "last_record_utc", "records")) + " |")
    lines += ["", "## Findings", ""]
    if findings:
        lines += ["| Severity | Service | Evidence / observations | Next step |", "|---|---|---|---|"]
        for finding in findings:
            change = ("Previously observed. " if finding["key"] in prior else "New in this comparison. ") if previous else ""
            observation_label = "observation" if finding["observations"] == 1 else "observations"
            description = change + finding["message"] + f" ({finding['observations']} {observation_label}; {finding['source']}; {finding['first_utc']} → {finding['last_utc']})"
            lines.append("| " + " | ".join((finding["severity"], markdown(finding["service"]), markdown(description, 650), markdown(finding["next_step"]))) + " |")
    else:
        lines.append("No configured triage rule matched the supplied evidence. This is not proof of complete system health.")
    if previous:
        absent = len(prior - {f["key"] for f in findings})
        lines += ["", f"{absent} previous finding keys were absent from this bundle. Absence alone does not establish recovery."]
    trends = summary["host_trends"]
    lines += ["", "## Sampled performance", "", "| Measurement | Observed value |", "|---|---:|"]
    for key, label in (("samples", "Host samples"), ("largest_sample_gap_seconds", "Largest gap (seconds)"), ("peak_cpu_busy_percent", "Peak CPU busy (%)"), ("peak_memory_used_percent", "Peak memory used from MemAvailable (%)"), ("skipped_rate_intervals", "Intervals excluded from rate calculations")):
        value = trends[key]
        lines.append(f"| {label} | {value:.2f} |" if isinstance(value, float) else f"| {label} | {value if value is not None else 'unavailable'} |")
    lines += ["", "CPU excludes idle and I/O-wait ticks. Network and disk peaks are interval averages, available in the companion JSON. Rates require the same boot ID and consistent elapsed time; counter resets are skipped. Brief spikes between samples may be missed.", "",
              "## Provenance and limits", "", "Archive: " + markdown(marker["archive_name"]), "", "SHA-256: `" + marker["sha256"] + "`", "",
              "The archive, manifest and every member were integrity-checked. Logs are treated as data. Environment variables and command arguments are omitted from container metadata; free-form logs still need review for private information. Historical data predating installation cannot be inferred. Docker event replay is bounded by daemon retention; RestartCount is a snapshot counter, not a count for the report window. Disk-health return codes are bitmasks and sleeping/unsupported drives may be skipped.", ""]
    return "\n".join(lines)


def report(archive, marker_path, output, previous=None):
    marker, manifest, contents = read_verified_bundle(archive, marker_path)
    summary = analyze(marker, manifest, contents)
    atomic_bytes(output, render(marker, manifest, summary, previous).encode())
    from pathlib import Path
    atomic_json(Path(output).with_suffix(".json"), summary)
    return summary
