#!/usr/bin/env python3
"""Verify/replay a local bundle through the actual export path; print aggregates only.

No network, live service changes or diagnostic payloads are printed. Temporary
spools are removed when the replay exits. Missing source tails cannot be rebuilt.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from homelab_health.bundle import read_verified_bundle, spool_chunks
from homelab_health.common import MIB, parse_time
from homelab_health.evidence import EvidenceDecoder, json_bytes
from homelab_health.report import analyze
from homelab_health.tables import unpack_stats


def canonical_bytes(value):
    # JSON object key order is immaterial; list/record order and every value are
    # checked unchanged. Metadata factoring can move dictionary keys on decode.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode()


def archive_size(contents):
    """Identical gzip/tar settings for both sides; includes updated manifest hashes."""
    manifest = json.loads(contents["manifest.json"])
    old = {entry["name"]: entry for entry in manifest["files"]}
    manifest["files"] = []
    for name, raw in sorted(contents.items()):
        if name == "manifest.json":
            continue
        entry = {**old.get(name, {}), "name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        manifest["files"].append(entry)
    with tempfile.TemporaryFile() as output:
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as tar:
                import io
                for name, raw in sorted({**contents, "manifest.json": json_bytes(manifest)}.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(raw); info.mode = 0o640
                    tar.addfile(info, io.BytesIO(raw))
        return output.tell()


def benchmark(marker, manifest, contents, *, docker_fields=False):
    began = time.monotonic()
    rewritten = dict(contents)
    results, totals = {}, Counter()
    start, end = parse_time(marker["requested_start_utc"]), parse_time(marker["requested_end_utc"])
    for domain in ("host", "docker"):
        names = sorted(name for name in contents if re.fullmatch(domain + r"/evidence(?:-[0-9]{3})?\.jsonl", name))
        before = sum(len(contents[n]) for n in names)
        before_kinds, after_kinds = Counter(), Counter()
        for name in names:
            for line in contents[name].splitlines():
                before_kinds[json.loads(line)["kind"]] += len(line) + 1
        with tempfile.TemporaryDirectory(prefix="hh-export-replay-") as root:
            counts = Counter()
            expected_digest = hashlib.sha256()
            raw_bytes = 0
            for name in names:
                decoder = EvidenceDecoder()
                for line in contents[name].splitlines():
                    record = decoder.decode(json.loads(line))
                    clean = json_bytes(record) + b"\n"
                    raw_bytes += len(clean)
                    with (Path(root) / (parse_time(record["at"]).date().isoformat() + ".jsonl")).open("ab") as spool:
                        spool.write(clean)
                    expected_digest.update(canonical_bytes(record) + b"\n")
                    counts["records"] += 1
                    data = record.get("data", {})
                    if record.get("kind") == "docker_stats_table": counts["stats_samples"] += len(unpack_stats(data))
                    if record.get("kind") == "docker_stats": counts["stats_samples"] += 1
                    if record.get("kind") == "docker_exec_summary": counts["exec_tuples"] += len(data["events"])
                    if record.get("kind") in ("kernel_journal", "unit_journal", "journal_warnings"):
                        counts["journal_occurrence_pairs"] += sum(len(g.get("occurrences", [])) for g in data.get("summaries", []))
            chunks, coverage = spool_chunks(root, start, end, 40 * MIB, compact=True,
                compact_docker=docker_fields and domain == "docker")
            if coverage["issues"]:
                raise ValueError("Replay could not retain the complete captured evidence")
            actual_digest = hashlib.sha256()
            restored = 0
            def expected_records():
                for path in sorted(Path(root).glob("*.jsonl")):
                    with path.open("rb") as stream:
                        for line in stream: yield json.loads(line)
            def actual_records():
                for chunk in chunks:
                    decoder = EvidenceDecoder()
                    for line in chunk.splitlines(): yield decoder.decode(json.loads(line))
            for original, recovered in itertools.zip_longest(expected_records(), actual_records()):
                if original != recovered:
                    raise ValueError("Replay changed an evidence record")
                restored += 1
                actual_digest.update(canonical_bytes(recovered) + b"\n")
            if restored != counts["records"] or actual_digest.digest() != expected_digest.digest():
                raise ValueError("Replay changed record count/order/bytes")
            for name in names: del rewritten[name]
            for index, chunk in enumerate(chunks): rewritten[f"{domain}/evidence-{index:03}.jsonl"] = chunk
            after = sum(map(len, chunks))
            for chunk in chunks:
                for line in chunk.splitlines():
                    after_kinds[json.loads(line)["kind"]] += len(line) + 1
            captured_seconds = (parse_time(coverage["last_record_utc"]) - parse_time(coverage["first_record_utc"])).total_seconds() if counts["records"] else 0
            window_seconds = (end - start).total_seconds()
            results[domain] = {"before_bytes": before, "after_bytes": after,
                "saved_bytes": before - after, "reduction_percent": round(100 * (1 - after / before), 4) if before else None,
                "raw_spool_bytes": raw_bytes, "bytes_by_kind_before": dict(before_kinds),
                "bytes_by_kind_after": dict(after_kinds),
                "first_record_utc": coverage["first_record_utc"], "last_record_utc": coverage["last_record_utc"],
                "captured_seconds": captured_seconds, "requested_window_seconds": window_seconds,
                "projected_requested_window_bytes_at_captured_rate": math.ceil(after * window_seconds / captured_seconds) if captured_seconds > 0 else None,
                "projected_raw_daily_spool_bytes_at_captured_rate": math.ceil(raw_bytes * 86400 / captured_seconds) if captured_seconds > 0 else None,
                "members_before": len(names), "members_after": len(chunks), "exact_record_roundtrip": True, **counts}
            totals.update(counts)
    # Line/member locations change when re-chunking. Compare substantive outcomes
    # with coverage metadata omitted on both sides; retain all raw evidence/logs.
    original_report = analyze(marker, {"files": [], "issues": []}, contents)
    replay_report = analyze(marker, {"files": [], "issues": []}, rewritten)
    for field in ("host_trends", "observed_coverage", "noise_reduction"):
        if original_report[field] != replay_report[field]: raise ValueError("Replay changed reporter output")
    def findings(report):
        return sorted(json.dumps({k: v for k, v in f.items() if k != "source"}, sort_keys=True)
                      for f in report["findings"] if not f["key"].startswith("coverage:"))
    if findings(original_report) != findings(replay_report): raise ValueError("Replay changed reporter findings")
    if any("Invalid records" in f["message"] for f in replay_report["findings"]): raise ValueError("Reporter rejected replay")
    old_gzip, new_gzip = archive_size(contents), archive_size(rewritten)
    return {"domains": results, "totals": dict(totals), "reporter_outcomes_equal": True,
        "normalized_archive_before_bytes": old_gzip, "normalized_archive_after_bytes": new_gzip,
        "normalized_archive_reduction_percent": round(100 * (1 - new_gzip / old_gzip), 4),
        "transport_parts_before": math.ceil(old_gzip / 393216), "transport_parts_after": math.ceil(new_gzip / 393216),
        "elapsed_seconds": round(time.monotonic() - began, 3),
        "limitations": "Retained evidence only; unavailable tails cannot be recovered. Actual 8 MiB member dictionary resets and all encoding overhead included. Gzip figures use identically rebuilt archives, not deployment artifacts. Full-window fit remains unverified."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--docker-fields", action="store_true", help="Replay the opt-in refs-v2 Docker field compaction")
    args = parser.parse_args()
    marker, manifest, contents = read_verified_bundle(args.archive, args.marker)
    print(json.dumps(benchmark(marker, manifest, contents, docker_fields=args.docker_fields), indent=2))
