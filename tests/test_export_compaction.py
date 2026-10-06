"""Synthetic export/recovery cases; no real diagnostic data belongs in fixtures."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_health.bundle import spool_chunks, read_verified_bundle
from homelab_health.collector import Collector
from homelab_health.common import MIB, Redactor, stamp
from homelab_health.evidence import EvidenceEncoder, EvidenceDecoder, ENCODING, json_bytes
from homelab_health.report import analyze
from homelab_health.tables import pack_stats, unpack_stats
from tests.fixtures import AT, FakeDocker, sample
from tests.test_compaction_v2 import stat


def row(kind, data, offset=0):
    return {"schema_version": 1, "at": stamp(AT + dt.timedelta(seconds=offset)), "kind": kind, "data": data}


def journal():
    pairs = [[hashlib.sha256(str(n).encode()).hexdigest(), str(2**63 + (7 - n) * 123)] for n in range(20)]
    pairs.append(pairs[3][:])
    return row("kernel_journal", {"ok": True, "rows": [], "summaries": [{
        "kind": "kernel_callback_suppression", "signature": "kauditd_printk_skb: 3 callbacks suppressed",
        "example": {"MESSAGE": "fixture", "__REALTIME_TIMESTAMP": pairs[0][1]},
        "occurrences": pairs, "count": len(pairs)}]})


def spool(root, rows):
    for record in rows:
        with (Path(root) / (record["at"][:10] + ".jsonl")).open("ab") as stream:
            stream.write(json_bytes(record) + b"\n")


def decode_chunks(chunks):
    records = []
    for chunk in chunks:
        decoder = EvidenceDecoder()
        records.extend(decoder.decode(json.loads(line)) for line in chunk.splitlines())
    return records


class EvidenceCodecTests(unittest.TestCase):
    def test_exact_roundtrip_all_shapes_order_unicode_and_large_integers(self):
        stats = [stat(n) for n in range(8)]
        stats[2]["extra"] = {"future": [None, -1, 2**64 - 1]}
        records = [row(k, {"ok": False, "text": "état\n雪\t" * 100}) for k in ("mounts", "dns_state", "routes")]
        records += [row("docker_stats_table", pack_stats(stats)), row("docker_exec_summary", {
            "id": "a" * 64, "attributes": {"name": "雪" * 100, "ref": "literal", "define": 0},
            "events": [["exec_start", 2**63 + 11]], "count": 1}), journal()]
        records = records * 3
        untouched = copy.deepcopy(records)
        encoder, decoder = EvidenceEncoder(), EvidenceDecoder()
        encoded = [encoder.encode(record) for record in records]
        self.assertLess(sum(map(lambda r: len(json_bytes(r)), encoded)), sum(map(lambda r: len(json_bytes(r)), records)))
        self.assertEqual([decoder.decode(r) for r in encoded], records)
        self.assertEqual(records, untouched)
        self.assertEqual(unpack_stats(decoder.decode(records[3])["data"]), stats)

    def test_unusual_occurrences_preserve_exact_input_without_guessing(self):
        for value in ("001", "+1", "١٢", 42, "-1", str(2**64)):
            record = journal()
            record["data"]["summaries"][0]["occurrences"][0][1] = value
            encoded = EvidenceEncoder().encode(record)
            self.assertEqual(encoded, record)
            self.assertEqual(EvidenceDecoder().decode(encoded), record)
        record = journal()
        record["data"]["summaries"][0]["occurrences"][0][0] = "A" * 64
        self.assertEqual(EvidenceEncoder().encode(record), record)

    def test_legacy_literal_wrapper_keys_are_never_interpreted(self):
        record = row("docker_exec_summary", {"attributes": {"ref": 0}, "events": []})
        self.assertEqual(EvidenceDecoder().decode(record), record)
        self.assertEqual(EvidenceEncoder().encode(record), record)

    def test_unknown_version_missing_forward_duplicate_boolean_and_wrong_namespace_refs(self):
        encoder = EvidenceEncoder()
        definition = encoder.encode(row("mounts", {"text": "large" * 100}))
        reference = encoder.encode(row("mounts", {"text": "large" * 100}))
        invalid = []
        for value in ({"ref": 99}, {"ref": True}, {"ref": -1}, {"ref": 0, "extra": 1},
                      {"define": True, "value": "x"}, {"define": 0, "value": []},
                      {"define": 0, "value": "duplicate"}):
            altered = copy.deepcopy(reference); altered["data"]["text"] = value; invalid.append(altered)
        invalid += [{**reference, "kind": "routes"}, {**reference, "export_encoding": "future-v9"}]
        for record in invalid:
            with self.subTest(record=record):
                decoder = EvidenceDecoder(); decoder.decode(definition)
                with self.assertRaises(ValueError): decoder.decode(record)
                with self.assertRaises(ValueError): decoder.decode(reference)
        with self.assertRaises(ValueError): EvidenceDecoder().decode(reference)
        self.assertEqual(EvidenceDecoder().decode(definition)["data"]["text"], "large" * 100)

    def test_bad_later_field_does_not_commit_earlier_definition(self):
        record = row("docker_stats_table", {"encoding": "dict-columns-v1", "tables": [
            {"columns": {"define": 0, "value": [["one"]]}}, {"columns": {"ref": 99}}]})
        record["export_encoding"] = ENCODING
        decoder = EvidenceDecoder()
        with self.assertRaises(ValueError): decoder.decode(record)
        self.assertEqual(decoder.values, {})
        self.assertEqual(decoder.dictionary_bytes, 0)
        self.assertTrue(decoder.failed)

    def test_dictionary_limits_fall_back_to_literals(self):
        records = [row("mounts", {"text": str(n) * 300}) for n in range(8)]
        with patch("homelab_health.evidence.MAX_DEFINITIONS", 1):
            encoder, decoder = EvidenceEncoder(), EvidenceDecoder()
            encoded = [encoder.encode(r) for r in records]
            self.assertIn("export_encoding", encoded[0])
            self.assertTrue(all("export_encoding" not in r for r in encoded[1:]))
            self.assertEqual([decoder.decode(r) for r in encoded], records)
        with patch("homelab_health.evidence.MAX_DICTIONARY_BYTES", 1):
            self.assertEqual(EvidenceEncoder().encode(records[0]), records[0])
            bad = {**records[0], "export_encoding": ENCODING, "data": {"text": {"define": 0, "value": "x" * 300}}}
            with self.assertRaises(ValueError): EvidenceDecoder().decode(bad)

    def test_decoded_byte_limit_includes_expanded_references_and_plain_records(self):
        record = row("mounts", {"text": "x" * 1000})
        encoder = EvidenceEncoder()
        first, second = encoder.encode(record), encoder.encode(record)
        decoder = EvidenceDecoder(max_decoded_bytes=2 * (len(json_bytes(record)) + 1) - 1)
        decoder.decode(first)
        with self.assertRaises(ValueError): decoder.decode(second)
        with self.assertRaises(ValueError): EvidenceDecoder(max_decoded_bytes=10).decode(record)

    def test_invalid_compact_hash_timestamp_and_pair_bounds(self):
        original = EvidenceEncoder().encode(journal())
        for field, value in (("base", "001"), ("encoding", "future"), ("pairs", [["!" * 44, 0]]),
                             ("pairs", [["A" * 43 + "=", True]]), ("pairs", []),
                             ("pairs", [["A" * 43 + "=", 2**65]])):
            record = copy.deepcopy(original)
            record["data"]["summaries"][0]["occurrences"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): EvidenceDecoder().decode(record)

    def test_encoder_does_not_reinterpret_already_encoded_spool_input(self):
        record = EvidenceEncoder().encode(journal())
        with self.assertRaises(ValueError): EvidenceEncoder().encode(record)


class ExportIntegrationTests(unittest.TestCase):
    def test_cap_after_encoding_retains_more_records_and_never_rewrites_spool(self):
        rows = [row("mounts", {"text": "unchanged " * 1000}, n) for n in range(15)]
        with tempfile.TemporaryDirectory() as root:
            spool(root, rows)
            source = next(Path(root).glob("*.jsonl")); original = source.read_bytes()
            legacy, old = spool_chunks(root, AT, AT + dt.timedelta(minutes=1), 25000)
            chunks, coverage = spool_chunks(root, AT, AT + dt.timedelta(minutes=1), 25000, compact=True)
            self.assertLess(old["records"], 15); self.assertEqual(coverage["records"], 15)
            self.assertIn("source_byte_limit", [i["error"] for i in old["issues"]])
            self.assertEqual(decode_chunks(chunks), rows); self.assertEqual(coverage["issues"], [])
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(spool_chunks(root, AT, AT + dt.timedelta(minutes=1), 25000, compact=True)[0], chunks)
            exact = sum(map(len, chunks))
            self.assertEqual(spool_chunks(root, AT, AT + dt.timedelta(minutes=1), exact, compact=True)[1]["records"], 15)
            self.assertEqual(spool_chunks(root, AT, AT + dt.timedelta(minutes=1), exact - 1, compact=True)[1]["records"], 14)

    def test_chunk_reset_reencodes_overflow_record_and_recovers_independently(self):
        rows = [row("mounts", {"text": "repeated " * 1000, "padding": "x " * 350000}, n) for n in range(8)]
        with tempfile.TemporaryDirectory() as root:
            spool(root, rows)
            chunks, _ = spool_chunks(root, AT, AT + dt.timedelta(minutes=1), 8 * MIB, compact=True, chunk_limit=2 * MIB)
            self.assertGreater(len(chunks), 1); self.assertTrue(all(len(c) <= 2 * MIB for c in chunks))
            self.assertEqual(decode_chunks(chunks), rows)
            for chunk in chunks:
                first = json.loads(chunk.splitlines()[0])
                self.assertIn("define", first["data"]["text"])
                self.assertEqual(first["data"]["text"]["define"], 0)
            self.assertEqual(decode_chunks(chunks[1:]), rows[len(chunks[0].splitlines()):])

    def test_midnight_partial_invalid_oversized_records_and_empty_window(self):
        earlier = row("mounts", {"text": "x" * 1000}, -7 * 3600)
        later = row("mounts", {"text": "x" * 1000})
        with tempfile.TemporaryDirectory() as root:
            spool(root, [earlier, later])
            path = Path(root) / (stamp(AT)[:10] + ".jsonl")
            with path.open("ab") as stream: stream.write(b'not json\n{"partial":')
            chunks, coverage = spool_chunks(root, AT - dt.timedelta(days=1), AT, compact=True)
            self.assertEqual(decode_chunks(chunks), [earlier, later])
            self.assertEqual([i["error"] for i in coverage["issues"]], ["invalid_spool_record", "partial_spool_record"])
            path.write_bytes(b"x" * (2 * MIB + 1))
            _, coverage = spool_chunks(root, AT, AT, compact=True)
            self.assertIn("oversized_spool_record", [i["error"] for i in coverage["issues"]])
            self.assertIn("no_records_in_requested_window", [i["error"] for i in coverage["issues"]])

    def test_redaction_before_interning_and_encoding(self):
        rows = [row("mounts", {"text": "fixture-private " * 100}), row("docker_exec_summary", {
            "attributes": {"name": "fixture-private " * 100}, "events": [["exec_start", 10]]})]
        with tempfile.TemporaryDirectory() as root:
            spool(root, rows)
            redactor = Redactor(["fixture-private"])
            chunks, _ = spool_chunks(root, AT, AT, compact=True, redactor=redactor)
            self.assertNotIn(b"fixture-private", b"".join(chunks))
            self.assertEqual(decode_chunks(chunks), [redactor.clean(r) for r in rows])

    def test_verified_bundle_and_report_match_legacy_with_mixed_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            c = Collector({"data_dir": root, "host_dir": root + "/host", "compact_evidence": True}, FakeDocker())
            c.host_dir.mkdir()
            rows = [sample(AT), row("mounts", {"text": "x" * 1000}), row("mounts", {"text": "x" * 1000}, 1)]
            # Valid historical microseconds for reporter datetime conversion.
            j = journal()
            for pair in j["data"]["summaries"][0]["occurrences"]: pair[1] = str(int(AT.timestamp() * 1e6))
            rows.append(j)
            spool(c.host_dir, rows)
            marker = c.bundle(AT + dt.timedelta(minutes=1))
            _, manifest, contents = read_verified_bundle(c.outbox / marker["archive_name"], c.outbox / (marker["bundle_id"] + ".ready.json"))
            raw = contents["host/evidence-000.jsonl"]
            self.assertIn(b'"export_encoding":"refs-v1"', raw)
            decoded = decode_chunks([raw]); self.assertEqual(decoded, rows)
            compact_report = analyze(marker, manifest, contents)
            expanded = {**contents, "host/evidence-000.jsonl": b"\n".join(json_bytes(r) for r in decoded)}
            legacy_report = analyze(marker, manifest, expanded)
            compact_report.pop("generated_at_utc"); legacy_report.pop("generated_at_utc")
            self.assertEqual(compact_report, legacy_report)

    def test_report_marks_broken_member_then_recovers_next_member(self):
        encoder = EvidenceEncoder()
        original = row("mounts", {"text": "x" * 1000})
        definition, reference = encoder.encode(original), encoder.encode(original)
        marker = {"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": stamp(AT),
                  "requested_end_utc": stamp(AT), "collection_finished_utc": stamp(AT)}
        contents = {"host/evidence-000.jsonl": b"bad\n" + json_bytes(reference),
                    "host/evidence-001.jsonl": json_bytes(definition) + b"\n" + json_bytes(sample(AT))}
        result = analyze(marker, {"files": [], "issues": []}, contents)
        self.assertEqual(result["host_trends"]["samples"], 1)
        self.assertTrue(any("Invalid records" in f["message"] for f in result["findings"]))
        self.assertFalse(any("001" in f["message"] for f in result["findings"] if "Invalid records" in f["message"]))

    def test_report_total_decoded_budget_does_not_reset_at_next_member(self):
        marker = {"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": stamp(AT),
                  "requested_end_utc": stamp(AT), "collection_finished_utc": stamp(AT)}
        # Scale only reporter budgets down, without constructing enormous fixtures.
        raw = json_bytes(row("unknown", {"text": "x" * 60}))
        contents = {f"host/evidence-{i:03}.jsonl": raw for i in range(6)}
        with patch("homelab_health.report.MAX_DECODED_MEMBER_BYTES", 192), patch("homelab_health.report.MAX_DECODED_BUNDLE_BYTES", 768):
            result = analyze(marker, {"files": [], "issues": []}, contents)
        self.assertTrue(any("Invalid records" in f["message"] for f in result["findings"]))

    def test_writer_decoded_member_resets_and_source_limit_match_reader(self):
        rows = [row("mounts", {"text": "x " * 2500}, n) for n in range(10)]
        with tempfile.TemporaryDirectory() as root:
            spool(root, rows)
            with patch("homelab_health.evidence.MAX_DECODED_MEMBER_BYTES", 12000), patch("homelab_health.evidence.MAX_DECODED_SOURCE_BYTES", 24000):
                chunks, coverage = spool_chunks(root, AT, AT + dt.timedelta(minutes=1), compact=True)
            self.assertEqual(len(chunks), 2)
            self.assertEqual(coverage["records"], 4)
            self.assertEqual(coverage["issues"][0]["error"], "decoded_source_byte_limit")
            recovered = []
            for chunk in chunks:
                decoder = EvidenceDecoder(max_decoded_bytes=12000)
                recovered.extend(decoder.decode(json.loads(line)) for line in chunk.splitlines())
            self.assertEqual(recovered, rows[:4])

    def test_ref_expansion_checked_before_copying_all_values(self):
        record = row("docker_stats_table", {"encoding": "dict-columns-v1", "tables": [
            {"columns": {"define": 0, "value": [["x" * 65536]]}}] + [{"columns": {"ref": 0}} for _ in range(95)]})
        record["export_encoding"] = ENCODING
        import tracemalloc
        tracemalloc.start()
        try:
            with self.assertRaises(ValueError): EvidenceDecoder().decode(record)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 4 * MIB)

    def test_exact_budget_reference_before_later_definition(self):
        old = [[f"old_field_{n}"] for n in range(20)]
        new = [[f"new_field_{n}"] for n in range(20)]
        first = row("docker_stats_table", {"encoding": "dict-columns-v1", "tables": [{"columns": old}]})
        second = row("docker_stats_table", {"encoding": "dict-columns-v1", "tables": [{"columns": old}, {"columns": new}]})
        encoder = EvidenceEncoder()
        decoder = EvidenceDecoder(max_decoded_bytes=sum(len(json_bytes(r)) + 1 for r in [first, second]))
        self.assertEqual(decoder.decode(encoder.encode(first)), first)
        self.assertEqual(decoder.decode(encoder.encode(second)), second)

    def test_exact_record_limit_journal_roundtrip(self):
        record = journal()
        record["padding"] = ""
        from homelab_health.evidence import MAX_RECORD_BYTES
        record["padding"] = "x" * (MAX_RECORD_BYTES - len(json_bytes(record)) - 1)
        self.assertEqual(len(json_bytes(record)) + 1, MAX_RECORD_BYTES)
        self.assertEqual(EvidenceDecoder().decode(EvidenceEncoder().encode(record)), record)

    def test_out_of_calendar_timestamp_is_a_report_gap_not_a_crash(self):
        marker = {"sha256": "a" * 64, "hostname": "fixture", "requested_start_utc": stamp(AT),
                  "requested_end_utc": stamp(AT), "collection_finished_utc": stamp(AT)}
        raw = json_bytes(EvidenceEncoder().encode(journal()))
        result = analyze(marker, {"files": [], "issues": []}, {"host/evidence-000.jsonl": raw})
        self.assertTrue(any("calendar range" in f["message"] for f in result["findings"]))

    def test_post_redaction_overflow_is_an_explicit_gap(self):
        record = row("mounts", {"text": "host " * 250000})
        with tempfile.TemporaryDirectory() as root:
            spool(root, [record])
            chunks, coverage = spool_chunks(root, AT, AT, compact=True, redactor=Redactor(["host"]))
            self.assertEqual(chunks, [b""])
            self.assertEqual(coverage["records"], 0)
            self.assertEqual(coverage["issues"][0], {"error": "export_record_size_limit", "omitted_from_utc": stamp(AT)})
