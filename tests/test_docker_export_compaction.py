"""Lossless Docker reductions: synthetic data only, no host or Docker daemon."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from homelab_health.bundle import read_verified_bundle, spool_chunks
from homelab_health.collector import Collector
from homelab_health.common import MIB, Redactor, Spool, stamp
from homelab_health.docker import EventPump, selected_event
from homelab_health.evidence import DOCKER_ENCODING, EvidenceDecoder, EvidenceEncoder, json_bytes
from homelab_health.tables import pack_stats, unpack_stats
from tests.fixtures import AT, FakeDocker
from tests.test_compaction_v2 import stat
from tests.test_export_compaction import decode_chunks, row, spool
from tests.test_noise import event, records


def exec_row(offset=0):
    actions = ("exec_create", "exec_start", "exec_die")
    pairs = [[actions[n % 3], 2**63 + (n % 27) * 1234567] for n in range(256)]
    return row("docker_exec_summary", {"id": "a" * 64, "attributes": {"name": "fixture"},
        "events": pairs, "count": len(pairs), "first_time_nano": pairs[0][1],
        "last_time_nano": pairs[-1][1]}, offset)


def stats_row(offset=0):
    samples = [stat(n) for n in range(24)]
    for n, sample in enumerate(samples):
        sample["blkio_stats"]["io_service_bytes_recursive"] = [
            {"major": major, "minor": 0, "op": op, "value": 2**63 + n}
            for major in (8, 259) for op in ("read", "write")]
        sample["blkio_stats"]["io_serviced_recursive"] = [
            {"major": 8, "minor": 0, "op": "write", "value": -n}]
    return row("docker_stats_table", pack_stats(samples), offset)


def state_row(offset=0):
    state = FakeDocker().inspect("a" * 64)
    state.update({"image_id": "sha256:" + "b" * 64, "created": stamp(AT),
        "log_driver": "json-file", "compose_project": "fixture", "compose_service": "web"})
    state["health"] = {"status": "unhealthy", "failing_streak": 2, "log": [
        {"Start": stamp(AT), "End": stamp(AT), "ExitCode": 1, "Output": "failed\n" * 100}]}
    return row("docker_state", state, offset)


class DockerCodecTests(unittest.TestCase):
    def test_exact_roundtrip_mixed_versions_large_signed_values_and_failures(self):
        source = [row("mounts", {"text": "unchanged " * 100}), exec_row(), stats_row(), state_row()]
        source *= 3
        untouched = copy.deepcopy(source)
        encoder, decoder = EvidenceEncoder(docker_compaction=True), EvidenceDecoder()
        encoded = [encoder.encode(record) for record in source]
        self.assertEqual([decoder.decode(record) for record in encoded], source)
        self.assertEqual(source, untouched)
        self.assertLess(sum(len(json_bytes(r)) for r in encoded), sum(len(json_bytes(r)) for r in source) * .65)
        self.assertEqual(encoded[0]["export_encoding"], "refs-v1")
        self.assertTrue(all(r["export_encoding"] == DOCKER_ENCODING for r in encoded[1:4]))
        self.assertEqual(encoded[1]["data"]["attributes"], {"literal": {"name": "fixture"}})
        recovered = EvidenceDecoder().decode(EvidenceEncoder(docker_compaction=True).encode(stats_row()))
        self.assertEqual(unpack_stats(recovered["data"]), unpack_stats(stats_row()["data"]))
        self.assertEqual(encoded[3]["data"]["health"], state_row()["data"]["health"])

    def test_exec_delta_preserves_order_duplicates_and_exact_nanoseconds(self):
        original = exec_row()
        encoded = EvidenceEncoder(docker_compaction=True).encode(original)
        self.assertEqual(encoded["data"]["events"]["base"], 2**63)
        self.assertEqual(EvidenceDecoder().decode(encoded), original)
        # Malformed/unknown source pairs remain literal, rather than guessed.
        for pair in (["future_action", 2**63], ["exec_start", True], ["exec_die", 2**64]):
            altered = copy.deepcopy(original); altered["data"]["events"][0] = pair
            encoded = EvidenceEncoder(docker_compaction=True).encode(altered)
            self.assertEqual(encoded["data"]["events"], altered["data"]["events"])
            self.assertEqual(EvidenceDecoder().decode(encoded), altered)

    def test_future_io_shapes_and_wrapper_like_values_stay_literal(self):
        for value in ([{"major": 8, "minor": 0, "op": "read", "value": 12, "future": "unit"}],
                      {"encoding": "io-rows-v1", "rows": [[8, 0, "read", 12]]},
                      {"literal": {"ref": 0}}, [], None):
            source = stats_row()
            table = source["data"]["tables"][0]
            index = table["columns"].index(["blkio_stats", "io_service_bytes_recursive"])
            table["rows"][0][index] = value
            encoded = EvidenceEncoder(docker_compaction=True).encode(source)
            self.assertEqual(EvidenceDecoder().decode(encoded), source)
        source = exec_row(); source["data"]["attributes"] = {"ref": 0}
        self.assertEqual(EvidenceDecoder().decode(EvidenceEncoder(docker_compaction=True).encode(source)), source)
        source = state_row(); source["data"]["_metadata"] = {"ref": 0}
        self.assertEqual(EvidenceEncoder(docker_compaction=True).encode(source), source)

    def test_metadata_changes_cannot_be_hidden_by_previous_definition(self):
        source = [state_row(), state_row(1)]
        source[1]["data"].update(id="c" * 64, image="fixture:2", name="renamed")
        encoder, decoder = EvidenceEncoder(docker_compaction=True), EvidenceDecoder()
        encoded = [encoder.encode(record) for record in source]
        self.assertNotEqual(encoded[0]["data"]["_metadata"], encoded[1]["data"]["_metadata"])
        self.assertEqual([decoder.decode(record) for record in encoded], source)
        with patch("homelab_health.evidence.MAX_DICTIONARY_BYTES", 1):
            encoded = EvidenceEncoder(docker_compaction=True).encode(source[0])
            self.assertEqual(EvidenceDecoder().decode(encoded), source[0])

    def test_stats_ids_share_exact_namespace_with_exec_and_bad_refs_fail(self):
        source = [exec_row(), stats_row(), stats_row(1)]
        encoder, decoder = EvidenceEncoder(docker_compaction=True), EvidenceDecoder()
        encoded = [encoder.encode(record) for record in source]
        self.assertIsInstance(encoded[0]["data"]["id"], dict)
        self.assertEqual([decoder.decode(record) for record in encoded], source)
        for value in ({"ref": 9999}, {"ref": False}, {"ref": 0}, {"define": 0, "value": "wrong"}):
            record = copy.deepcopy(encoded[1])
            table = record["data"]["tables"][0]
            index = source[1]["data"]["tables"][0]["columns"].index(["id"])
            table["rows"][0][index] = value
            # 0 is the previously defined exec ID, which is valid. Wrong
            # namespaces are tested using the stats-column definition instead.
            if type(value.get("ref")) is int and value.get("ref") == 0:
                table["rows"][0][index] = {"ref": table["columns"]["define"]}
            decoder = EvidenceDecoder(); decoder.decode(encoded[0])
            with self.subTest(value=value), self.assertRaises(ValueError): decoder.decode(record)
            self.assertEqual(len(decoder.values), 1)

    def test_invalid_exec_wrappers_fail_without_committing_definitions(self):
        source = exec_row(); source["data"]["attributes"] = {"name": "fixture " * 100}
        original = EvidenceEncoder(docker_compaction=True).encode(source)
        changes = [{"base": True}, {"base": 0}, {"base": 2**64}, {"pairs": []},
            {"pairs": [[True, 0]]}, {"pairs": [[3, 0]]}, {"pairs": [[1, False]]},
            {"pairs": [[1, -2**63]]}, {"pairs": [[1, 2**64]]}, {"extra": 1},
            {"encoding": "future"}, {"pairs": [[1, 0]] * 32769}]
        for change in changes:
            record = copy.deepcopy(original); record["data"]["events"].update(change)
            decoder = EvidenceDecoder()
            with self.subTest(change=str(change)[:100]), self.assertRaises(ValueError): decoder.decode(record)
            self.assertTrue(decoder.failed); self.assertEqual(decoder.values, {})
        bad = {**original, "kind": "mounts"}
        with self.assertRaises(ValueError): EvidenceDecoder().decode(bad)

    def test_invalid_io_and_colliding_metadata_are_rejected(self):
        original = EvidenceEncoder(docker_compaction=True).encode(stats_row())
        for value in ({"encoding": "future", "rows": [[8, 0, "read", 1]]},
                      {"encoding": "io-rows-v1", "rows": [[]]},
                      {"encoding": "io-rows-v1", "rows": []},
                      {"encoding": "io-rows-v1", "rows": [[8, 0, "read", 1]] * 129},
                      {"literal": []}):
            record = copy.deepcopy(original)
            record["data"]["tables"][0]["rows"][0][0] = value
            with self.subTest(value=str(value)[:100]), self.assertRaises(ValueError): EvidenceDecoder().decode(record)
        for metadata in ({"unknown": "future"}, {}, {"state": {"Running": True}}):
            record = EvidenceEncoder(docker_compaction=True).encode(state_row())
            record["data"]["_metadata"] = {"literal": metadata}
            with self.assertRaises(ValueError): EvidenceDecoder().decode(record)
        record = EvidenceEncoder(docker_compaction=True).encode(state_row())
        record["data"]["id"] = "overlap"
        with self.assertRaises(ValueError): EvidenceDecoder().decode(record)

    def test_expansion_limits_count_original_records_not_compacted_bytes(self):
        for source in (exec_row(), stats_row(), state_row()):
            encoded = EvidenceEncoder(docker_compaction=True).encode(source)
            exact = len(json_bytes(source)) + 1
            self.assertEqual(EvidenceDecoder(max_decoded_bytes=exact).decode(encoded), source)
            with self.subTest(kind=source["kind"]), self.assertRaises(ValueError):
                EvidenceDecoder(max_decoded_bytes=exact - 1).decode(encoded)
        source = exec_row()
        with patch("homelab_health.evidence.MAX_RECORD_BYTES", len(json_bytes(source))):
            encoded = EvidenceEncoder(docker_compaction=True).encode(source)
            with self.assertRaises(ValueError): EvidenceDecoder().decode(encoded)


class DockerExportIntegrationTests(unittest.TestCase):
    def test_cap_after_compaction_more_records_and_deterministic_midnight_reset(self):
        source = [record for n in range(8) for record in (exec_row(n), stats_row(n), state_row(n))]
        source[0]["at"] = stamp(AT - dt.timedelta(days=1))
        with tempfile.TemporaryDirectory() as root:
            spool(root, source)
            originals = {path.name: path.read_bytes() for path in Path(root).glob("*.jsonl")}
            start, end = AT - dt.timedelta(days=1), AT + dt.timedelta(minutes=1)
            chunks, coverage = spool_chunks(root, start, end, 40 * MIB, compact=True, compact_docker=True)
            self.assertEqual(coverage["issues"], [])
            self.assertEqual(coverage["evidence_encoding"], DOCKER_ENCODING)
            self.assertEqual(decode_chunks(chunks), source)
            exact = sum(map(len, chunks))
            _, legacy = spool_chunks(root, start, end, exact, compact=True)
            self.assertLess(legacy["records"], len(source))
            self.assertEqual(spool_chunks(root, start, end, exact, compact=True, compact_docker=True)[0], chunks)
            _, capped = spool_chunks(root, start, end, exact - 1, compact=True, compact_docker=True)
            self.assertEqual(capped["records"], len(source) - 1)
            self.assertEqual(capped["issues"][0]["error"], "source_byte_limit")
            self.assertEqual(originals, {path.name: path.read_bytes() for path in Path(root).glob("*.jsonl")})
        with tempfile.TemporaryDirectory() as root:
            source = [state_row(n) for n in range(6)]
            for record in source: record["padding"] = "x " * 350000
            spool(root, source)
            chunks, _ = spool_chunks(root, AT, AT + dt.timedelta(minutes=1), 8 * MIB,
                compact=True, compact_docker=True, chunk_limit=2 * MIB)
            self.assertGreater(len(chunks), 1)
            self.assertEqual(decode_chunks(chunks), source)
            for chunk in chunks:
                first = json.loads(chunk.splitlines()[0])
                self.assertEqual(first["data"]["_metadata"]["define"], 0)

    def test_individual_important_events_unchanged_through_real_pump(self):
        with tempfile.TemporaryDirectory() as root:
            pump = EventPump(None, Spool(root), Path(root) / "cursor.json", threading.Event())
            with patch("homelab_health.common.now", return_value=AT):
                for n in range(120): pump.record_event(event(n, ("exec_create", "exec_start", "exec_die")[n % 3], "0"))
                important = [event(200, "exec_die", "1"), event(201, "exec_die"), event(202, "oom"),
                    event(203, "health_status: unhealthy"), event(204, "die", "137"), event(205, "restart")]
                for raw in important: pump.record_event(raw)
                pump.flush_exec()
            original = records(root)
            chunks, _ = spool_chunks(root, AT, AT, compact=True, compact_docker=True)
            restored = decode_chunks(chunks)
            self.assertEqual(restored, original)
            self.assertEqual([r["data"] for r in restored if r["kind"] == "docker_event"], [selected_event(e) for e in important])

    def test_bundle_enables_only_docker_v2_and_redacts_before_factoring(self):
        with tempfile.TemporaryDirectory() as root:
            c = Collector({"data_dir": root, "host_dir": root + "/host", "compact_evidence": True,
                "compact_docker_evidence": True, "redact_literals": ["fixture"]}, FakeDocker())
            c.host_dir.mkdir()
            host = [row("mounts", {"text": "unchanged " * 100})]
            docker = [exec_row(), stats_row(), state_row()]
            spool(c.host_dir, host); spool(c.spool.directory, docker)
            marker = c.bundle(AT + dt.timedelta(minutes=1))
            _, manifest, contents = read_verified_bundle(c.outbox / marker["archive_name"], c.outbox / (marker["bundle_id"] + ".ready.json"))
            raw = contents["docker/evidence-000.jsonl"]
            self.assertNotIn(b"fixture", raw)
            self.assertEqual(decode_chunks([raw]), [Redactor(["fixture"]).clean(r) for r in docker])
            self.assertIn(b'"export_encoding":"refs-v1"', contents["host/evidence-000.jsonl"])
            entries = {item["name"]: item for item in manifest["files"]}
            self.assertEqual(entries["docker/evidence-000.jsonl"]["evidence_encoding"], DOCKER_ENCODING)
            self.assertEqual(entries["host/evidence-000.jsonl"]["evidence_encoding"], "refs-v1")
            with self.assertRaises(ValueError): spool_chunks(root, AT, AT, compact_docker=True)


if __name__ == "__main__":
    unittest.main()
