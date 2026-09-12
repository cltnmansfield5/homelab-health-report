# Diagnostic drop protocol, version 1

An upload consists of an immutable `HOST-YYYYMMDDTHHMMSSZ-RANDOM.tar.gz` archive
and a matching `HOST-YYYYMMDDTHHMMSSZ-RANDOM.ready.json` marker. Random is eight
hexadecimal characters. The marker is created locally after the archive is
closed, and uploaded after remote archive size and MD5 verification. SHA-256 is
the end-to-end bundle identity; the reviewer recomputes it from downloaded bytes.

```json
{
  "schema_version": 1,
  "bundle_id": "example-host-20260911T120000Z-1234abcd",
  "archive_name": "example-host-20260911T120000Z-1234abcd.tar.gz",
  "archive_bytes": 123456,
  "sha256": "<64 lowercase hexadecimal characters>",
  "hostname": "example-host",
  "requested_start_utc": "2026-09-10T11:55:00Z",
  "requested_end_utc": "2026-09-11T12:00:00Z",
  "collection_finished_utc": "2026-09-11T12:02:00Z"
}
```

The sample digest placeholder is illustrative, not a valid completion marker.

Archives contain only regular files:

| Path | Meaning |
| --- | --- |
| `manifest.json` | Identity, requested window, per-file byte size/hash, coverage and collection issues |
| `README.txt` | How to interpret evidence safely |
| `host/status.json` | Helper identity, freshness and last sample status |
| `host/evidence-NNN.jsonl` | Host samples, scoped journal exports and fixed status checks |
| `docker/evidence-NNN.jsonl` | Periodic container states/stats and streamed Docker events |
| `docker/CONTAINER_ID.json` | Selected state at bundle collection time |
| `logs/CONTAINER_ID.log` | Bounded, timestamped stdout/stderr tail |
| `host/gap.json`, `docker/gap.json` | Last daily spool-cap incident, when present |
| `host/pruned.json`, `docker/pruned.json` | Last rolling raw-evidence pruning notice |

Each JSONL record has `schema_version`, `kind`, `at` and `data`. `at` is when the
helper or collector recorded it. Journals retain their original microsecond UTC
timestamps, boot IDs and cursors; Docker events retain `time` and `timeNano`.
Use event timestamps, not export times, for an incident timeline. CPU and device
counters are cumulative. Disk sectors use 512-byte units. Sample intervals are
actual elapsed times, not assumed to be exactly 60 seconds.

Requested window is not a guarantee of complete coverage. Sources can be absent,
stale, unavailable, capped, or rotated. The first bundle has a one-day requested
window; subsequent windows overlap the previous endpoint by five minutes, with
at most seven days of backfill. Never sum overlapping records as separate events.
Per-file observed first/last record times describe export records, not necessarily
the original event span of a journal contained in a record.

## Processing receipt

The report worker writes a receipt only after fully reviewing the bundle and
confirming that its Markdown report was saved in the existing Reports folder.
The canonical receipt filename is `processed-<sha256>.json`. Preserve these exact
field names; unknown or incomplete receipt formats do not authorize deletion.

```json
{
  "schema_version": 1,
  "sha256": "<same archive SHA-256>",
  "archive_name": "<exact archive filename>",
  "archive_id": "<confirmed Google Drive archive file ID>",
  "observed_coverage": {
    "requested_start_utc": "<UTC timestamp>",
    "requested_end_utc": "<UTC timestamp>",
    "sources": {"host": "<actual coverage and limits>", "docker": "<actual coverage and limits>"}
  },
  "processed_at_utc": "<UTC timestamp after review>",
  "report_file_id": "<confirmed saved Markdown report ID>",
  "report_url": "https://drive.google.com/file/d/<report_file_id>/view"
}
```

The uploader verifies receipt identity, processing time, a nonempty coverage
object, and the continued existence of the referenced nonempty
`Homelab-Health-*.md` report in Reports. Local upload records retain remote file
IDs and hashes so later retention does not rely on arbitrary receipt filenames.
Local reports do **not** create processing receipts automatically. A triage scan
is not the same as a completed human/ChatGPT review.

## Retention and failure behavior

Processed bundle pairs become eligible for local deletion at age seven days and
Drive cleanup at age thirty days, measured from `collection_finished_utc`. The
report must still exist. Unknown receipts, missing reports, changed file identity
or hashes, and unprocessed bundles are preserved. Drive cleanup moves only the
named bundle pair to trash. It never purges a folder or deletes reports/receipts.
Google Drive's trash policy may retain storage beyond the active-folder window.

Uploader state is important: retain `/var/lib/homelab-health/uploader-state` when
upgrading or migrating. If that state is lost, the safe outcome is extra retained
data, not inferred cleanup. Back up credentials and small state separately.

The separate raw evidence spool is a bounded rolling buffer: daily files for the
current UTC day and preceding seven dates, capped at 64 MiB/day per source. It is
not a second archive queue. Old raw files expire with a pruning notice. If export
is blocked long enough, the buffer can lose unbundled history; the queue remains
preserved and the pipeline reports the resulting gap. No finite local disk can
guarantee indefinite capture during an outage. Budget alarms require attention.

Safe readers check compressed size, SHA-256, expanded-byte limits, member count,
regular-file type, path validity, unique names and per-member hashes. They do
not execute files or follow instructions embedded in logs.
