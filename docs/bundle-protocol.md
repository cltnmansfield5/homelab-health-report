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

### Optional noise compaction

These additive record fields do not change the archive or receipt schema.

- `docker_exec_summary`: per-container batches of routine `exec_create`,
  `exec_start`, and successful `exec_die` events. `events` contains
  `[action, timeNano]` pairs; each summarized `exec_die` has exit code 0.
  `count`, `first_time_nano`, and `last_time_nano` describe those entries.
  Deduplicate by `(id, action, timeNano)` across batches and original events.
  Failed or unknown-status exec exits remain full `docker_event` records, as do
  lifecycle, health and OOM events. Exec-command text is not retained.
- Host journal records can have `summaries` alongside `rows`. Only repeated
  `docker-default` / `tokio-rt-worker` ptrace-read denials against `unconfined`
  peers are compacted. Exact `kauditd_printk_skb: N callbacks suppressed`
  kernel messages can also be grouped as `kernel_callback_suppression`; each
  distinct N stays in its own signature. These warn of missing original journal
  messages: occurrence counts are neither suppressed-callback counts nor incidents.
  Error/critical priorities, unfamiliar denials and other messages stay individual. Signatures keep the PID, boot and access details;
  only audit sequence/timestamp text is normalized for grouping.
  Each summary retains an `example` plus `occurrences` pairs of
  `[identity_sha256, original_realtime_microseconds]`, and first/last timestamps.
  Identity is SHA-256 of the JSON-encoded journal cursor, or of the boot,
  timestamp, unit and message tuple if no cursor is available. Count the union
  of identities across summaries and exports; an example is already included
  in `occurrences`, not an additional entry. Counts are observed journal entries,
  not incidents or kernel-suppressed messages.
- `exported_rows_before_compaction` and `duplicate_rows_removed` describe a
  journal export before compaction. Duplicate removal is within an export;
  overlaps between exports remain identifiable. Original cap/error flags are
  preserved. Compaction cannot recover records the journal command did not return.

Docker batches flush every 60 seconds of received traffic or at 256 pending
events, and on disconnect/graceful thread exit. Pending entries and the last 512
replay hashes are checkpointed atomically with the event cursor. On restart,
pending entries are emitted before reconnecting. A crash between append and
checkpoint can replay a batch, hence identity-based deduplication is required.
Selected events above 4 KiB after redaction remain individual records to bound
checkpoint size.
If the spool is full, at most 256 pending entries are retained; further events
follow the existing bounded-spool behavior and produce a cap notice. Summary
`at` is flush time, which can be later than the original events after an outage.
No summary extends demonstrated event coverage into that delay.


### Compact statistics and successful health checks

`docker_stats_table` is a self-contained record for one collector sampling cycle,
with `data.encoding = "dict-columns-v1"`, `data.samples`, and `data.tables`.
Every table contains `columns` (arrays of nested dictionary keys), `rows` (arrays
of corresponding values), and `indexes` (original positions in the cycle).
Assign each row value to its column's nested dictionary path, then restore the
rows by index. Empty dictionaries, nulls and arrays are values, not missing data.
`homelab_health.tables.unpack_stats` in the trusted project implements the bounded
reader. Never load code from a diagnostic archive. Readers must reject malformed
or unknown encodings and report a coverage gap rather than silently skip them.

There is no numeric aggregation or reduced sampling frequency. Every statistic,
integer precision, sign, container ID and Docker `read` timestamp survives. Batch
`at` is when the cycle's results are written; use individual `read` timestamps for
measurement intervals. Each cycle flushes before `sample()` returns, with no
cross-cycle pending queue. Statistics remain legacy `docker_stats` records when
compaction is disabled, not beneficial, or exceeds encoder bounds. A process
crash before the cycle flush can lose that cycle's in-memory statistics; it does
not create a durable backlog. All original error records remain individual.

Limits: 128 samples, 128 columns per table, 8 dictionary levels, 128 characters
per nonempty key, and 1 MiB encoded payload. Duplicate/conflicting paths, repeated
or missing indexes, wrong row widths and count mismatches are rejected. Keys and
values are redacted **before** dictionary keys are factored into column arrays.
Archive and receipt schema versions and safety limits are unchanged.

In periodic `docker_state` only, a healthy snapshot's successful probe `Output`
longer than 256 UTF-8 bytes may be replaced with `successful_output_omitted=true`,
`output_bytes` and `output_sha256` of its **redacted** text. Start, End, ExitCode
and other fields remain. Short successes, unknown/nonzero exits and all probe
logs in unhealthy/starting snapshots stay verbatim (subject to normal redaction).
New sampled failures/failing-streak changes trigger a state record even before
the usual five-minute heartbeat. Final `docker/ID.json` files retain full probe
logs. A hash proves neither correctness nor the meaning of omitted output.

Successful complete `links`, `routes` and `mounts` JSON command output may have
insignificant indentation removed, flagged by `json_whitespace_compacted=true`.
Parsed values are unchanged. Failed, truncated, timed-out and non-JSON output is
not compacted. No source, sampling interval, cap, permission or application
logging setting is changed by these representations.

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


## Deployment and compatibility

Changing deployment managers does not change bundle or receipt identities. Keep
the outbox and uploader state together; follow [Komodo adoption](komodo.md).
Exec-create/start argument suffixes are removed before event spooling. This
changes only newly collected event content; old immutable archives retain their
original hashes and bytes and must not be silently rewritten.
