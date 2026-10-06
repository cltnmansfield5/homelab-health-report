# Keep a complete Docker window within the existing evidence cap

The **daily raw spool** and **per-bundle exported source** have different caps.
This patch keeps the 64 MiB/day spool, 40 MiB exported source, 8 MiB members and
128 MiB bundle defaults. It changes the export representation, preserves the
raw spools, and leaves application log drivers, health checks, event collection,
state cadence and one-minute resource measurements unchanged.

## Target the repeated bytes

- Reference repeated container IDs in stats and exec summaries.
- Store exact exec actions as numeric codes with integer nanosecond offsets.
- Factor four repeated disk-I/O keys into compact rows, preserving device,
  operation, every counter and its sign.
- Reference unchanged container metadata while keeping health/state/failure
  information literal.

All captured records reconstruct exactly as JSON values. There is no sampling,
event-count aggregation, rounding or removal of failure output. Lifecycle,
health-transition, OOM and failed/unknown exec events remain individual records;
final container state/log files are unchanged. Dictionary references reset at
every member, and malformed data fails visibly rather than being guessed.
See [the v2 encoding and bounds](export-compaction.md#additional-docker-fields-in-v2).

## Measured replay

One verified retained window produced these incremental savings over v1:

| Docker source | Before | After |
| --- | ---: | ---: |
| Stats tables | 18.19 MiB | 13.28 MiB |
| Routine exec summaries | 14.28 MiB | 9.60 MiB |
| State snapshots | 7.51 MiB | 5.23 MiB |
| Individual events / coverage notices | 0.022 MiB | 0.022 MiB |
| **Total captured evidence** | **40.00 MiB** | **28.12 MiB** |

Reduction: **29.69%**, including real member resets and all encoding overhead.
Every one of 29,386 Docker records, 44,067 resource samples and 252,105 routine
exec tuples reconstructed unchanged, and reporter outcomes matched. Host evidence
was byte-identical. An identically rebuilt whole archive was 9.22% smaller after
gzip; the source cap applies to uncompressed JSONL, where the larger saving matters.

The captured Docker interval was approximately 19h52m. At that interval's rate,
the full requested 24h05m window projects to **34.12 MiB**, below the unchanged
40 MiB source cap with approximately **5.88 MiB** headroom. The raw daily spool
projects to 54.19 MiB, below its 64 MiB default. These are estimates: the unavailable
tail cannot be restored, and future bursts or more containers may change the rate.
A complete newly collected window is still required to confirm production coverage.

## Validate the change offline

From the trusted updated checkout, use an authorized local bundle:

```bash
python3 -m unittest discover -v
python3 scripts/benchmark-export-compaction.py BUNDLE.tar.gz \
  --marker BUNDLE.ready.json --docker-fields
```

The benchmark verifies archive/member hashes, uses the real exporter at 40 MiB
with actual 8 MiB resets, compares every restored record/value/list order, and
checks reporter trends, coverage, deduplicated counts and substantive findings.
It prints aggregates only and uses temporary spools. Missing source tails remain
missing; full-window projections are estimates, not recovered observations.

## Deploy the reviewed revision

1. Upgrade every report/automation reader to this revision's trusted
   `homelab_health.evidence.EvidenceDecoder` first. It reads legacy, v1 and v2
   records. Keep that decoder for previously produced compacted archives.
2. Merge the reviewed patch. In Komodo, pull the revision and **build/redeploy
   the existing collector service**. A pull-only image update does not rebuild
   the code or built-in configuration. Do not start a second collector/stack.
   The example enables both `compact_evidence` and `compact_docker_evidence`;
   compare any collector config mounted over `/config/collector.toml` separately.
   Preserve private settings, volumes, source files and uploader state. No
   host-helper, monitored-application or Docker daemon change is required.
3. Confirm the collector's status is fresh and healthy. After a complete new
   reporting window, check the last Docker **stats, state and event-source**
   timestamps independently, compare requested versus actual coverage, and
   verify archive/member hashes. Confirm there are no current `source_byte_limit`,
   `daily_spool_limit`, decoded-budget or parsing issues. Historical gap notices
   can remain, so check their original UTC dates.
4. Keep the current caps until a full window proves headroom. More containers,
   bursts and heavy failure logs can still hit hard limits, which must continue
   to produce explicit coverage notices. A green final snapshot alone does not
   verify continuous history.

Rollback by setting `compact_docker_evidence = false` and rebuilding/redeploying
the collector: future Docker exports use v1. Disable `compact_evidence` for
literal exports. Retain the v2 reader for existing v2 bundles; raw spools are
unchanged and can be re-exported while retained. Preserve pending bundles and
do not fabricate processing receipts.
