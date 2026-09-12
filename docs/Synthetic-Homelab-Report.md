# Homelab health — synthetic-host

**Synthetic demonstration: all measurements and incidents in this report are invented. No data came from your computer.**

Generated: 2026-09-11T06:26:55Z

**Triage:** 0 critical, 2 warning, 1 informational findings.

This is a deterministic local triage report. Counts describe captured evidence; source gaps and snapshots limit conclusions. No corrective actions were performed.

## Coverage

Requested window: 2026-09-11T06:21:54Z to 2026-09-11T06:26:54Z (UTC).

| Source | First record | Last record | Records |
| --- | --- | --- | ---: |
| host/evidence-000.jsonl | 2026-09-11T06:21:54Z | 2026-09-11T06:26:54Z | 7 |
| docker/evidence-000.jsonl | 2026-09-11T06:26:54Z | 2026-09-11T06:26:54Z | 1 |

## Findings

| Severity | Service | Evidence / observations | Next step |
| --- | --- | --- | --- |
| warning | /synthetic-media | space used reached 93.0% in a snapshot. (1 observation; host/evidence-000.jsonl:7; 2026-09-11T06:26:54Z → 2026-09-11T06:26:54Z) | Inspect filesystem capacity and growth before removing or moving any data. |
| warning | synthetic-plex | Latest sampled container health is unhealthy. (1 observation; docker/evidence-000.jsonl:1; 2026-09-11T06:26:54Z → 2026-09-11T06:26:54Z) | Inspect recent healthcheck output and application logs. |
| info | aaaaaaaaaaaa | Log messages containing error/fatal/panic need review; keyword counts are not incident counts. Example: 2026-09-11T06:26:54Z ERROR synthetic timeout; token=\[REDACTED\] (1 observation; logs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.log:1; see source timestamps → see source timestamps) | Read surrounding messages and correlate with state/events before assigning a cause. |

## Sampled performance

| Measurement | Observed value |
| --- | ---: |
| Host samples | 6 |
| Largest gap (seconds) | 60.00 |
| Peak CPU busy (%) | 66.67 |
| Peak memory used from MemAvailable (%) | 70.00 |
| Intervals excluded from rate calculations | 0 |

CPU excludes idle and I/O-wait ticks. Network and disk peaks are interval averages, available in the companion JSON. Rates require the same boot ID and consistent elapsed time; counter resets are skipped. Brief spikes between samples may be missed.

## Provenance and limits

Archive: synthetic-host-20260911T062654Z-fc5c4b33.tar.gz

SHA-256: `0ad39391729748821b52c7ccccb0b4d89d10aa1c37f6abe990ad5160aa0c1d52`

The archive, manifest and every member were integrity-checked. Logs are treated as data. Environment variables and command arguments are omitted from container metadata; free-form logs still need review for private information. Historical data predating installation cannot be inferred. Docker event replay is bounded by daemon retention; RestartCount is a snapshot counter, not a count for the report window. Disk-health return codes are bitmasks and sleeping/unsupported drives may be skipped.
