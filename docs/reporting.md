# Reporting

Local triage validates the archive and writes Markdown plus companion JSON.
It reports evidence gaps, sampled resource use, failed units/probes/jobs,
container health/OOM state and log messages needing review. Keyword matches are
not incident counts. Use --previous PATH.json to compare finding keys; absence
does not establish recovery.

A fuller report worker should:

1. Read completed archive/marker pairs and prior receipts from the configured
   private folders. Deduplicate by archive SHA-256; do not reissue old reports
   when no new evidence exists. Flag the newest completed drop as stale after
   36 hours.
2. Verify the archive and every member, then review all relevant source content.
   Deduplicate overlaps using original timestamps and source identities.
3. Separate observed facts, plausible causes, snapshots and sampled trends.
   Compare prior reports; call recovery only when fresh evidence supports it.
4. Save a substantive Markdown report with coverage, prioritized findings,
   confidence, sources and next diagnostic steps. Use the chosen local timezone
   while preserving UTC evidence timestamps.
5. Confirm persistence, then write the exact [processing receipt](bundle-protocol.md)
   for each fully reviewed bundle. Do not delete inputs or remediate the host.

Use the [generic task template](chatgpt-report-prompt.md), substituting private
folder URLs and timezone outside Git. Verify the first real drop and saved
report/receipt before enabling recurring analysis. No model API or cloud
credential is needed in the collector.

If Drive reads Markdown but cannot materialize archive downloads, use the
[lossless text fallback](text-transport.md). It reconstructs the exact original
archive and preserves all integrity and full-review receipt requirements.


## Severity within a reporting window

A finding keeps the highest observed severity across its window, along with the
message and source supporting that escalation. A later lower reading does not
remove an earlier critical condition. First/last timestamps bound all observations;
recovery requires separate fresh evidence. The 2026-09-27 regression covers disk
usage rising from 90% to 98% and then falling to 88%, including out-of-order input.

For [refs-v1 and refs-v2 export records](export-compaction.md), verify archive
and member integrity first, then pass every JSONL line in order through a fresh
trusted `homelab_health.evidence.EvidenceDecoder` per member. Use the decoder
supporting both versions before interpreting records or expanding stats. V2
restores container IDs, exact exec timestamps/actions, I/O dictionaries and state
metadata; these are encoded values, not missing evidence. Legacy and both marked
versions can share a member. Malformed/unknown encodings, invalid references and
expansion failures are coverage gaps; never infer healthy status or issue a
processing receipt from rejected or partially reviewed evidence. Upgrade every
report/automation consumer and its task instructions before enabling the
collector options. Follow the [updated task template](chatgpt-report-prompt.md).
