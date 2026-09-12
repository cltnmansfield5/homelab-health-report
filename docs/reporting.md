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
