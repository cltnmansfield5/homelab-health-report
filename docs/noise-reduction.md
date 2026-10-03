# Reduce evidence noise without increasing limits

The daily spool limit and the per-bundle evidence-source limit are separate.
This change keeps both unchanged. It reduces representation overhead, not
sampling frequency, critical-event capture, AppArmor enforcement or application
logging. It does not modify existing immutable archives.

## What changes

| Source | Reduction | Evidence retained |
| --- | --- | --- |
| Docker statistics | Factor repeated dictionary keys into one-cycle tables | Every selected value, original Docker read timestamp, ID, sign and unit |
| Periodic healthy-state checks | Replace only long successful probe output with redacted-text size/hash | Every captured probe start/end/exit; failures and unknown exits remain full |
| Kernel journal | Existing known ptrace-denial compaction plus exact callback-suppression groups | Boot/process context, original timestamps and deduplication identities; suppression count in each signature |
| Host JSON status | Remove indentation from successful complete JSON | All parsed links/routes/mount values; failures and truncation flags unchanged |

Health-state changes, OOMs, exits, failed/unknown execs and new sampled probe
failures remain individual evidence. Final container snapshots keep full probe
logs. Tables have a bounded reader; old records and old archives remain readable.
See the [exact format](bundle-protocol.md#compact-statistics-and-successful-health-checks).

## Measured replay

Offline replay of one retained diagnostic window reduced host JSONL from about
39.8 MiB to 15.2 MiB (62%) and Docker JSONL from 40.0 MiB to 23.0 MiB (42%).
All 25,994 supplied Docker stats objects round-tripped exactly, and failed probe
output and parsed JSON status values were compared unchanged. This includes the
benefit of installing the earlier journal compaction on a helper whose captured
output still lacked it. It is not entirely incremental to an already-updated
native helper. Private logs and host identifiers are not included in this repo.

This is a replay of retained evidence, not proof of full-day production coverage.
The sample has gaps; bursts, container counts and workloads can change. Do not
lower limits until a complete new reporting window confirms adequate headroom.
The reported reduction applies to uncompressed evidence, where the caps apply,
not the already-compressed archive size.

Reproduce on an authorized local archive (read-only):

```bash
python3 scripts/benchmark-compaction.py /path/BUNDLE.tar.gz \
  --marker /path/BUNDLE.ready.json
```

## Roll out the reviewed revision

1. Merge/review through the normal GitHub workflow. In Komodo, pull that revision
   and **rebuild/redeploy the existing collector service**. These images are
   locally built; a pull-only operation does not rebuild them. Keep one collector
   and one uploader for this host. Preserve the existing volumes, credentials,
   configured caps and data paths. Do not start a second stack.
2. Update the separately installed **native host helper from the same checkout**.
   Rebuilding the container does not update `/opt/homelab-health`. From that
   reviewed checkout on the host, run:

   ```bash
   sudo bash scripts/prepare-host.sh
   sudo systemctl restart homelab-health-host.service
   sudo systemctl status homelab-health-host.service --no-pager
   ```

   The installer preserves `/etc/homelab-health/host.toml` and existing `.env`.
   Review any explicit opt-outs; absent keys default to compaction enabled.
   This step restarts only the diagnostic helper, not monitored applications.
3. Update offline readers to this revision before reading the new stats-table
   format. Bundled README text describes it for reviewers. The trusted reader is
   `homelab_health.tables.unpack_stats`; do not run archive-supplied code.
4. Confirm collector/helper status is fresh and healthy. After a complete new
   reporting window, verify: journal `data.summaries` are present; stats tables
   decode; source-byte-limit notices are gone or their omitted times improved;
   final daily checks are included; failures remain visible. An old `gap.json`
   can persist, so compare its timestamp with the new window.

Opt-outs (no limit changes):

- Collector config: `compact_stats = false`, `compact_health_successes = false`;
  rebuild/redeploy collector after editing its built-in config.
- Root-owned host config: `compact_journal_denials = false`,
  `compact_json_checks = false`; restart only the native helper after editing.

Rollback code using the same deployment process while preserving spool/outbox
and uploader state. Keep the new reader available for archives already written
with table records; an older reader will not understand those statistics.
