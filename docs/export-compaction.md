# Lossless export references (opt-in)

`compact_evidence = true` in the collector enables the export-only `refs-v1`
format. It defaults to **false**, including when the setting is absent. Upgrade
all readers before enabling it. The trusted project reporter reads both legacy
and new records, mixed within a member. Older reporters do not understand new
records and may fail or misinterpret them; leave this setting off for them.
The outer archive/marker protocol remains schema version 1.

This format preserves every selected record, original value, sample, container
identity, journal identity and timestamp. It does not change collection frequency,
raw persistent spools, update policy, existing exec/journal grouping, or successful
probe handling. The existing 40 MiB per-source and 128 MiB bundle limits are
unchanged. Export compaction runs **before** the source limit is applied, allowing
more captured records to fit. It cannot recover evidence already absent from a
spool or an older capped archive.

## Wire format

Only changed records gain `"export_encoding":"refs-v1"`. This top-level key is
reserved; attempting to export an already-encoded spool fails rather than nesting
or guessing its meaning. The original `schema_version`, `kind`, `at` and other
fields are retained. A record without this marker is literal legacy data.

Eligible fields are:

- `mounts`, `dns_state`, `routes`: `data.text`, separately namespaced by kind
- `docker_stats_table` using `dict-columns-v1`: each `data.tables[].columns`
- `docker_exec_summary`: `data.attributes`

The first eligible value of at least 128 serialized bytes becomes
`{"define":0,"value":<original value>}`. A repeat becomes `{"ref":0}`.
IDs are zero-based, consecutive across definitions within that member; a reference
must resolve to the same field namespace. Definitions count toward the byte cap.
Reference values are interpreted only at these explicit fields in marked records;
keys inside literal values never become protocol. Other fields, including failed
check status, stats rows/indexes, exec actions/timeNano and container IDs, stay
literal. Small/new values after the bounded dictionary fills remain literal.
No references cross a JSONL member boundary, midnight alone does not reset one,
and a new bundle always starts with fresh state.

Journal `data.summaries[].occurrences` may become:

~~~json
{"encoding":"sha256-b64-us-delta-v1","base":"1700000000000000","pairs":[["<canonical base64 of all 32 SHA-256 bytes>",0]]}
~~~

Each pair reconstructs `[original_lowercase_hex_hash, str(int(base)+offset)]`.
Offsets are exact signed integers, with no floating point conversion. Pair order,
duplicates, hash width and microseconds are unchanged. Noncanonical hashes or
timestamp strings (leading zeros, signs, non-ASCII digits), numeric timestamp
values, and values outside unsigned 64-bit range remain in their original list
form. Packing is used only when that representation is smaller. Counts, examples,
signatures and first/last metadata are unchanged. Decode first, then deduplicate
journal occurrences or expand stats using the existing trusted helpers.

## Bounded reading and recovery

Instantiate `homelab_health.evidence.EvidenceDecoder` once **per member**, process
lines in order, and call `decode(json.loads(line))`. Never execute files supplied
inside a diagnostic archive. Archive hashes must be verified before interpretation.
The member's manifest entry declares `evidence_encoding: refs-v1` when enabled.

The decoder rejects unknown versions, extra wrapper fields, missing or forward references,
duplicate/nonconsecutive IDs, bool IDs, wrong namespaces/types, invalid base64,
malformed occurrence pairs, and excessive expansion. Definitions are transactional:
a bad record cannot install partial dictionary state. Once a marked record fails,
subsequent marked records in that member fail too. A caller must also mark the
member failed on invalid JSON or invalid record metadata (the reporter does so).
Literal records remain independently readable; the next member resets the decoder.
Do not start from an arbitrary line or concatenate members with one decoder.

Bounds are 2 MiB per encoded/decoded record, 4,096 definitions and 8 MiB of
literal dictionary bytes, 32,768 pairs per packed occurrence list, 128 stats-table
groups, 64 MiB decoded per member, and 256 MiB decoded JSON evidence per report (not a process-memory/RSS limit). The
writer also resets at the decoded-member limit, and limits each decoded source
to 128 MiB, so its two sources fit that report budget. Expansion is checked before
copying referenced values. Limits become explicit coverage gaps, never guessed
values. Post-redaction oversized records emit `export_record_size_limit`;
`decoded_source_byte_limit` and the existing `source_byte_limit` include the first
omitted record's UTC timestamp. These safety limits do not promise complete coverage.

Members still stop only between complete records and are at most 8 MiB encoded.
The first record after a reset is re-encoded against an empty dictionary. Retrying
an export of the same raw input reconstructs the same evidence bytes; no persisted
dictionary state is needed. A missing/damaged member cannot invalidate dictionaries
in later members, although the complete archive must still fail integrity checks
until the authentic original is recovered. Do not edit hashes to hide corruption.

## Verify, roll out and roll back

1. Run `python3 -m unittest discover -v`, the existing demo and release/CI checks.
   Review the patch and exact commit before any publication or deployment.
2. Upgrade the reporter and every other consumer first. Keep `compact_evidence =
   false` while validating an existing legacy archive and synthetic mixed-format
   fixtures. Retain the updated decoder for historical compacted archives.
3. In an approved deployment, set `compact_evidence = true` for the collector.
   No host-helper/spool migration is required. Preserve existing configuration,
   volumes and automation/update policies. No live rollout is part of this patch.
4. Verify a newly produced archive/marker and all member hashes. Compare decoded
   records against the retained raw spool, and check sample counts, identities,
   timestamp ranges, findings and every source/daily/bundle coverage issue.
5. After a complete requested window, verify actual final coverage and remaining
   headroom. Do not infer success from extrapolation or a partial first window.
   The unrelated historical Docker event-connection gap remains a separate issue.

Rollback: disable `compact_evidence` before reverting consumers; future exports
return to literal records. Already-produced compacted bundles still require the
new decoder. Raw spools were never changed and can be re-exported while retained.
Do not delete pending bundles or fabricate processing receipts during rollback.

## Reproducible replay

~~~bash
python3 scripts/benchmark-export-compaction.py ARCHIVE.tar.gz --marker ARCHIVE.ready.json
~~~

The script verifies archive/member integrity, replays captured records through the
real exporter with 8 MiB resets, checks exact record equality/order, and compares
reporter trends, coverage, deduplicated counters and substantive findings. It prints
only aggregate measurements and uses temporary spools. It also measures gzip with
identical reconstructed tar metadata on both sides and the corresponding 384 KiB
transport part count. It does not write or publish an archive. It cannot supply
missing tails or prove that a future full window fits the unchanged source caps.
