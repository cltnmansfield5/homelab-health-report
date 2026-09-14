# Drive text fallback

Some connected Drive runtimes can list binary archives but cannot materialize
their download references. When ordinary Markdown reads work, the uploader also
publishes a lossless text copy in the **same private Inbox**, using its existing
credential and outbound connection. Original archives and markers remain intact.

## Enable and verify

`text_transport = true` is enabled in the bundled `config/upload.toml`.
Rebuild/redeploy the existing uploader from this revision. Completed pairs still
in its outbox are backfilled automatically; keep its state and retry files.
The Ubuntu helper does not need an update for this change. Restarting an old
image does not install the new code.

Status shows `phase: text_transport`, `completed_parts`, and `total_parts` during
upload. Pending upload health becomes OK only after the completion index is
verified. Failures use the existing retry/backoff behavior.

Expect `transport-<archive-sha256>-000.md`, subsequent numbered parts, and finally
`transport-<archive-sha256>.ready.md` in Inbox. Parts without that final index are
incomplete. Do not change folder sharing.

## Consumer procedure

1. List original archive/marker pairs, text indexes, parts, and receipts. Select
   unprocessed bundles chronologically and deduplicate by archive SHA-256.
2. Try the normal authenticated original-file download first. If its bytes cannot
   be materialized, read the matching text index and every listed part using
   Drive's **readable-text fetch**. No inline-binary tool mode is needed.
3. Confirm `archive_id` against the original archive's metadata in Inbox, including
   name/size and the corresponding original completion-marker filename. The index
   embeds the validated original marker; require agreement with any independently
   accessible original marker.
4. Save complete returned text unchanged in a private workspace. Fail closed on
   truncation, missing files, duplicate identities, or hash mismatches.
   Preserve the exact trailing newline; some patch-based writers add a blank
   line. Do not trim or normalize source text to force a hash match.
5. Restore using the reviewed repository code, never bundled code:

   ```bash
   python3 -m homelab_health restore-transport \
     /workspace/parts/transport-SHA256.ready.md \
     --output-dir /workspace/restored --archive-id CONFIRMED_DRIVE_ID
   ```

The decoder verifies part text and decoded byte hashes/sizes, the **original
archive SHA-256 and byte size**, and the original manifest and every member.
Restoration is not a health review. Review all evidence before saving a report
and issuing the original `processed-<sha256>.json` receipt. Its `archive_id`
still identifies the original archive, not the text index or a part.

## Format and bounds

Version 1 uses ASCII Markdown. Each part has a JSON header and a base64 code
block. The header contains `schema_version`, `archive_sha256`, `part_index`,
`decoded_bytes`, and `decoded_sha256`.

The completion index has one JSON code block containing `schema_version: 1`,
`encoding: base64`, `part_bytes: 393216`, `marker`, `archive_id`, and `parts`.
Each ordered part entry records `name`, `file_id`, `part_index`, `decoded_bytes`,
`decoded_sha256`, `text_bytes`, and `text_sha256`. Filenames must match the
archive hash and contiguous zero-based part positions.

Parts encode at most 384 KiB; text files are limited to 600 KiB, the index to
512 KiB, and a transfer to 512 parts (192 MiB of compressed archive). Existing
limits remain: 512 regular members, 16 MiB per member, 160 MiB expanded payload,
and bounded tar metadata. Encoding adds about 35% to archive size, alongside
the original archive. Generation uses one temporary part at a time.

## Retention and failures

Completed text copies use the original full-review receipt and 30-day remote
retention. Recorded Drive IDs, sizes and MD5s must still match before deletion;
the index is removed before parts. Seven-day local retention is unchanged.
Reconstruction alone never issues a processing receipt.

If upload stops before its index/state record is committed, retry reuses
identical filenames and refuses conflicts. Partial files remain ineligible for
automatic cleanup until upload completes and a valid receipt exists. Turning
the fallback off does not delete copies. Base64 is encoding, **not encryption
or extra redaction**: protect these files like the diagnostic archives.
