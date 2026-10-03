#!/usr/bin/env python3
"""Offline replay of a verified archive. Never modify inputs or run bundled code."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from homelab_health.bundle import read_verified_bundle
from homelab_health.noise import compact_health_successes, compact_journal, compact_json_text
from homelab_health.tables import pack_stats, unpack_stats


def size(record):
    return len(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()) + 1


def benchmark(contents):
    before, after, counts = Counter(), Counter(), Counter()
    pending, minute = [], None
    source = {}
    def flush():
        if not pending:
            return
        values = [record['data'] for record in pending]
        try:
            packed = pack_stats(values)
            assert unpack_stats(packed) == values, 'Stats changed in round-trip'
            packed_size = size({**pending[-1], 'kind': 'docker_stats_table', 'data': packed})
        except ValueError:
            packed_size = sum(size(record) for record in pending)
        after['docker_stats'] += min(packed_size, sum(size(record) for record in pending))
        counts['stats_verified'] += len(pending)
        pending.clear()
    for path, raw in sorted(contents.items()):
        if not (path.startswith(('host/evidence-', 'docker/evidence-')) and path.endswith('.jsonl')):
            continue
        for line in raw.splitlines():
            record = json.loads(line)
            kind, data = record['kind'], record['data']
            source[kind] = path.split('/')[0]
            before[kind] += len(line) + 1
            if kind == 'docker_stats':
                key = record['at'][:16]
                if minute != key or len(pending) >= 128:
                    flush()
                    minute = key
                pending.append(record)
                continue
            if kind in ('kernel_journal', 'unit_journal', 'journal_warnings'):
                rows = data.get('rows', [])
                kept, groups, duplicates = compact_journal(rows)
                data.update(rows=kept, summaries=data.get('summaries', []) + groups,
                            exported_rows_before_compaction=data.get('exported_rows_before_compaction', len(rows)),
                            duplicate_rows_removed=data.get('duplicate_rows_removed', 0) + duplicates)
            elif kind in ('links', 'routes', 'mounts'):
                old = data
                data = compact_json_text(data)
                if data.get('json_whitespace_compacted'):
                    assert json.loads(data['text']) == json.loads(old['text'])
                record['data'] = data
            elif kind == 'docker_state':
                compact = compact_health_successes(data)
                old_probes = data.get('health', {}).get('log', [])
                new_probes = compact.get('health', {}).get('log', [])
                for old, new in zip(old_probes, new_probes):
                    if old.get('ExitCode') != 0:
                        assert old == new, 'Failed probe changed'
                record['data'] = compact
            after[kind] += size(record)
    flush()
    domains = {}
    for domain in ('host', 'docker'):
        kinds = [k for k in before if source[k] == domain]
        old = sum(before[k] for k in kinds)
        new = sum(after[k] for k in kinds)
        domains[domain] = {'before_bytes': old, 'after_bytes': new,
                           'reduction_percent': round(100*(1-new/old), 2) if old else None}
    return {'domains': domains, 'counts': counts,
            'kinds': {k: {'before_bytes': before[k], 'after_bytes': after[k]} for k in before},
            'limitations': 'Replay only of captured records; cannot recover missing periods. Stats grouped by recorded minute to approximate a collection cycle. No host access, deployment or size-limit change.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--marker', type=Path, required=True)
    args = parser.parse_args()
    _, _, contents = read_verified_bundle(args.archive, args.marker)
    print(json.dumps(benchmark(contents), indent=2))
