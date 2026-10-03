import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_health.bundle import read_verified_bundle
from homelab_health.collector import Collector
from homelab_health.common import Redactor
from homelab_health.noise import compact_health_successes, compact_json_text, compact_journal
from homelab_health.report import analyze
from homelab_health.tables import pack_stats, unpack_stats
from tests.fixtures import AT, FakeDocker
from tests.test_noise import denial, records


def stat(n):
    return {"id": str(n).zfill(64), "name": "/fixture", "read": AT.isoformat(),
            "cpu_stats": {"total_usage": 123456789012345678 + n, "system_cpu_usage": 999999999999999999,
                          "online_cpus": 16, "throttling_data": {"periods": 0, "throttled_time": 0}},
            "memory_stats": {"usage": 1000, "limit": 8192, "stats": {"inactive_file": 100}},
            "networks": {"eth0": {"rx_bytes": n, "tx_bytes": 12, "rx_dropped": 0}},
            "blkio_stats": {"io_service_bytes_recursive": [{"major": 8, "minor": 0, "op": "write", "value": n}],
                            "io_serviced_recursive": None}, "empty": {}}


class TableTests(unittest.TestCase):
    def test_exact_roundtrip_variable_shapes_signs_and_integer_precision(self):
        samples = [stat(n) for n in range(30)]
        samples[2]['memory_stats']['stats']['unexpected'] = -123
        samples[3]['networks'] = {}
        samples[4]['networks']['eth1'] = {'rx_bytes': 0}
        packed = pack_stats(samples)
        self.assertEqual(unpack_stats(packed), samples)
        self.assertLess(len(json.dumps(packed)), len(json.dumps(samples)) * .7)
        self.assertEqual(samples[0]['cpu_stats']['total_usage'], 123456789012345678)

    def test_untrusted_table_bounds_and_conflicting_paths(self):
        good = pack_stats([stat(0), stat(1)])
        bad = []
        for key, value in [('samples', True), ('samples', 129), ('samples', 1), ('encoding', 'unknown')]:
            x=copy.deepcopy(good);x[key]=value;bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['columns'][1]=x['tables'][0]['columns'][0];bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['columns'][1]=x['tables'][0]['columns'][0]+['child'];bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['rows'][0].pop();bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['indexes']=[0,0];bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['indexes']=[False,1];bad.append(x)
        x=copy.deepcopy(good);x['tables'][0]['columns'][0]=['x']*9;bad.append(x)
        for x in bad:
            with self.subTest(data=str(x)[:100]), self.assertRaises(ValueError):unpack_stats(x)
        with self.assertRaises(ValueError):pack_stats([stat(0)]*129)
        with self.assertRaises(ValueError):pack_stats([{'v':'x'*1048576}])

    def test_report_marks_bad_tables_as_coverage_gaps_and_reads_old_records(self):
        marker={'sha256':'a'*64,'hostname':'fixture','requested_start_utc':AT.isoformat(),
                'requested_end_utc':AT.isoformat(),'collection_finished_utc':AT.isoformat()}
        rows=[{'schema_version':1,'kind':'docker_stats_table','at':AT.isoformat(),'data':pack_stats([stat(0)])},
              {'schema_version':1,'kind':'docker_stats','at':AT.isoformat(),'data':stat(1)},
              {'schema_version':1,'kind':'docker_stats_table','at':AT.isoformat(),'data':{'encoding':'broken'}}]
        result=analyze(marker,{'files':[],'issues':[]},{'docker/evidence-000.jsonl':b'\n'.join(json.dumps(r).encode() for r in rows)})
        self.assertTrue(any('Invalid records' in f['message'] for f in result['findings']))


class HealthAndJournalTests(unittest.TestCase):
    def test_only_long_success_text_omitted_and_failures_are_preserved(self):
        success={'Start':'start','End':'end','ExitCode':0,'Output':'ok '*1000}
        failed={**success,'ExitCode':1,'Output':'diagnostic '*1000}
        missing={k:v for k,v in failed.items() if k!='ExitCode'}
        state={'health':{'status':'healthy','log':[success,failed,missing,{**success,'Output':'ok'}]}}
        result=compact_health_successes(state)
        self.assertEqual(result['health']['log'][1:],state['health']['log'][1:])
        probe=result['health']['log'][0]
        self.assertTrue(probe['successful_output_omitted']);self.assertEqual(probe['output_bytes'],3000)
        self.assertEqual(probe['Start'],'start');self.assertNotIn('Output',probe)
        self.assertIn('Output',state['health']['log'][0])
        for status in ('unhealthy','starting',None):
            state['health']['status']=status
            self.assertEqual(compact_health_successes(state),state)

    def test_suppression_group_keeps_counts_boots_and_event_identities_distinct(self):
        rows=[denial(n,MESSAGE='kauditd_printk_skb: 14 callbacks suppressed') for n in range(10)]
        rows += [denial(20,MESSAGE='kauditd_printk_skb: 9 callbacks suppressed')]
        unknown=denial(21,MESSAGE='other_source: 14 callbacks suppressed')
        critical=denial(22,MESSAGE='kauditd_printk_skb: 14 callbacks suppressed',PRIORITY='2')
        kept,summaries,_=compact_journal(rows+[unknown,critical])
        self.assertEqual(len(summaries),1);self.assertEqual(summaries[0]['kind'],'kernel_callback_suppression')
        self.assertEqual(summaries[0]['count'],10);self.assertIn('14 callbacks',summaries[0]['signature'])
        self.assertEqual(len(kept),3);self.assertIn(critical,kept);self.assertIn(unknown,kept)

    def test_json_whitespace_only_valid_complete_success(self):
        source={'ok':True,'text':json.dumps({'nested':['a',{'n':-5,'null':None}]},indent=4),'returncode':0}
        result=compact_json_text(source)
        self.assertEqual(json.loads(result['text']),json.loads(source['text']))
        self.assertTrue(result['json_whitespace_compacted']);self.assertEqual(result['returncode'],0)
        for change in ({'ok':False},{'truncated':True},{'timed_out':True},{'text':'warning\n{}'}):
            bad={**source,**change};self.assertEqual(compact_json_text(bad),bad)


class SamplingTests(unittest.TestCase):
    class Docker(FakeDocker):
        failure=False
        def containers(self):return [{'Id':str(n).zfill(64),'Names':['/fixture'],'Labels':{}} for n in range(20)]
        def stats(self,container):
            value=stat(int(container));value['token']='very-private-fixture';return value
        def inspect(self,container):
            value=super().inspect(container)
            value['health']={'status':'healthy','failing_streak':0,'log':[{'Start':'start','End':'end',
                'ExitCode':1 if self.failure else 0,'Output':'very-private-fixture '*100}]}
            return value

    def test_cycle_retains_every_sample_redacts_before_packing_and_emits_probe_failure(self):
        with tempfile.TemporaryDirectory() as root:
            docker=self.Docker();collector=Collector({'data_dir':root,'redact_literals':['very-private-fixture']},docker)
            self.assertTrue(collector.sample());first=records(Path(root)/'samples')
            tables=[r for r in first if r['kind']=='docker_stats_table'];self.assertEqual(len(tables),1)
            samples=unpack_stats(tables[0]['data']);self.assertEqual(len(samples),20)
            self.assertNotIn('very-private-fixture',json.dumps(first))
            self.assertTrue(all(s['token']=='[REDACTED]' for s in samples))
            docker.failure=True;collector.sample()
            states=[r['data'] for r in records(Path(root)/'samples') if r['kind']=='docker_state']
            self.assertEqual(len(states),40)
            self.assertTrue(all('Output' in s['health']['log'][0] for s in states[20:]))
            # Full final inspect snapshots remain unchanged by periodic compaction.
            self.assertIn('Output',docker.inspect('0')['health']['log'][0])

    def test_new_tables_survive_archive_verification_and_final_probe_output_stays_full(self):
        with tempfile.TemporaryDirectory() as root:
            c = Collector({'data_dir': root, 'redact_literals': ['very-private-fixture']}, self.Docker())
            c.sample()
            marker = c.bundle()
            _, manifest, contents = read_verified_bundle(
                c.outbox / marker['archive_name'], c.outbox / (marker['bundle_id'] + '.ready.json'))
            tables = [json.loads(line) for name, raw in contents.items()
                      if name.startswith('docker/evidence-') for line in raw.splitlines()
                      if json.loads(line)['kind'] == 'docker_stats_table']
            self.assertEqual(sum(len(unpack_stats(row['data'])) for row in tables), 20)
            snapshots = [json.loads(raw) for name, raw in contents.items()
                         if name.startswith('docker/') and name.endswith('.json')]
            self.assertEqual(len(snapshots), 20)
            self.assertTrue(all('Output' in row['health']['log'][0] for row in snapshots))
            self.assertNotIn(b'very-private-fixture', b''.join(contents.values()))
            summary = analyze(marker, manifest, contents)
            self.assertFalse(any('Invalid records' in f['message'] for f in summary['findings']))

    def test_opt_out_and_singleton_fallback_keep_legacy_records(self):
        for config,docker in [({'compact_stats':False,'compact_health_successes':False},self.Docker()),({},FakeDocker())]:
            with tempfile.TemporaryDirectory() as root:
                c=Collector({'data_dir':root,**config},docker);c.sample();rows=records(Path(root)/'samples')
                self.assertTrue(any(r['kind']=='docker_stats' for r in rows))
                self.assertFalse(any(r['kind']=='docker_stats_table' for r in rows))

    def test_stats_failures_remain_individual_errors(self):
        with tempfile.TemporaryDirectory() as root:
            c=Collector({'data_dir':root},self.Docker())
            with patch.object(c.docker,'stats',side_effect=TimeoutError):self.assertFalse(c.sample())
            self.assertEqual(sum(r['kind']=='docker_source_error' for r in records(Path(root)/'samples')),20)
