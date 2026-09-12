import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_health.host import HostHelper, host_sample
from tests.fixtures import AT


class HostTests(unittest.TestCase):
    def test_native_proc_parser_and_missing_source(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            sources = {
                "sys/kernel/random/boot_id": "fixture-boot\n", "uptime": "120.4 240\n", "stat": "cpu 10 20 30 40 50 60 70 80 90 0\n",
                "loadavg": "0.1 0.2 0.3 1/100 5\n", "meminfo": "MemTotal: 8000 kB\nMemAvailable: 6000 kB\nSwapTotal: 1000 kB\nSwapFree: 900 kB\n",
                "vmstat": "pswpin 4\npswpout 5\noom_kill 1\n", "net/dev": "header\nheader\n eth0: 100 1 2 3 0 0 0 0 200 4 5 6 0 0 0 0\n",
                "diskstats": "8 0 sda 10 0 30 40 50 0 70 80 0 90 100\n",
                "pressure/cpu": "some avg10=0.10 avg60=0.20 avg300=0.30 total=1000\n",
                "pressure/memory": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            }
            for name, raw in sources.items():
                path = proc / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(raw)
            result = host_sample(proc)
            self.assertEqual(result["memory_kib"]["MemAvailable"], 6000)
            self.assertEqual(result["network_counters"]["eth0"]["tx_bytes"], 200)
            self.assertEqual(result["disk_counters"]["sda"]["read_sectors_512b"], 30)
            self.assertEqual(result["pressure_cpu"]["some"]["total"], 1000)
            self.assertIn("pressure_io", result["errors"])

    def test_configuration_cannot_supply_commands_or_device_options(self):
        with tempfile.TemporaryDirectory() as root:
            for config in ({"job_units": ["backup.service;rm -rf /"]}, {"smart_devices": ["--test=long"]}, {"journal_units": ["../../etc/passwd"]}):
                with self.subTest(config=config), self.assertRaises(ValueError):
                    HostHelper(config, root)

    def test_unavailable_tools_produce_visible_records(self):
        with tempfile.TemporaryDirectory() as root:
            helper = HostHelper({"dns_probe_hosts": [], "filesystem_paths": [], "smart_autodetect": False}, root)
            with patch("homelab_health.host.command", return_value={"ok": False, "error": "command_unavailable"}), patch("homelab_health.host.read_text", return_value="Ubuntu fixture"):
                helper.snapshot(AT, AT)
                helper.daily()
            rows = [json.loads(line) for path in Path(root).glob("*.jsonl") for line in path.read_text().splitlines()]
            self.assertTrue(any(r["kind"] == "failed_units" and not r["data"]["ok"] for r in rows))
            self.assertTrue(any(r["kind"] == "smart" and r["data"].get("error") for r in rows))
