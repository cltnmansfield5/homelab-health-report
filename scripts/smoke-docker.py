#!/usr/bin/env python3
"""Live Docker verification for an isolated runner or explicitly invoked host check.

Creates only randomly named test containers/network, then removes those exact IDs.
No Drive credentials, helper installation, public ports, or existing service changes.
"""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from homelab_health.bundle import read_verified_bundle
from homelab_health.common import Spool, atomic_json, now, stamp
from tests.fixtures import sample

image = sys.argv[1] if len(sys.argv) > 1 else "homelab-health:local"
prefix = "hh-smoke-" + uuid.uuid4().hex[:10]
network = prefix + "-net"
container_ids = []
created_network = False


def docker(*args, timeout=120):
    result = subprocess.run(["docker", *map(str, args)], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def start(*args):
    identity = docker("run", "-d", *args)
    container_ids.append(identity)
    return identity


try:
    with tempfile.TemporaryDirectory(prefix=prefix) as temp:
        root = Path(temp)
        # Match the invoking user so the test remains usable without root chown.
        os.chmod(root, 0o755)
        for name in ("host", "data", "data/outbox", "data/samples", "data/collector-state"):
            (root / name).mkdir(exist_ok=True)
        at = now()
        spool = Spool(root / "host")
        spool.append("host_sample", sample(at - dt.timedelta(seconds=60))["data"], at - dt.timedelta(seconds=60))
        atomic_json(root / "host/status.json", {"at": stamp(at), "ok": True, "hostname": "synthetic-smoke"})
        config = root / "collector.toml"
        config.write_text('docker_url = "http://docker-api:2375"\ndata_dir = "/data"\nhost_dir = "/host"\ninclude_containers = ["' + prefix + '-app"]\n')
        docker("network", "create", "--internal", network)
        created_network = True
        hardening = ["--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:size=32m", "--network", network]
        socket_gid = os.stat("/var/run/docker.sock").st_gid
        gateway = start("--name", prefix + "-api", "--network-alias", "docker-api", *hardening,
                        "--group-add", socket_gid, "-v", "/var/run/docker.sock:/var/run/docker.sock:ro", image, "proxy", "--bind", "0.0.0.0")
        start("--name", prefix + "-app", *hardening, "--entrypoint", "python", image, "-u", "-c",
              "import time; print('ERROR synthetic-smoke token=smoke-secret-value'); time.sleep(180)")
        # Wait at most 15 seconds for the gateway, using a container on its internal network.
        for attempt in range(15):
            try:
                docker("run", "--rm", *hardening, image, "health", "--url", "http://docker-api:2375/_ping")
                break
            except RuntimeError:
                if attempt == 14:
                    raise
                time.sleep(1)
        # Leave one timestamp tick between emitted logs and Docker's --until boundary.
        time.sleep(1)
        output = docker("run", "--rm", *hardening, "-v", f"{root / 'data'}:/data",
                        "-v", f"{root / 'host'}:/host:ro", "-v", f"{config}:/config/collector.toml:ro",
                        image, "collector", "--once", timeout=180)
        marker = json.loads(output)
        outbox = root / "data/outbox"
        _, manifest, contents = read_verified_bundle(outbox / marker["archive_name"], outbox / (marker["bundle_id"] + ".ready.json"))
        raw = b"\n".join(contents.values())
        assert b"synthetic-smoke" in raw and b"smoke-secret-value" not in raw, "Missing fixture or failed redaction"
        assert any(n.startswith("logs/") and b"ERROR synthetic-smoke" in b for n, b in contents.items()), "Docker log was not collected"
        assert not manifest["issues"], manifest["issues"]
        assert any(b'"docker_stats"' in b for n, b in contents.items() if n.startswith("docker/evidence")), "No live Docker stats collected"
        deny = "import urllib.request,urllib.error; r=urllib.request.Request('http://docker-api:2375/containers/create',data=b'{}',method='POST');\ntry:\n urllib.request.urlopen(r); raise SystemExit('mutation unexpectedly allowed')\nexcept urllib.error.HTTPError as e:\n assert e.code==403,e.code"
        docker("run", "--rm", *hardening, "--entrypoint", "python", image, "-c", deny)
        print("Live Docker gateway, logs, stats, bundle integrity, redaction and POST rejection passed.")
finally:
    for identity in reversed(container_ids):
        subprocess.run(["docker", "rm", "--force", identity], capture_output=True, timeout=30)
    if created_network:
        subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=30)
