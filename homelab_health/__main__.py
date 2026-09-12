import argparse
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request

from .common import Redactor, load_config, lock, now, parse_time, read_json


def main():
    parser = argparse.ArgumentParser(prog="homelab-health")
    sub = parser.add_subparsers(dest="role", required=True)
    proxy = sub.add_parser("proxy")
    proxy.add_argument("--socket", default="/var/run/docker.sock")
    proxy.add_argument("--bind", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=2375)
    for role in ("host", "collector", "upload"):
        item = sub.add_parser(role)
        item.add_argument("--config", default="/config/" + role + ".toml")
        item.add_argument("--once", action="store_true")
        if role == "host":
            item.add_argument("--output", default="/var/lib/homelab-health/host")
            item.add_argument("--sample-only", action="store_true")
    bundle = sub.add_parser("bundle")
    bundle.add_argument("--config", default="/config/collector.toml")
    for role in ("verify", "report"):
        item = sub.add_parser(role)
        item.add_argument("archive")
        item.add_argument("--marker", required=True)
        if role == "report":
            item.add_argument("--output", required=True)
            item.add_argument("--previous")
    health = sub.add_parser("health")
    health.add_argument("--status")
    health.add_argument("--url")
    health.add_argument("--max-age", type=int, default=300)
    args = parser.parse_args()
    if args.role == "proxy":
        from .proxy import Server
        Server((args.bind, args.port), args.socket).serve_forever()
    elif args.role == "host":
        from .host import HostHelper
        helper = HostHelper(load_config(args.config), args.output)
        if args.once:
            with lock(Path(args.output) / ".helper.lock"):
                helper.once(full=not args.sample_only)
        else:
            helper.run()
    elif args.role in ("collector", "bundle"):
        from .collector import Collector
        collector = Collector(load_config(args.config, {"hostname": "HH_HOSTNAME", "timezone": "HH_TIMEZONE"}))
        if args.role == "bundle" or args.once:
            with lock(collector.state / ".collector.lock"):
                collector.sample()
                print(json.dumps(collector.bundle()))
        else:
            collector.run()
    elif args.role == "upload":
        from .uploader import Uploader
        uploader = Uploader(load_config(args.config, {"remote": "HH_DRIVE_REMOTE", "inbox_folder_id": "HH_INBOX_FOLDER_ID", "reports_folder_id": "HH_REPORTS_FOLDER_ID"}))
        if args.once:
            with lock(uploader.state / ".uploader.lock"):
                result = uploader.once()
                print(json.dumps(result))
                return 1 if result["failures"] or result["issues"] or result["pending_uploads"] else 0
        uploader.run()
    elif args.role == "verify":
        from .bundle import read_verified_bundle
        marker, manifest, contents = read_verified_bundle(args.archive, args.marker)
        print(json.dumps({"verified": True, "sha256": marker["sha256"], "members": len(contents), "issues": manifest["issues"]}))
    elif args.role == "report":
        from .report import report
        result = report(args.archive, args.marker, args.output, read_json(args.previous) if args.previous else None)
        print(json.dumps({"report": args.output, "findings": len(result["findings"])}))
    elif args.role == "health":
        if args.url:
            target = urllib.parse.urlsplit(args.url)
            if target.scheme != "http" or not target.hostname or target.username or target.password or target.path != "/_ping" or target.query or target.fragment:
                raise ValueError("Health URL must be an HTTP gateway /_ping endpoint")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(args.url, timeout=5) as response:
                return 0 if response.status == 200 else 1
        value = read_json(args.status)
        age = (now() - parse_time(value["at"])).total_seconds()
        return 0 if value.get("ok") and -30 <= age <= args.max_age else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(Redactor().text(f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        sys.exit(1)
