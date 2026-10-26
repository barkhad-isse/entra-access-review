"""Command line entry point.

    entra-access-review --demo                     # offline, bundled sample tenant
    entra-access-review --snapshot snapshot.json   # analyse a saved snapshot
    entra-access-review                            # live, reads AZURE_* env vars
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from importlib import resources
from pathlib import Path

from .report import print_console, summary, write_csv, write_html, write_json
from .rules import SEVERITY_ORDER, Config, analyse


def _load_live() -> dict:
    from .collector import collect_snapshot
    from .graph_client import GraphClient

    missing = [v for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET") if not os.environ.get(v)]
    if missing:
        sys.exit(f"Missing environment variables: {', '.join(missing)} (or use --demo)")
    client = GraphClient(os.environ["AZURE_TENANT_ID"], os.environ["AZURE_CLIENT_ID"],
                         os.environ["AZURE_CLIENT_SECRET"])
    return collect_snapshot(client)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only access review of Microsoft Entra ID.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--demo", action="store_true", help="use the bundled sample tenant (no Azure needed)")
    src.add_argument("--snapshot", type=Path, help="analyse a previously saved snapshot JSON")
    p.add_argument("--save-snapshot", type=Path, help="save the collected raw snapshot to this file")
    p.add_argument("--out", type=Path, default=Path("reports"), help="output folder (default: reports)")
    p.add_argument("--inactive-days", type=int, default=90)
    p.add_argument("--break-glass", action="append", default=[], metavar="UPN",
                   help="documented emergency access account; not flagged for standing access (repeatable)")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit with code 2 if any finding is at or above this severity (for CI/scheduling)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    if args.demo:
        snapshot = json.loads(resources.files("entra_access_review.data").joinpath("sample_tenant.json").read_text())
    elif args.snapshot:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    else:
        snapshot = _load_live()

    if args.save_snapshot:
        args.save_snapshot.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    break_glass = {b.lower() for b in args.break_glass} | {b.lower() for b in snapshot.get("breakGlassAccounts", [])}
    cfg = Config(inactive_days=args.inactive_days, break_glass=break_glass)
    if snapshot.get("collectedAt"):
        # Measure inactivity relative to when the snapshot was taken, so old snapshots give stable results
        cfg.now = datetime.fromisoformat(snapshot["collectedAt"].replace("Z", "+00:00"))

    findings = analyse(snapshot, cfg)
    stats = summary(snapshot, findings)

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(args.out / "findings.csv", findings)
    write_json(args.out / "findings.json", stats, findings)
    write_html(args.out / "report.html", stats, findings)
    print_console(stats, findings)
    print(f"Reports written to {args.out}/ (findings.csv, findings.json, report.html)")

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
