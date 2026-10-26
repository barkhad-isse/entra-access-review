"""Report output: console summary, CSV, JSON and a self-contained HTML report."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .rules import SEVERITY_ORDER, Finding

COLORS = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}


def summary(snapshot: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    users = snapshot["users"]
    by_sev = Counter(f.severity for f in findings)
    return {
        "collectedAt": snapshot.get("collectedAt"),
        "users": len(users),
        "guests": sum(u["userType"] == "Guest" for u in users),
        "enabled": sum(bool(u["accountEnabled"]) for u in users),
        "roleAssignments": len(snapshot["roleAssignments"]),
        "findings": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
    }


def print_console(stats: dict[str, Any], findings: list[Finding]) -> None:
    print(f"\nEntra ID access review  |  snapshot {stats['collectedAt']}")
    print(f"Users: {stats['users']} ({stats['guests']} guests)  |  role assignments: {stats['roleAssignments']}")
    print("Findings: " + "  ".join(f"{k}={v}" for k, v in stats["bySeverity"].items()) + "\n")
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.rule_id}  {f.title}")
        print(f"           {f.principal}: {f.detail}")
    print()


def write_csv(path: Path, findings: list[Finding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(Finding.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(f.as_dict() for f in findings)


def write_json(path: Path, stats: dict[str, Any], findings: list[Finding]) -> None:
    path.write_text(json.dumps({"summary": stats, "findings": [f.as_dict() for f in findings]},
                               indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(path: Path, stats: dict[str, Any], findings: list[Finding]) -> None:
    e = html.escape
    tiles = "".join(
        f'<div class="tile"><span style="color:{COLORS[s]}">{n}</span>{s}</div>'
        for s, n in stats["bySeverity"].items()
    )
    rows = "".join(
        f'<tr><td><b style="color:{COLORS[f.severity]}">{f.severity}</b></td>'
        f'<td style="white-space:nowrap">{f.rule_id}</td>'
        f"<td>{e(f.title)}</td><td>{e(f.principal)}</td><td>{e(f.detail)}</td>"
        f"<td>{e(f.recommendation)}</td></tr>"
        for f in findings
    )
    path.write_text(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Entra ID Access Review</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem;color:#101828}}
.tiles{{display:flex;gap:1rem;margin:1rem 0 2rem}}.tile{{border:1px solid #eaecf0;border-radius:8px;
padding:.75rem 1.25rem;text-transform:capitalize}}.tile span{{display:block;font-size:1.75rem;font-weight:700}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;vertical-align:top;padding:.5rem;
border-bottom:1px solid #eaecf0}}th{{background:#f9fafb}}
</style></head><body>
<h1>Entra ID Access Review</h1>
<p>Snapshot {e(str(stats['collectedAt']))} &middot; {stats['users']} users ({stats['guests']} guests)
&middot; {stats['roleAssignments']} role assignments &middot; {stats['findings']} findings</p>
<div class="tiles">{tiles}</div>
<table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Principal</th><th>Detail</th>
<th>Recommendation</th></tr>{rows}</table></body></html>""", encoding="utf-8")
