"""Build a self-contained HTML report from the parsed events and findings.

All values come from log files we do not control, so everything is escaped
before it goes into the page.
"""

from datetime import datetime, timezone
from html import escape

import pandas as pd

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Keys every finding has; anything else is shown in the details column.
CORE_KEYS = {"pattern", "mitre", "severity", "start", "end"}

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f23}
h1{margin-bottom:.2rem} .sub{color:#57606a;margin-top:0}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}
.card{border:1px solid #d0d7de;border-radius:8px;padding:.8rem 1.2rem;min-width:150px}
.card b{display:block;font-size:1.6rem}
table{border-collapse:collapse;width:100%;margin-top:.5rem}
th,td{border:1px solid #d0d7de;padding:.5rem .7rem;text-align:left;vertical-align:top;font-size:.92rem}
th{background:#f6f8fa}
.sev{font-weight:600;padding:.1rem .5rem;border-radius:10px;color:#fff}
.high{background:#cf222e}.medium{background:#bf8700}.low{background:#57606a}
.none{padding:1rem;border:1px dashed #d0d7de;border-radius:8px;color:#57606a}
dl{margin:0} dt{font-weight:600;display:inline} dd{display:inline;margin:0 0 0 .3rem} .kv{display:block}
"""


def _technique_link(tid: str) -> str:
    """Link a technique ID (T1110 or T1003.001) to its ATT&CK page."""
    path = tid.replace(".", "/")
    return f'<a href="https://attack.mitre.org/techniques/{escape(path)}/">{escape(tid)}</a>'


def _details(finding: dict) -> str:
    items = []
    for key, value in finding.items():
        if key in CORE_KEYS or value in (None, "", []):
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        items.append(f'<span class="kv"><dt>{escape(key)}:</dt><dd>{escape(str(value))}</dd></span>')
    return "<dl>" + "".join(items) + "</dl>"


def sort_findings(findings: list[dict]) -> list[dict]:
    """Most severe first, then oldest first."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["start"]))


def build_report(findings: list[dict], df: pd.DataFrame, source: str, skipped: int) -> str:
    findings = sort_findings(findings)

    if df.empty:
        span, hosts = "n/a", "n/a"
    else:
        span = f"{df['timestamp'].min():%Y-%m-%d %H:%M} to {df['timestamp'].max():%Y-%m-%d %H:%M} UTC"
        hosts = ", ".join(sorted(set(df["computer"].dropna()))[:3]) or "n/a"

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    top_ids = ", ".join(f"{k} (x{v})" for k, v in df["event_id"].value_counts().head(8).items()) if not df.empty else "n/a"

    if findings:
        rows = "".join(
            f"<tr><td><span class='sev {escape(f['severity'])}'>{escape(f['severity'])}</span></td>"
            f"<td>{escape(f['pattern'])}</td><td>{_technique_link(f['mitre'])}</td>"
            f"<td>{escape(f['start'][:19].replace('T', ' '))}</td><td>{_details(f)}</td></tr>"
            for f in findings
        )
        table = ("<table><tr><th>Severity</th><th>Finding</th><th>ATT&amp;CK</th>"
                 f"<th>Time (UTC)</th><th>Details</th></tr>{rows}</table>")
    else:
        table = ("<p class='none'>No findings. None of the implemented detections matched "
                 "this log. That does not prove the host is clean; it only means these specific "
                 "patterns were not present.</p>")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security Log Analysis Report</title>
<style>{CSS}</style></head><body>
<h1>Security Log Analysis Report</h1>
<p class="sub">Source: {escape(source)} &middot; generated {generated}</p>
<div class="cards">
<div class="card"><b>{len(df)}</b>events parsed</div>
<div class="card"><b>{counts['high']}</b>high</div>
<div class="card"><b>{counts['medium']}</b>medium</div>
<div class="card"><b>{counts['low']}</b>low</div>
</div>
<p><b>Time range:</b> {escape(span)}<br><b>Host:</b> {escape(hosts)}<br>
<b>Most common event IDs:</b> {escape(top_ids)}<br><b>Records skipped:</b> {skipped}</p>
<h2>Findings</h2>
{table}
</body></html>
"""
