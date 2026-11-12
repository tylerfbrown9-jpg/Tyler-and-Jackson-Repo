"""Build one self-contained HTML report from the results of one or more analyzed logs.

Each result is a dict made by main.analyze():
    file, events, skipped, error, first, last, top_ids, findings

All values come from log files we do not control, so everything is escaped
before it goes into the page.
"""

from datetime import datetime, timezone
from html import escape

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Keys every finding has; anything else is shown in the details column.
CORE_KEYS = {"pattern", "mitre", "severity", "start", "end", "source_file"}

# Readable names for the techniques the detectors currently emit.
TECHNIQUE_NAMES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1078": "Valid Accounts",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1136": "Create Account",
    "T1204.002": "User Execution: Malicious File",
    "T1569.002": "System Services: Service Execution",
    "T1572": "Protocol Tunneling",
}

MAX_DETAIL_VALUES = 6

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:1150px;margin:2rem auto;padding:0 1rem;color:#1b1f23}
h1{margin-bottom:.2rem} h2{margin-top:2rem} .sub{color:#57606a;margin-top:0}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}
.card{border:1px solid #d0d7de;border-radius:8px;padding:.8rem 1.2rem;min-width:130px}
.card b{display:block;font-size:1.6rem}
.summary{background:#f6f8fa;border:1px solid #d0d7de;border-radius:8px;padding:.2rem 1.2rem 1rem}
table{border-collapse:collapse;width:100%;margin-top:.5rem}
th,td{border:1px solid #d0d7de;padding:.45rem .65rem;text-align:left;vertical-align:top;font-size:.9rem}
th{white-space:nowrap} td.nw{white-space:nowrap} td.wrap{overflow-wrap:anywhere} td.file{min-width:220px}
th{background:#f6f8fa} td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{font-weight:600;padding:.1rem .5rem;border-radius:10px;color:#fff}
.high{background:#cf222e}.medium{background:#bf8700}.low{background:#57606a}
.none{padding:1rem;border:1px dashed #d0d7de;border-radius:8px;color:#57606a}
.filters{margin:.8rem 0;display:flex;gap:1rem;align-items:center;flex-wrap:wrap}
.filters input[type=search]{padding:.3rem .5rem;min-width:260px}
.muted{color:#57606a} .x{font-weight:600;color:#57606a}
dl{margin:0} dt{font-weight:600;display:inline} dd{display:inline;margin:0 0 0 .3rem} .kv{display:block}
"""

FILTER_JS = """
(function(){
var rows=[].slice.call(document.querySelectorAll('#findings tr[data-sev]'));
var boxes=[].slice.call(document.querySelectorAll('.filters input[type=checkbox]'));
var q=document.getElementById('q'), shown=document.getElementById('shown');
function apply(){
  var on={}; boxes.forEach(function(b){on[b.getAttribute('data-sev')]=b.checked;});
  var t=q.value.toLowerCase(), n=0;
  rows.forEach(function(r){
    var ok=on[r.getAttribute('data-sev')]&&(!t||r.textContent.toLowerCase().indexOf(t)>-1);
    r.style.display=ok?'':'none'; if(ok){n++;}
  });
  shown.textContent=n+' of '+rows.length+' shown';
}
boxes.forEach(function(b){b.addEventListener('change',apply);});
q.addEventListener('input',apply); apply();
})();
"""


def sort_findings(findings: list[dict]) -> list[dict]:
    """Most severe first, then oldest first."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["start"]))


def group_findings(findings: list[dict]) -> list[dict]:
    """Merge repeats of the same finding (same file, account, host, source) into one row.

    A log with 15 near-identical group changes becomes one row marked "x15"
    instead of 15 rows. The JSON output keeps every finding unmerged.
    """
    groups: dict[tuple, dict] = {}
    for f in sort_findings(findings):
        key = (f.get("source_file"), f["severity"], f["pattern"], f["mitre"],
               f.get("account"), f.get("host"), f.get("source"))
        g = groups.setdefault(key, {
            "severity": f["severity"], "pattern": f["pattern"], "mitre": f["mitre"],
            "file": f.get("source_file"), "count": 0, "start": f["start"], "end": f["end"],
            "details": {},
        })
        g["count"] += 1
        g["start"], g["end"] = min(g["start"], f["start"]), max(g["end"], f["end"])
        for k, v in f.items():
            if k in CORE_KEYS or v in (None, "", []):
                continue
            seen = g["details"].setdefault(k, [])
            for x in (v if isinstance(v, list) else [v]):
                x = str(x)
                if x not in seen and x != "…":
                    if len(seen) < MAX_DETAIL_VALUES:
                        seen.append(x)
                    elif seen[-1] != "…":
                        seen.append("…")
    return sorted(groups.values(), key=lambda g: (SEVERITY_ORDER.get(g["severity"], 9), g["start"]))


def _technique_link(tid: str) -> str:
    """Link a technique ID (T1110 or T1003.001) to its ATT&CK page, with its name if known."""
    path = tid.replace(".", "/")
    name = TECHNIQUE_NAMES.get(tid)
    label = f"{escape(tid)} {escape(name)}" if name else escape(tid)
    return f'<a href="https://attack.mitre.org/techniques/{escape(path)}/">{label}</a>'


def _details(details: dict) -> str:
    items = [f'<span class="kv"><dt>{escape(k)}:</dt><dd>{escape(", ".join(v))}</dd></span>'
             for k, v in details.items()]
    return "<dl>" + "".join(items) + "</dl>"


def _fmt_time(iso: str) -> str:
    return iso[:19].replace("T", " ")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _unreadable(r: dict) -> bool:
    """True when nothing could be read from the file."""
    return bool(r["error"]) or (r["events"] == 0 and r["skipped"] > 0)


def _summary_html(results: list[dict], groups: list[dict]) -> str:
    findings = [f for r in results for f in r["findings"]]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    total_events = sum(r["events"] for r in results)
    unreadable = [r for r in results if _unreadable(r)]
    readable = [r for r in results if not _unreadable(r)]
    clean = [r for r in readable if not r["findings"]]

    firsts = [r["first"] for r in results if r["first"] is not None]
    lasts = [r["last"] for r in results if r["last"] is not None]
    span = f" spanning {min(firsts):%Y-%m-%d} to {max(lasts):%Y-%m-%d}" if firsts else ""

    techniques: dict[str, dict] = {}
    for r in results:
        for f in r["findings"]:
            t = techniques.setdefault(f["mitre"], {"count": 0, "files": set(), "worst": 9})
            t["count"] += 1
            t["files"].add(r["file"])
            t["worst"] = min(t["worst"], SEVERITY_ORDER.get(f["severity"], 9))

    sentences = [f"Analyzed {_plural(len(results), 'log file')} containing {total_events:,} events{span}."]
    if findings:
        sentences.append(
            f"The analyzer reported {_plural(len(findings), 'finding')}: {counts['high']} high, "
            f"{counts['medium']} medium and {counts['low']} low, covering "
            f"{_plural(len(techniques), 'MITRE ATT&CK technique')}.")
    else:
        sentences.append("The analyzer reported no findings. That means none of its implemented "
                         "detections matched, not that the logs are clean.")
    if len(results) > 1:
        note = f"{len(clean)} of {len(readable)} readable files produced no findings."
        if unreadable:
            note += f" {_plural(len(unreadable), 'file')} could not be read."
        sentences.append(note)

    top = [g for g in groups if g["severity"] == "high"][:5]
    if top:
        items = "".join(
            f"<li>{escape(g['pattern'])} ({escape(g['mitre'])})"
            + (f", {escape(str(g['details']['account'][0]))}" if g["details"].get("account") else "")
            + (f", x{g['count']}" if g["count"] > 1 else "")
            + (f" <span class='muted'>in {escape(g['file'])}</span>" if len(results) > 1 and g["file"] else "")
            + "</li>" for g in top)
        top_html = f"<p><b>Most serious findings</b></p><ul>{items}</ul>"
    else:
        top_html = "<p><b>Most serious findings:</b> none rated high.</p>" if findings else ""

    tech_html = ""
    if techniques:
        sev_name = {v: k for k, v in SEVERITY_ORDER.items()}
        rows = "".join(
            f"<tr><td>{_technique_link(tid)}</td><td class='num'>{t['count']}</td>"
            f"<td class='num'>{len(t['files'])}</td>"
            f"<td><span class='sev {sev_name.get(t['worst'], 'low')}'>{sev_name.get(t['worst'], '')}</span></td></tr>"
            for tid, t in sorted(techniques.items(), key=lambda kv: (kv[1]["worst"], -kv[1]["count"])))
        tech_html = ("<p><b>By ATT&amp;CK technique</b></p><table><tr><th>Technique</th>"
                     f"<th>Findings</th><th>Files</th><th>Highest severity</th></tr>{rows}</table>")

    cards = (f"<div class='cards'><div class='card'><b>{len(results)}</b>files</div>"
             f"<div class='card'><b>{total_events:,}</b>events parsed</div>"
             f"<div class='card'><b>{counts['high']}</b>high</div>"
             f"<div class='card'><b>{counts['medium']}</b>medium</div>"
             f"<div class='card'><b>{counts['low']}</b>low</div></div>")

    return (f"<h2>Summary</h2>{cards}<div class='summary'><p>{escape(' '.join(sentences))}</p>"
            f"{top_html}{tech_html}</div>")


def _files_html(results: list[dict]) -> str:
    rows = []
    for r in results:
        sev = {s: sum(1 for f in r["findings"] if f["severity"] == s) for s in SEVERITY_ORDER}
        if r["error"]:
            note = "error: " + r["error"]
        elif _unreadable(r):
            note = f"could not read ({r['skipped']} records skipped)"
        elif not r["findings"]:
            note = "no findings"
        else:
            note = f"{r['skipped']} records skipped" if r["skipped"] else ""
        rows.append(
            f"<tr><td class='wrap'>{escape(r['file'])}</td><td class='num'>{r['events']:,}</td>"
            f"<td class='num'>{sev['high']}</td><td class='num'>{sev['medium']}</td><td class='num'>{sev['low']}</td>"
            f"<td>{escape(r.get('top_ids') or '')}</td><td class='muted'>{escape(note)}</td></tr>")
    return ("<h2>Files analyzed</h2><table><tr><th>File</th><th>Events</th><th>High</th><th>Medium</th>"
            f"<th>Low</th><th>Most common event IDs</th><th>Notes</th></tr>{''.join(rows)}</table>")


def _findings_html(groups: list[dict], multi: bool) -> str:
    if not groups:
        return ("<h2>Findings</h2><p class='none'>No findings. None of the implemented detections "
                "matched. That does not prove the host is clean; it only means these specific "
                "patterns were not present.</p>")
    rows = []
    for g in groups:
        times = escape(_fmt_time(g["start"]))
        if g["count"] > 1 and g["end"] != g["start"]:
            times += f"<br><span class='muted'>to {escape(_fmt_time(g['end']))}</span>"
        label = escape(g["pattern"]) + (f" <span class='x'>x{g['count']}</span>" if g["count"] > 1 else "")
        file_cell = f"<td class='wrap file'>{escape(g['file'] or '')}</td>" if multi else ""
        rows.append(
            f"<tr data-sev='{escape(g['severity'])}'><td class='nw'><span class='sev {escape(g['severity'])}'>"
            f"{escape(g['severity'])}</span></td><td>{label}</td><td>{_technique_link(g['mitre'])}</td>"
            f"{file_cell}<td class='nw'>{times}</td><td class='wrap'>{_details(g['details'])}</td></tr>")
    file_head = "<th>File</th>" if multi else ""
    filters = ("<div class='filters'><b>Show:</b>"
               "<label><input type='checkbox' data-sev='high' checked> High</label>"
               "<label><input type='checkbox' data-sev='medium' checked> Medium</label>"
               "<label><input type='checkbox' data-sev='low' checked> Low</label>"
               "<input type='search' id='q' placeholder='Filter by file, account, technique...'>"
               "<span id='shown' class='muted'></span></div>")
    note = ("<p class='muted'>Repeats of the same finding for the same file, account and host are "
            "merged into one row with a count. findings.json keeps every finding separately.</p>")
    return (f"<h2>Findings</h2>{note}{filters}<table id='findings'><tr><th>Severity</th><th>Finding</th>"
            f"<th>ATT&amp;CK</th>{file_head}<th>Time (UTC)</th><th>Details</th></tr>{''.join(rows)}</table>"
            f"<script>{FILTER_JS}</script>")


def build_report(results: list[dict]) -> str:
    """Return the full HTML page for a list of per-file results."""
    all_findings = [f for r in results for f in r["findings"]]
    groups = group_findings(all_findings)
    multi = len(results) > 1
    source = results[0]["file"] if len(results) == 1 else f"{len(results)} files"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security Log Analysis Report</title>
<style>{CSS}</style></head><body>
<h1>Security Log Analysis Report</h1>
<p class="sub">Source: {escape(source)} &middot; generated {generated}</p>
{_summary_html(results, groups)}
{_files_html(results)}
{_findings_html(groups, multi)}
</body></html>
"""
