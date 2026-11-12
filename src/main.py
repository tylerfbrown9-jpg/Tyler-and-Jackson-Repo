"""Command line entry point for the Windows Security Log Forensics Analyzer.

Usage:
    python src/main.py Security.evtx
    python src/main.py data/datasets data/samples --out output/

Each argument can be a .evtx file or a folder (searched recursively). Every
log is analyzed on its own, then all results go into one combined report.
"""

import argparse
import json
import logging
from pathlib import Path

from detections import DETECTORS
from parser import parse_evtx
from report import build_report, sort_findings

log = logging.getLogger("analyzer")


def collect_files(paths: list[str]) -> list[tuple[Path, str]]:
    """Expand files and folders into (path, display label) pairs, without duplicates."""
    found, seen = [], set()
    for arg in paths:
        p = Path(arg)
        if p.is_dir():
            candidates = [(f, f.relative_to(p.parent).as_posix()) for f in sorted(p.rglob("*.evtx"))]
        elif p.is_file():
            candidates = [(p, p.name)]
        else:
            raise FileNotFoundError(f"Not a file or folder: {arg}")
        for f, label in candidates:
            if f.resolve() not in seen:
                seen.add(f.resolve())
                found.append((f, label))
    if not found:
        raise FileNotFoundError("No .evtx files found in the given paths")
    return found


def analyze(path: Path, label: str, limit: int | None) -> dict:
    """Parse one log and run every detector on it. Never raises: problems go in the result."""
    result = {"file": label, "events": 0, "skipped": 0, "error": None,
              "first": None, "last": None, "top_ids": "", "findings": []}
    try:
        df, skipped = parse_evtx(path, limit=limit)
    except Exception as exc:  # a library error on one odd file should not stop the batch
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result["events"], result["skipped"] = len(df), skipped
    if df.empty:
        return result

    result["first"], result["last"] = df["timestamp"].min(), df["timestamp"].max()
    top = df["event_id"].value_counts().head(5)
    result["top_ids"] = ", ".join(f"{k} (x{v})" for k, v in top.items())

    # Detectors run per file on purpose: mixing hosts and dates from different logs
    # would create correlations that never happened.
    for detector in DETECTORS:
        try:
            found = detector(df)
        except Exception as exc:  # keep the other detectors running
            log.warning("%s failed on %s: %s", detector.__name__, label, exc)
            continue
        for finding in found:
            finding["source_file"] = label
            result["findings"].append(finding)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze Windows Security .evtx logs.")
    ap.add_argument("paths", nargs="+", help="one or more .evtx files or folders")
    ap.add_argument("--out", default="output", help="directory for results (default: output/)")
    ap.add_argument("--limit", type=int, help="only read the first N records of each log (quick test)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show debug output")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    try:
        files = collect_files(args.paths)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    results = []
    for i, (path, label) in enumerate(files, start=1):
        print(f"[{i}/{len(files)}] {label}")
        r = analyze(path, label, args.limit)
        results.append(r)
        if r["error"]:
            print(f"    could not read: {r['error']}")
        else:
            print(f"    {r['events']} events ({r['skipped']} skipped), {len(r['findings'])} finding(s)")

    findings = sort_findings([f for r in results for f in r["findings"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
    print(f"\n{len(results)} file(s), {sum(r['events'] for r in results)} events, "
          f"{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings, indent=2))
    (out / "report.html").write_text(build_report(results), encoding="utf-8")
    print(f"Wrote {out / 'report.html'} and {out / 'findings.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
