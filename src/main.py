"""Command line entry point for the Windows Security Log Forensics Analyzer.

Usage:
    python src/main.py path/to/Security.evtx --out output/
"""

import argparse
import json
import logging
from pathlib import Path

from detections import DETECTORS
from parser import parse_evtx


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze a Windows Security .evtx log.")
    ap.add_argument("evtx", help="path to the .evtx file")
    ap.add_argument("--out", default="output", help="directory for results (default: output/)")
    ap.add_argument("--limit", type=int, help="only read the first N records (quick test)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show debug output")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    try:
        df, skipped = parse_evtx(args.evtx, limit=args.limit)
    except (FileNotFoundError, OSError) as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Parsed {len(df)} events ({skipped} records skipped)")
    if not df.empty:
        # Quick overview of what the log contains, most common event IDs first.
        counts = df["event_id"].value_counts().head(8)
        print("Top event IDs: " + ", ".join(f"{k} (x{v})" for k, v in counts.items()))

    findings = []
    for detector in DETECTORS:
        findings.extend(detector(df))
    print(f"{len(findings)} finding(s)")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings, indent=2))
    print(f"Wrote {out / 'findings.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
