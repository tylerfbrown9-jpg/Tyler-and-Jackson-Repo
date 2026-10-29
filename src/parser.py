"""EVTX parsing: turn a Windows Security .evtx file into a normalized DataFrame.

Each record becomes one row with a few fixed columns (timestamp, event_id, ...)
plus one column per EventData field (TargetUserName, IpAddress, LogonType, ...).
Bad records are counted and skipped rather than crashing the run.
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
from Evtx.Evtx import Evtx

log = logging.getLogger(__name__)

# Namespace used by every Windows event XML record.
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_record(xml_text: str) -> dict:
    """Flatten one event's XML into a dict."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)

    row = {
        "event_id": int(system.findtext("e:EventID", default="0", namespaces=NS)),
        "timestamp": system.find("e:TimeCreated", NS).get("SystemTime"),
        "record_id": int(system.findtext("e:EventRecordID", default="0", namespaces=NS)),
        "computer": system.findtext("e:Computer", default="", namespaces=NS),
    }

    # EventData holds the fields that differ per event ID.
    for data in root.findall("e:EventData/e:Data", NS):
        name = data.get("Name")
        if name:
            row[name] = data.text
    return row


def parse_evtx(path: str | Path, limit: int | None = None) -> tuple[pd.DataFrame, int]:
    """Parse an .evtx file.

    limit stops after that many records (handy for a quick test on a big log).

    Returns (dataframe, skipped) where skipped is the number of records
    that could not be parsed.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    rows, skipped = [], 0
    with Evtx(str(path)) as log_file:
        for i, record in enumerate(log_file.records(), start=1):
            if limit and i > limit:
                break
            if i % 5000 == 0:
                log.info("  ...read %d records", i)
            try:
                rows.append(_parse_record(record.xml()))
            except Exception as exc:  # corrupt or truncated record
                skipped += 1
                log.debug("Skipping record: %s", exc)

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df, skipped
