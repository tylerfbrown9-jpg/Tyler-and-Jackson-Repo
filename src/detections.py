"""Attack pattern detections.

Each detector takes the normalized events DataFrame and returns a list of
findings (plain dicts) so they are easy to dump to JSON and render later.
Add new detectors to DETECTORS at the bottom.
"""

import pandas as pd

FAILED_LOGON = 4625
SUCCESS_LOGON = 4624


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window: str = "5min",
    success_within: str = "10min",
) -> list[dict]:
    """Many failed logons (4625) from one source, optionally followed by a success (4624).

    A success shortly after the failures from the same source means the
    guessing may have worked, so those findings get a higher severity.
    """
    if df.empty or "IpAddress" not in df.columns:
        return []

    findings = []
    failures = df[df["event_id"] == FAILED_LOGON]
    successes = df[df["event_id"] == SUCCESS_LOGON]

    # Group by source address; "-" and blank mean a local/unknown source.
    for ip, group in failures.groupby("IpAddress"):
        if ip in (None, "", "-"):
            continue
        times = group["timestamp"].reset_index(drop=True)
        win = pd.Timedelta(window)

        # Slide a window over the failures and flag the first burst.
        for start in range(len(times)):
            end = times.searchsorted(times[start] + win, side="right")
            if end - start >= threshold:
                last_fail = times[end - 1]
                later_success = successes[
                    (successes["IpAddress"] == ip)
                    & (successes["timestamp"] > last_fail)
                    & (successes["timestamp"] <= last_fail + pd.Timedelta(success_within))
                ]
                findings.append({
                    "pattern": "Brute force logon attempts",
                    "mitre": "T1110",
                    "severity": "high" if not later_success.empty else "medium",
                    "source": ip,
                    "start": times[start].isoformat(),
                    "end": last_fail.isoformat(),
                    "failed_count": int(end - start),
                    "followed_by_success": not later_success.empty,
                    "accounts": sorted(set(group["TargetUserName"].dropna())),
                })
                break  # one finding per source is enough for now
    return findings


# Register detectors here. main.py runs every function in this list.
DETECTORS = [detect_brute_force]
