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


PRIVILEGED_LOGON = 4672
PROCESS_CREATED = 4688
ACCOUNT_CREATED = 4720
GROUP_MEMBER_ADDED = {4728, 4732, 4756}  # global, local, universal security groups

# Accounts that always show up in 4672 and are not interesting on their own.
SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

# Executables that are rarely legitimate on a normal host, mapped to ATT&CK.
KNOWN_TOOLS = {
    "plink.exe": ("SSH tunneling tool (plink)", "T1572"),
    "psexec.exe": ("Remote execution tool (PsExec)", "T1569.002"),
    "psexesvc.exe": ("Remote execution service (PsExec)", "T1569.002"),
    "mimikatz.exe": ("Credential dumping tool (Mimikatz)", "T1003.001"),
    "procdump.exe": ("Process dumper (possible LSASS dump)", "T1003.001"),
    "nc.exe": ("Netcat", "T1095"),
    "ncat.exe": ("Netcat", "T1095"),
}

# Folders a normal user can write to; legitimate software rarely runs from here.
USER_WRITABLE_PATHS = ("\\desktop\\", "\\downloads\\", "\\temp\\")

# Well-known RIDs/SIDs for groups that grant broad control.
PRIVILEGED_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
}
PRIVILEGED_GROUP_RIDS = {"-512": "Domain Admins", "-518": "Schema Admins", "-519": "Enterprise Admins"}


def _has(df: pd.DataFrame, *cols: str) -> bool:
    """True if the DataFrame has every column (they are missing when no event used them)."""
    return not df.empty and all(c in df.columns for c in cols)


def _is_system_account(name) -> bool:
    """Machine accounts, built-in service accounts, and per-session helper accounts."""
    if not isinstance(name, str) or not name:
        return True
    return (
        name.upper() in SYSTEM_ACCOUNTS
        or name.endswith("$")
        or name.upper().startswith(("DWM-", "UMFD-"))
    )


def detect_suspicious_process(df: pd.DataFrame) -> list[dict]:
    """Process creation (4688) of known attacker tools or from user-writable folders."""
    if not _has(df, "event_id", "NewProcessName"):
        return []

    findings = []
    for _, ev in df[df["event_id"] == PROCESS_CREATED].iterrows():
        path = ev["NewProcessName"]
        if not isinstance(path, str):
            continue
        exe = path.rsplit("\\", 1)[-1].lower()

        if exe in KNOWN_TOOLS:
            label, technique = KNOWN_TOOLS[exe]
            severity = "high"
        elif any(p in path.lower() for p in USER_WRITABLE_PATHS):
            label, technique, severity = "Process started from a user-writable folder", "T1204.002", "low"
        else:
            continue

        findings.append({
            "pattern": label,
            "mitre": technique,
            "severity": severity,
            "start": ev["timestamp"].isoformat(),
            "end": ev["timestamp"].isoformat(),
            "account": ev.get("SubjectUserName"),
            "host": ev.get("computer"),
            "process": path,
            "command_line": ev.get("CommandLine") if isinstance(ev.get("CommandLine"), str) else None,
        })
    return findings


def detect_privileged_logon_then_process(df: pd.DataFrame, window: str = "10min") -> list[dict]:
    """A privileged logon (4672) followed by a process started by the same account.

    Ordinary admin work looks like this too, so on its own it is only medium
    severity. It matters when combined with the other detectors or a baseline.
    """
    if not _has(df, "event_id", "SubjectUserName", "NewProcessName"):
        return []

    win = pd.Timedelta(window)
    procs = df[df["event_id"] == PROCESS_CREATED]
    findings = []

    for _, logon in df[df["event_id"] == PRIVILEGED_LOGON].iterrows():
        user = logon["SubjectUserName"]
        if _is_system_account(user):
            continue
        followed = procs[
            (procs["SubjectUserName"] == user)
            & (procs["timestamp"] >= logon["timestamp"])
            & (procs["timestamp"] <= logon["timestamp"] + win)
        ]
        if followed.empty:
            continue
        findings.append({
            "pattern": "Privileged logon followed by process execution",
            "mitre": "T1078",
            "severity": "medium",
            "start": logon["timestamp"].isoformat(),
            "end": followed["timestamp"].max().isoformat(),
            "account": user,
            "host": logon.get("computer"),
            "process_count": int(len(followed)),
            "processes": sorted(set(followed["NewProcessName"].dropna()))[:10],
        })
    return findings


def detect_account_and_group_changes(df: pd.DataFrame, window: str = "1h") -> list[dict]:
    """New accounts (4720) and members added to security groups (4728/4732/4756).

    Adding someone to Administrators or a domain admin group is high severity.
    A new account that is then added to such a group is flagged as one chain.
    """
    findings = []
    win = pd.Timedelta(window)

    created = df[df["event_id"] == ACCOUNT_CREATED] if _has(df, "event_id") else df.iloc[0:0]
    added = df[df["event_id"].isin(GROUP_MEMBER_ADDED)] if _has(df, "event_id") else df.iloc[0:0]

    # Work out which group additions hit a privileged group.
    privileged_adds = []
    for _, ev in added.iterrows():
        sid = ev.get("TargetSid") if isinstance(ev.get("TargetSid"), str) else ""
        group = PRIVILEGED_GROUP_SIDS.get(sid) or next(
            (name for rid, name in PRIVILEGED_GROUP_RIDS.items() if sid.endswith(rid)), None
        )
        privileged_adds.append((ev, group))

    for ev, group in privileged_adds:
        findings.append({
            "pattern": "Member added to " + (f"privileged group ({group})" if group else "security group"),
            "mitre": "T1098",
            "severity": "high" if group else "low",
            "start": ev["timestamp"].isoformat(),
            "end": ev["timestamp"].isoformat(),
            "account": ev.get("SubjectUserName"),
            "host": ev.get("computer"),
            "group": ev.get("TargetUserName"),
            "member_sid": ev.get("MemberSid"),
        })

    for _, ev in created.iterrows():
        # Did the same new account land in a privileged group soon after?
        chained = any(
            group and add.get("MemberSid") == ev.get("TargetSid")
            and ev["timestamp"] <= add["timestamp"] <= ev["timestamp"] + win
            for add, group in privileged_adds
        )
        name = ev.get("SamAccountName")
        findings.append({
            "pattern": "Account created then added to privileged group" if chained else "Account created",
            "mitre": "T1136",
            "severity": "high" if chained else "medium",
            "start": ev["timestamp"].isoformat(),
            "end": ev["timestamp"].isoformat(),
            "account": ev.get("SubjectUserName"),
            "host": ev.get("computer"),
            "new_account": name,
            "new_account_sid": ev.get("TargetSid"),
        })
    return findings


# Register detectors here. main.py runs every function in this list.
DETECTORS = [
    detect_brute_force,
    detect_suspicious_process,
    detect_privileged_logon_then_process,
    detect_account_and_group_changes,
]
