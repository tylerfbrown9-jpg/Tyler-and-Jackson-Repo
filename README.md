# Windows Security Log Forensics Analyzer

IT 360 final project by Tyler Brown and Jackson.

**Video presentation:**

## Overview

A command line tool that reads Windows Security event logs (`.evtx`) and turns raw events into findings an investigator can act on. Instead of listing events, it correlates them into attack patterns, tags each finding with a MITRE ATT&CK technique, and (planned) scores logon behavior against a baseline and renders a timeline.

## Features

| Feature | Status |
|---|---|
| Parse `.evtx` into a normalized table, skipping corrupt records | Done |
| Brute force detection (4625 bursts by IP or local workstation, followed by 4624 success) | Done |
| Suspicious process creation (4688): known attacker tools, user-writable folders | Done |
| Privileged logon followed by process execution (4672 + 4688) | Done |
| Account creation and privileged group changes (4720, 4728, 4732, 4756) | Done |
| Log clearing (1102) | Planned |
| MITRE ATT&CK mapping on every finding | In progress |
| Logon baseline and anomaly scoring | Planned |
| HTML report: summary, per-file table, severity-sorted findings, ATT&CK links, filters | Done |
| Analyze many logs or whole folders in one run, one combined report | Done |
| Interactive timeline dashboard | Planned |

## Setup

Requires Python 3.10 or newer. Clone the repo somewhere outside OneDrive.

**Windows (Command Prompt):**

```
git clone https://github.com/tylerfbrown9-jpg/Tyler-and-Jackson-Repo.git
cd Tyler-and-Jackson-Repo
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**Mac / Linux:**

```
git clone https://github.com/tylerfbrown9-jpg/Tyler-and-Jackson-Repo.git
cd Tyler-and-Jackson-Repo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The prompt should start with `(.venv)` once the environment is active.

## Usage

Run it on a bundled sample log (Windows paths shown; use `/` on Mac/Linux):

```
python src\main.py data\samples\DE_RDP_Tunnel_5156.evtx
```

Then open `output\report.html` in a browser (`start output\report.html` on Windows). The same findings are in `output\findings.json`.

### Analyze many logs at once

Pass any mix of files and folders. Folders are searched recursively, each log is analyzed on its own, and everything goes into one combined report:

```
python src\main.py data\datasets data\samples
python src\main.py data\datasets\deepblue\smb-password-guessing-security.evtx data\samples
```

All 28 included logs take about 75 seconds.

### Reading the report

- **Summary:** totals, a plain-language overview, the most serious findings, and a table by ATT&CK technique.
- **Files analyzed:** events, findings per severity and the most common event IDs for each log, plus any logs that could not be read.
- **Findings:** sorted by severity. Repeats of the same finding for the same file, account and host are merged into one row with a count (`findings.json` keeps every finding). Use the severity checkboxes and the search box to filter, for example by technique ID, file name or account.

Options: `--out DIR` changes the output folder, `--limit N` reads only the first N records of each log (quick test on big logs), `-v` shows debug output.

To analyze your own log, export it from an admin terminal on a lab machine, then pass the file path:

```
wevtutil epl Security C:\temp\Security.evtx
python src\main.py C:\temp\Security.evtx
```

Large logs are slow to parse (a 21 MB log takes a few minutes).

Sample logs from the public EVTX-ATTACK-SAMPLES collection are in `data/samples/` (see the README there for what each contains and its license). Expected findings: plink.exe in `DE_RDP_Tunnel_5156` (T1572), Guest and Network Service added to Administrators in `Network_Service_Guest_added_to_admins_4732` (T1098), and the fake computer account in `DE_Fake_ComputerAccount_4720` (T1136). For brute force, use `data/datasets/deepblue/smb-password-guessing-security.evtx`.

## Datasets

Free, public logs are included under `data/` (all licensed for reuse, see each folder):

- `data/samples/`: 7 logs from EVTX-ATTACK-SAMPLES (GPL-3.0)
- `data/datasets/deepblue/`: 6 logs from SANS DeepBlueCLI, including a real SMB password guessing attack (GPL-3.0)
- `data/datasets/evtx-to-mitre/`: 15 logs from EVTX-to-MITRE-Attack, labeled by ATT&CK technique (CC0)

`data/datasets/README.md` lists every file with what the tool reports for it.

## Repository layout

```
src/        parser, detections, entry point
docs/       final report and report assets
data/       sanitized sample logs for demos
```

## Data and privacy

This repository is public. Do not commit real logs. Everything in `data/` comes from free public datasets, with licenses and sources listed in each folder.

## License

MIT
