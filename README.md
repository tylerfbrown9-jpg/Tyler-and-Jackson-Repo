# Windows Security Log Forensics Analyzer

IT 360 final project by Tyler Brown and Jackson.

**Video presentation:** _link goes here (unlisted YouTube/Vimeo)_

## Overview

A command line tool that reads Windows Security event logs (`.evtx`) and turns raw events into findings an investigator can act on. Instead of listing events, it correlates them into attack patterns, tags each finding with a MITRE ATT&CK technique, and (planned) scores logon behavior against a baseline and renders a timeline.

## Features

| Feature | Status |
|---|---|
| Parse `.evtx` into a normalized table, skipping corrupt records | Done |
| Brute force detection (4625 bursts, followed by 4624 success) | Done |
| Privilege escalation / suspicious process creation (4672, 4688) | Planned |
| Log clearing, account creation, group changes (1102, 4720, 4732) | Planned |
| MITRE ATT&CK mapping on every finding | In progress |
| Logon baseline and anomaly scoring | Planned |
| HTML timeline dashboard | Planned |

## Setup

Requires Python 3.10 or newer.

```bash
git clone https://github.com/tylerfbrown9-jpg/Tyler-and-Jackson-Repo.git
cd Tyler-and-Jackson-Repo
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py path/to/Security.evtx --out output/
```

Results are written to `output/findings.json`. Add `-v` for debug output.

Sample logs from the public EVTX-ATTACK-SAMPLES collection are in `data/samples/` (see the README there for what each one contains and its license). Try one:

```bash
python src/main.py data/samples/DE_RDP_Tunnel_5156.evtx
```

The parser handles all of them. The only detector so far looks for brute force, and none of the samples contain failed-logon bursts, so expect "0 finding(s)" until more detectors are added or you generate a log in a lab VM.

## Repository layout

```
src/        parser, detections, entry point
docs/       final report and report assets
data/       sanitized sample logs for demos
```

## Data and privacy

This repository is public. Do not commit real logs. Sample data in `data/` must be synthetic (Atomic Red Team in a lab VM) or from public datasets such as Mordor/Security Datasets.

## License

MIT
