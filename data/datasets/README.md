# Datasets

Real Windows event logs from free, public sources, used to test and demo the analyzer.
All files are unmodified `.evtx` copies (some renamed to avoid spaces and long paths; the original
path is listed). They are data files only. The tool parses them as text records and never executes
anything inside them. Logs come from lab machines, not real organizations.

Run any of them the same way:

```
python src/main.py data/datasets/deepblue/smb-password-guessing-security.evtx
```

Also see `data/samples/` for the first set of samples (EVTX-ATTACK-SAMPLES).

## DeepBlueCLI sample logs (`deepblue/`)

- Source: [sans-blue-team/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI), `evtx/` folder
- License: GPL-3.0 (copy in `deepblue/LICENSE.GPL`)

| File | Original path in source repo | Events | What the tool reports |
|---|---|---|---|
| `smb-password-guessing-security.evtx` | `DeepBlueCLI evtx/smb-password-guessing-security.evtx` | 3561 | Brute force logon attempts (T1110, medium) |
| `password-spray.evtx` | `DeepBlueCLI evtx/password-spray.evtx` | 295 | none |
| `sliver-security.evtx` | `DeepBlueCLI evtx/sliver-security.evtx` | 528 | 5x Privileged logon followed by process execution (T1078, medium) |
| `new-user-security.evtx` | `DeepBlueCLI evtx/new-user-security.evtx` | 4 | Account created then added to privileged group (T1136, high); Member added to privileged group (Administrators) (T1098, high); 2x Member added to security group (T1098, low) |
| `psattack-security.evtx` | `DeepBlueCLI evtx/psattack-security.evtx` | 24 | 2x Process started from a user-writable folder (T1204.002, low) |
| `many-events-security.evtx` | `DeepBlueCLI evtx/many-events-security.evtx` | 13223 | Account created then added to privileged group (T1136, high); Member added to privileged group (Administrators) (T1098, high); 2x Member added to security group (T1098, low); 19x Process started from a user-writable folder (T1204.002, low) |

Highlights: `smb-password-guessing-security.evtx` is a real SMB password guessing attack, 3,561 failed
logons from one address in under three minutes, and is the best brute force demo. `password-spray.evtx`
is logged as 294 explicit-credential events (4648) and no failed logons, so the current detectors do not
flag it; a 4648-based spray detector is planned. `many-events-security.evtx` is a larger mixed log (13k
events, about 45 seconds to parse) that suits baseline scoring.

## EVTX to MITRE ATT&CK (`evtx-to-mitre/`)

- Source: [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
- License: CC0 1.0, public domain (copy in `evtx-to-mitre/LICENSE.CC0`)
- The source repo organizes about 290 logs by ATT&CK tactic and technique. The filename prefix here
  (`T1098_`, `T1136_`, ...) is that technique ID, which gives each log a known expected technique to
  check the analyzer against.

| File | Original path in source repo | Events | What the tool reports |
|---|---|---|---|
| `T1110_ID-4776-4625-AccountRestore-local-bruteforce.evtx` | `TA0006-Credential Access/T1110.xxx-Brut force/ID 4776,4625-AccountRestore local bruteforce.evtx` | 16 | Brute force logon attempts (T1110, medium) |
| `T1098_ID4756-Exchange-admin-group-change.evtx` | `TA0003-Persistence/T1098.xxx-Account manipulation/ID4756-Exchange admin group change.evtx` | 15 | 15x Member added to security group (T1098, low) |
| `T1098_ID4728-Massive-account-group-membership-change.evtx` | `TA0003-Persistence/T1098.xxx-Account manipulation/ID4728-Massive account group membership change.evtx` | 11 | 11x Member added to security group (T1098, low) |
| `T1098_ID4728-4756-Member-added-to-sensitive-domain-groups.evtx` | `TA0003-Persistence/T1098.xxx-Account manipulation/ID4728-4756-Member added to sensitive domain groups.evtx` | 4 | Member added to privileged group (Domain Admins) (T1098, high); Member added to privileged group (Enterprise Admins) (T1098, high); Member added to privileged group (Schema Admins) (T1098, high); Member added to security group (T1098, low) |
| `T1098_ID4732-User-added-to-local-admin-groups.evtx` | `TA0003-Persistence/T1098.xxx-Account manipulation/ID4732-User added to local admin groups.evtx` | 3 | Member added to privileged group (Administrators) (T1098, high); 2x Member added to security group (T1098, low) |
| `T1136_ID4688-User-creation-via-commandline.evtx` | `TA0003-Persistence/T1136-Create account/ID4688-User creation via commandline.evtx` | 9 | Account created (T1136, medium); 2x Member added to security group (T1098, low) |
| `T1136_ID472-4728-Hidden-user-creation.evtx` | `TA0003-Persistence/T1136-Create account/ID472, 4728 Hidden user creation.evtx` | 21 | Account created then added to privileged group (T1136, high); Member added to privileged group (Administrators) (T1098, high); Member added to security group (T1098, low) |
| `T1136_ID4720-Admin-like-user-created.evtx` | `TA0003-Persistence/T1136-Create account/ID4720-Admin like user created.evtx` | 1 | Account created (T1136, medium) |
| `T1047_ID4688-5145-WMIexec-execution-via-SMB.evtx` | `TA0002-Execution/T1047-Windows Management Instrumentation/ID4688-5145-WMIexec execution via SMB.evtx` | 1023 | 7x Privileged logon followed by process execution (T1078, medium) |
| `T1003_ID4688-4663-4656-LSASS-dump-with-LSASSY-process-.evtx` | `TA0006-Credential Access/T1003-Credential dumping/ID4688-4663-4656-LSASS dump with LSASSY (process).evtx` | 28 | 5x Privileged logon followed by process execution (T1078, medium) |
| `T1003_ID4756-Exchange-critical-group-change-DCsync-.evtx` | `TA0006-Credential Access/T1003-Credential dumping/ID4756-Exchange critical group change (DCsync).evtx` | 3 | 3x Member added to security group (T1098, low) |
| `T1021.002_ID4688-4697-5140-5145-PSexec-remote-execution-admin-share.evtx` | `TA0008-Lateral Movement/T1021.002-SMB Windows Admin Shares/ID4688,4697,5140-5145 PSexec remote execution + admin share.evtx` | 30 | Remote execution service (PsExec) (T1569.002, high) |
| `T1550_ID4624-Mimikatz-Pass-the-hash.evtx` | `TA0008-Lateral Movement/T1550-Use Alternate Authentication Material/ID4624-Mimikatz Pass the hash.evtx` | 8 | Privileged logon followed by process execution (T1078, medium) |
| `APT_ID4720-4698-Fortinet-APT-group-abuse-on-Windows.evtx` | `EVTX_full_APT_attack_steps/ID4720,4698-Fortinet APT group abuse on Windows.evtx` | 3 | 2x Account created (T1136, medium) |
| `T1134_ID4688-4648-4624-Runas-execution-with-different-user.evtx` | `TA0004-Privilege Escalation/T1134-Access Token Manipulation/ID4688,4648,4624-Runas execution with different user.evtx` | 9 | Privileged logon followed by process execution (T1078, medium) |

## Notes and limits

- Findings above are what the analyzer reports today, not a claim that every attack in a log is caught.
  Some logs show an attack through event IDs we do not detect yet (for example PowerShell logging, 4103/4104).
- About 5% of the logs in the EVTX-to-MITRE collection (15 of 293) cannot be read by the `python-evtx`
  library because of how their chunks are structured. The tool reports them as 0 events parsed with a skip
  count and continues; none of them are included here.
- Severity labels are the tool's own heuristics, not a verdict. Lab logs contain normal admin activity too.
