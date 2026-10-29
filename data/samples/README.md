# Sample logs

These `.evtx` files come from the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
collection by Samir Bousseaden (GPL-3.0, license copied here as `LICENSE.GPL`).
They are unmodified copies, included so the tool can be run and demoed without
any setup. The project's own code is MIT licensed; these data files are not.

| File | What it contains |
|---|---|
| `DE_RDP_Tunnel_5156.evtx` | RDP tunneling: logons (4624), explicit creds (4648), special privileges (4672), process creation (4688) |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | Lateral movement through a remote scheduled task |
| `DE_1102_security_log_cleared.evtx` | Security log cleared (1102) |
| `DE_Fake_ComputerAccount_4720.evtx` | Account creation (4720) |
| `Network_Service_Guest_added_to_admins_4732.evtx` | Group membership change (4732) |
| `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | One failed and several successful interactive logons |
| `kerberos_pwd_spray_4771.evtx` | Kerberos password spray |

Note: most files in the original collection end with a 1102 event because the
log was cleared after the attack was recorded. Treat a lone 1102 at the end of
a sample as an artifact of how it was captured, not as the attack itself.

None of these contain a burst of failed logons (4625), so the brute force
detector needs a log generated in a lab VM to demo.
