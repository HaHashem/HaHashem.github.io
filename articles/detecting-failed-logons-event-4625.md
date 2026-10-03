> **Lab write-up.** This was done on my own Windows lab machine. The host and account names are changed (`LAB-PC`, `labuser`) and times are UTC. The queries are templates: index, sourcetype and field names depend on how your logs are ingested. Test them on a short time range first. No employer data is included.

## 1. The question

A failed logon is one of the most common events in a Windows environment and one of the easiest to misread. A single 4625 is usually a typo. Hundreds of them, from one address, against many accounts, are an attack. This write-up shows how I produced real failed logons in a lab, exported the log, triaged it with a script, and what separates a typo from password guessing.

## 2. Reproducing it

I typed a wrong password for my own local account three times at a `runas` prompt. Then I read the live Security log from an Administrator PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
  Format-List TimeCreated, Message
```

Windows records each failure as **Event ID 4625, "An account failed to log on."** This needs the audit policy *Logon, Failure* enabled. You can check it with `auditpol /get /subcategory:"Logon"`.

## 3. Reading one 4625

The message has several blocks. These are the fields that matter:

| Field | Value in the lab | What it tells you |
|---|---|---|
| **Account For Which Logon Failed** (`TargetUserName`) | `labuser` | The account being attacked. |
| **Subject** (`SubjectUserName`) | `LAB-PC$` | The process that *asked* for the logon, usually the machine account. It is **not** the attacker. |
| **Logon Type** | `2` | How the logon was attempted (table below). |
| **Source Network Address** | `127.0.0.1` | Where it came from. Loopback means this machine. |
| **Workstation Name** | `LAB-PC` | The name the client reports. It can be spoofed. |
| **Caller Process / Logon Process** | `svchost.exe` / `User32` | The Windows component handling the prompt. |
| **Status / SubStatus** | `0xC000006D` / `0xC000006A` | The reason (table below). |

Two traps for new analysts. First, the *Subject* block describes who made the request, which for local sign-ins is the computer itself. Look at the *Account For Which Logon Failed* block for the victim. Second, `Status 0xC000006D` is only the generic "logon failure". The real reason is in **SubStatus**.

### Logon types you will meet

| Type | Meaning | Typical source |
|---|---|---|
| 2 | Interactive (keyboard) | Console, lock screen, `runas` |
| 3 | Network | SMB, shares, many remote tools |
| 4 / 5 | Batch / Service | Scheduled tasks, services |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP |

### SubStatus codes worth memorizing

| SubStatus | Meaning | Hunting value |
|---|---|---|
| `0xC000006A` | Account exists, **wrong password** | Guessing against a valid account |
| `0xC0000064` | **Account does not exist** | Username guessing or spraying with a list |
| `0xC0000234` | Account locked out | Follows repeated failures, see Event 4740 |
| `0xC0000072` | Account disabled | Stale or former account is still being tried |
| `0xC000006F` | Outside allowed logon hours | Policy violation |
| `0xC0000070` | Workstation restriction | Account used from the wrong host |

My lab result, `0xC000006A` with type 2 from loopback, reads as: **a valid local user, wrong password, typed at this machine.** Harmless.

## 4. Triage with a script

For anything beyond a few events I do not want to read the message text. I exported the log and ran my [DFIR toolkit](https://github.com/HaHashem/dfir-toolkit) triage script:

```powershell
wevtutil epl Security .\Security.evtx /ow:true
python .\evtx_triage.py .\Security.evtx --ids 4625
```

Real output (trimmed):

```
2026-10-03 06:45:57  4625  LAB-PC  TargetUserName=labuser; SubjectUserName=LAB-PC$; IpAddress=127.0.0.1; LogonType=2; ...
2026-10-03 06:46:01  4625  LAB-PC  TargetUserName=labuser; SubjectUserName=LAB-PC$; IpAddress=127.0.0.1; LogonType=2; ...
2026-10-03 06:46:05  4625  LAB-PC  TargetUserName=labuser; SubjectUserName=LAB-PC$; IpAddress=127.0.0.1; LogonType=2; ...

3 events
```

Three lessons from getting here:
- **An export is a snapshot.** My first run printed `0 events` because the file was exported *before* the failures happened. `Get-WinEvent` reads the live log. The `.evtx` file does not update itself.
- **`wevtutil epl` will not overwrite a file** unless you add `/ow:true`, and exporting the Security log needs an elevated shell.
- **One command per line.** Pasting two commands on one line made `wevtutil` read the second as extra arguments ("Too many arguments are specified").

Working on a copy of the evidence is also good DFIR practice. The script is read-only and never modifies the log.

## 5. Typo, brute force or spray?

The same event ID means very different things depending on the *shape* of the activity:

| Pattern | One account | Many accounts | Source | Likely cause |
|---|---|---|---|---|
| A few failures, then a success (4624) | 1 | 1 | Local or the user's own host | Typo |
| Many failures, **one** account, **many** attempts | 1 | 1 | One address | **Brute force** |
| **One or two** attempts per account, across **many** accounts | many | many | One address or a small set | **Password spray** |
| Many `0xC0000064` (unknown user) | n/a | many | One address | **Username enumeration** |
| Many failures then a success, **type 3 or 10**, from an outside address | 1 | 1 | External | **Possible compromise, escalate** |

Password spraying is the one that slips through, because it stays under lockout thresholds. Count **distinct accounts per source**, not just attempts.

## 6. Hunting queries

### Splunk: failures by source and account
```
index=wineventlog source="WinEventLog:Security" EventCode=4625 earliest=-24h
| stats count dc(Account_Name) as accounts values(Logon_Type) as types by Source_Network_Address
| where count>=20
| sort - count
```

### Splunk: spray pattern (many accounts, few tries each)
```
index=wineventlog source="WinEventLog:Security" EventCode=4625 earliest=-1h
| stats count dc(Account_Name) as accounts by Source_Network_Address
| where accounts>=10 AND count/accounts<=3
```
Field names (`Account_Name`, `Source_Network_Address`) vary with the Windows add-on version. Use `Account_Name` for the *target* block and check which value you get.

### Splunk: failures followed by a success from the same source
```
index=wineventlog source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) earliest=-24h
| eval result=if(EventCode=4625,"fail","success")
| stats count(eval(result="fail")) as fails count(eval(result="success")) as successes by Source_Network_Address, Account_Name
| where fails>=10 AND successes>=1
```
This is the highest-value version: it finds the cases where guessing may have worked.

### Defender / Sentinel KQL
```kql
DeviceLogonEvents
| where Timestamp > ago(24h) and ActionType == "LogonFailed"
| summarize Fails=count(), Accounts=dcount(AccountName), Types=make_set(LogonType)
    by RemoteIP
| where Fails >= 20
| order by Fails desc
```
With Windows Security events in Sentinel, use `SecurityEvent | where EventID == 4625` and summarize on `IpAddress` and `TargetUserName`.

### CrowdStrike Falcon
```
#event_simpleName=UserLogonFailed2
| groupBy([RemoteAddressIP4], function=[count(as=fails), count(UserName, distinct=true, as=accounts)])
| fails > 20
| sort(fails, order=desc)
```
Field names depend on sensor and tenant. Validate on a short range.

## 7. Cross-checking with DeepBlueCLI

I do not rely on one tool. [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) is an open-source PowerShell hunting tool from SANS (by Eric Conrad). It reads event logs, live or from `.evtx` files, and prints findings for patterns such as password guessing, new accounts, suspicious services and encoded PowerShell. It also ships with sample attack logs, which makes it a safe way to practice.

```powershell
.\DeepBlue.ps1 -log security                     # the live Security log
.\DeepBlue.ps1 .\evtx\new-user-security.evtx      # a sample .evtx file
```

**Live log.** DeepBlue reported *"Multiple admin logons for one account"* (Event 4672, count 9) for my own administrator account. That is the pattern it looks for, but here it is normal: Windows records "special privileges assigned" every time an administrator signs in. It would deserve attention if one account logged on as admin across many hosts in a short time.

**Sample log, new account.** On the bundled `new-user-security.evtx`, DeepBlue showed two findings one second apart:

1. **4720, a user was created** (`IEUser`).
2. **4732, a user was added to the local Administrators group**, for the same account SID.

A new account that becomes an administrator within seconds is a classic persistence step (ATT&CK T1136.001 Create Account, T1098 Account Manipulation). The username shows as `-` in the 4732 line because only the SID is recorded, and it matches the SID of the new account. The dates in that file (2013) belong to the sample, not to my machine.

**How the two fit together.** DeepBlue finds patterns quickly. My [triage script](https://github.com/HaHashem/dfir-toolkit) shows the raw events behind them, with every field, and exports to CSV. For a real case I use the first to decide where to look and the second to build the evidence and timeline. Neither replaces reading the event and deciding what it means.

## 8. What I check next

1. **Is there a 4624 after the failures** from the same source? That means the guessing may have worked.
2. **Logon type 3 or 10 from a public IP**, or an IP never seen before for that account.
3. **Lockouts (4740)** and password resets (4723, 4724) around the same time.
4. **Exposure.** Is RDP or SMB reachable from the internet? Check the firewall (see [the ransomware network queries](https://github.com/HaHashem/soc-hunting-queries/blob/main/ransomware/network-firewall-proxy-waf.md)).
5. **The account.** Is it privileged, a service account, or disabled?

## 9. Limits and false positives

- **Services with stale credentials** (a mapped drive, a scheduled task, a phone checking mail) generate steady 4625s that look like attacks. Find the source and fix it.
- **Auditing must be on.** If *Logon, Failure* is not audited, you will see nothing.
- **Network failures may appear on a different host**, such as a domain controller, not the machine being attacked. Check both.
- **Kerberos failures use other events** (4771, 4768 with a failure code), not 4625. NTLM failures on a domain controller are logged in 4776.
- **Workstation name and source IP can be spoofed or proxied.** Treat them as leads.

## 10. Key takeaways

1. **4625 is a failed logon.** The victim is in *Account For Which Logon Failed*. The *Subject* is usually the machine.
2. **SubStatus gives the real reason.** `0xC000006A` is a wrong password for a real user, `0xC0000064` is an unknown user.
3. **Logon type and source address decide the severity.** A type 2 from loopback is a typo. A type 3 or 10 from the internet is a lead.
4. **Count distinct accounts per source** to catch password spraying, and **look for a success after the failures**.
5. **An exported `.evtx` is a snapshot.** Re-export with `/ow:true` after new events.
6. **Cross-check tools.** DeepBlueCLI flags patterns, a raw-event script gives the evidence. A flag is a lead, not a verdict.
