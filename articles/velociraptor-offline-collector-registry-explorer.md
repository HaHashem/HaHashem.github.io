> **Lab write-up, part 2 of 2.** Same lab VM and harmless test artifacts as [part 1](article.html?slug=velociraptor-hunting-persistence-and-failed-logons). Here I build an **offline collector**, run it, check the output and open the collected registry hives in Registry Explorer. Names, paths, hashes and times are lab values. No employer or incident data is included.

## 1. Why an offline collector

Sometimes there is no Velociraptor agent on the machine, or the machine cannot reach your server. An **offline collector** is a single executable (Velociraptor plus an embedded list of what to collect). You run it as Administrator on the target and it writes a **zip** of the evidence. You then carry the zip back for analysis.

## 2. Getting the triage targets

The artifacts I wanted, `Windows.Triage.Targets` and `Windows.KapeFiles.Targets`, were not in my build. They come from the **Server.Import.Extras** server artifact, which downloads extra artifact bundles. I imported only **"The Triage Artifacts"** bundle.

Importing third-party artifacts means running someone else's VQL on your server, so I read the parameters first and checked that the download URLs pointed at the official velocidex.com and GitHub locations.

I hit two small problems on the way:

- A direct link to the collector page rendered blank. The server was fine. I used the paper-plane **Build offline collector** icon on the Server Artifacts page instead.
- A mix-up between server artifacts (type: server, run on the server, such as `Server.Utils.CreateCollector`) and client artifacts (run on endpoints).

## 3. Choosing targets

![Triage targets parameters](assets/velociraptor/shot-16-triage-targets-parameters.png)
*Windows.Triage.Targets parameters. I selected registry hives, event logs and similar.*

I selected the registry hives and related files. The collection includes the `.LOG1` and `.LOG2` **transaction logs** next to each hive, which hold recent changes not yet merged into the hive. Velociraptor also writes `.idx` index files for the collected files.

## 4. Configuring the collector

![Offline collector configuration](assets/velociraptor/shot-17-offline-collector-config.png)
*Collector configuration.*

I set encryption to **None** because it is a lab. In a real case use **Password, X509 or PGP**: the hives contain sensitive data such as account names and, depending on the target, hashes and recently used files.

![Collector built](assets/velociraptor/shot-18-offline-collector-built.png)
*The built collector executable and its upload record.*

## 5. Running it

I ran the collector from an elevated PowerShell on the VM. It wrote a log and a zip to `C:\Lab\collector`.

![Collector running](assets/velociraptor/shot-19-offline-collector-run.png)
*Collector run, log and output zip.*

## 6. Verify the evidence

Before analysing, I compared the zip's hash with the value the collector reports for its container.

```powershell
Get-FileHash C:\Lab\collector\<collector-output>.zip -Algorithm SHA256
```

![Hash comparison and extracted listing](assets/velociraptor/shot-20-collector-hash-verify.png)
*The two SHA256 values match, and the SOFTWARE hive listing after extraction.*

Zip SHA256 in the lab: `5b31e37ad8a77678759eb80433246fb2e2da41f7221934097c64b4be07d61d64`. A matching hash shows the file was not changed between collection and analysis. Record it in your notes. Work on **copies** of the evidence.

## 7. Registry Explorer on the collected hives

I opened the collected hives in **Registry Explorer** (Eric Zimmerman) and let it **replay the transaction logs**. That creates `_clean` copies with the pending changes applied. Without this step, recent changes can be missing from what you see.

### The Defender exclusion

![Defender exclusion in the collected SOFTWARE hive](assets/velociraptor/shot-21-collector-hive-defender-exclusion.png)
*`Windows Defender\Exclusions\Paths` in the collected SOFTWARE hive shows `C:\LabTemp`.*

### The service

![LabSvc in the collected SYSTEM hive](assets/velociraptor/shot-22-collector-hive-labsvc.png)
*LabSvc in the SYSTEM hive, with its last-write time.*

Note that an **offline** SYSTEM hive has `ControlSet001`, not `CurrentControlSet`. `CurrentControlSet` is a live link that only exists on a running system.

## 8. Cross-checking the timestamps

From part 1, Velociraptor's `Created` for LabSvc came from the registry key's last-write time. Registry Explorer's Services view gives the same key a **Name Key Last Write** of **08:33:27**, so the two tools agree.

The parent `Services` key shows a different time, **08:53:08**.

The rule I tested: a key's last-write time changes when one of **its own values** changes, or when a **direct subkey is added or removed**. It is not the creation time, and a parent's time does not tell you when a child key was created. The parent changed at 08:53:08 for its own reasons, and that is why the two times differ.

## 9. Planted vs found

| Planted | Found by | Confirmed in |
|---|---|---|
| Service `LabSvc` | `Windows.System.Services` | SYSTEM hive (Registry Explorer) |
| Run key `LabUpdater` | `Windows.Sys.StartupItems` | Task Manager |
| Defender exclusion | Collected SOFTWARE hive | Registry Explorer |
| 3 failed logons | `Windows.EventLogs.EvtxHunter`, as a collection and as a hunt | Event fields |
| Masqueraded `invoice.exe` | Hash and certificate columns + VirusTotal | File location in Task Manager |
| `RunMRU` entry | Not checked in Velociraptor | n/a |

## 10. Limits and open questions

- I could not explain what modified the Defender key at **06:09:22** (UTC). A last-write time only says the key changed, not who changed it or why.
- Encryption was off, which is only acceptable in a lab.
- Importing the triage bundle trusts that bundle's authors. Read what you import.
- Only one VM. Nothing here shows how it behaves at scale.

## 11. Key takeaways

1. An **offline collector** is for machines without an agent: one executable, a zip out, run as Administrator.
2. **Encrypt** the output in real cases, and **verify the hash** before analysis.
3. Collect hives **with their transaction logs** and replay them.
4. Two independent tools agreeing on a timestamp is stronger than one tool alone.
5. A parent key's last-write time says nothing certain about when a child key was created.

Sources: [Velociraptor documentation](https://docs.velociraptor.app/), [MITRE ATT&CK](https://attack.mitre.org/), [Registry Explorer by Eric Zimmerman](https://ericzimmerman.github.io/).
