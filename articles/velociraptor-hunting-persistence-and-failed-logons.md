> **Lab write-up, part 1 of 2.** Everything below was done on a single lab VM with harmless test artifacts (Notepad copied and renamed to look like malware, a fake service, a Run key, three failed logons made on purpose). Names, paths, hashes and times are lab values. The method comes from the public Velociraptor documentation and my own testing. No employer or incident data is included. Part 2 covers the offline collector: [Velociraptor part 2: offline collector and checking the collected hives](article.html?slug=velociraptor-offline-collector-registry-explorer).

## 1. What I wanted to learn

I work in a SOC and I am moving toward DFIR. Velociraptor comes up everywhere in that world, so I wanted to understand it properly, not just click through it. The questions I set myself:

- What is an **artifact**, and how is it different from running a command on a machine?
- What is the difference between a **collection** and a **hunt**?
- Can I find things I planted on purpose, using only Velociraptor?

## 2. The lab

Velociraptor v0.77.2 in **instant mode**, which runs the server, the frontend and a client in one process on the same VM:

```powershell
velociraptor.exe gui --datastore C:\Velociraptor\datastore
```

The GUI opens at `https://127.0.0.1:8889` and all times in it are UTC. Because server and client are the same machine, there is one client in the list.

![The client list with the one lab client](assets/velociraptor/shot-01-client-list.png)
*The client list. One client, because instant mode runs everything on one host.*

![Client overview for the lab host](assets/velociraptor/shot-02-client-overview.png)
*Client overview (MAC addresses cropped out).*

In a real deployment the pieces are separate: agents run on endpoints and connect to a server over TLS. Instant mode is only for learning and testing.

## 3. What I planted

| Planted item | Where | Why it is interesting |
|---|---|---|
| `C:\LabTemp\invoice.exe` | A copy of `notepad.exe` | A signed Microsoft binary under a different name in a non-standard folder |
| Service `LabSvc` | Runs `invoice.exe` as LocalSystem, automatic start | Service persistence |
| Run key `LabUpdater` | `HKCU\...\Run`, runs `invoice.exe` | Per-user persistence, needs no admin |
| Defender exclusion | `C:\LabTemp` | Hides the folder from Defender |
| 3 failed logons | `net use \\localhost\IPC$ /user:labfake BadPass123` | Event 4625 with an unknown user |

## 4. Collecting the services

An **artifact** in Velociraptor is a named recipe that wraps a query written in **VQL**, a SQL-like language. A **collection** runs artifacts on one client, on demand.

I collected `Windows.System.Services`.

![Services collection finished](assets/velociraptor/shot-03-services-collection.png)
*The Windows.System.Services collection.*

Before reading results I opened the **Requests** tab to see the VQL that ran. It reads services through WMI (`Win32_service`), and then adds details from the registry, such as the key's last-write time, `ServiceDll` and `FailureCommand`.

![The VQL behind the collection, WMI line highlighted](assets/velociraptor/shot-04-vql-requests.png)
*The VQL behind the artifact. The WMI query is highlighted.*

Reading the query told me something that mattered later: the `Created` column is **not** the time the service was created with `sc.exe`. It is the **last-write time of the service's registry key**. I confirmed this in part 2 against Registry Explorer.

## 5. Spotting LabSvc

![LabSvc row in the services table](assets/velociraptor/shot-05-labsvc-row.png)
*The LabSvc row.*

Three things stood out in that row without any threat intelligence:

1. It runs as **LocalSystem**, the most privileged service account.
2. It runs as its **own process**.
3. The binary is in **`C:\LabTemp`**, not in the normal system folders.

I re-ran the collection with hashing and certificate information turned on, which is an optional parameter of the artifact.

![Hash and certificate information for the LabSvc binary](assets/velociraptor/shot-06-labsvc-hash-cert.png)
*Hash and certificate details for the service binary.*

The certificate says Microsoft. I right-clicked the hash and looked it up on VirusTotal.

![VirusTotal result for the hash](assets/velociraptor/shot-07-virustotal.png)
*VirusTotal: 0 detections, file name NOTEPAD.EXE.*

SHA256 `2f3daf08b248b0a8aa0c47ba81864be7d379a0229599cdec3b93281b57fcd280`.

### Why a clean result still means something

This is the first lesson I want to keep. The hash is clean and the file is signed by Microsoft, yet a Windows service running Notepad from `C:\LabTemp` as SYSTEM named `invoice.exe` is wrong.

- A digital signature covers the **contents** of a file. It does not cover the **name** or the **location**.
- Windows can also trust system files through **catalog signing**: trust comes from a catalog of known hashes, so a copy of the file stays "trusted" from any folder.
- So "0 detections" means "this exact file is a known good Microsoft file", not "this is fine here".

This is **masquerading** (MITRE ATT&CK T1036). Things to compare in a real case: the file's original name against its current name, its path, and the files next to it (a trusted binary beside a strange DLL can mean DLL sideloading).

My own words after this step: the hash is Microsoft's and it runs under a service account outside the Windows directory, so the context is what is suspicious.

## 6. Why an artifact and not services.msc

I asked myself why this is better than opening `services.msc`. On one machine it is not. On 500 endpoints you cannot sign in to each one. An artifact collects the same fields, in the same format, from every endpoint, and you can filter and sort the result in one table. You also get the hash, the signer and the registry details that `services.msc` does not show.

## 7. Startup items and a misleading column

I collected `Windows.Sys.StartupItems` for the Run key persistence. `LabUpdater` appeared and pointed at `C:\LabTemp\invoice.exe`.

![LabUpdater in StartupItems](assets/velociraptor/shot-08-startupitems-labupdater.png)
*LabUpdater in the StartupItems results.*

Run keys under `HKCU` belong to one user. They need no admin rights and run when that user logs on. Windows Task Manager shows the startup entry using the file's **description and publisher**, so it lists "Notepad" from Microsoft and hides the names `LabUpdater` and `invoice.exe`. Only the file location gives it away.

![Task Manager startup tab and the file location](assets/velociraptor/shot-09-startup-taskmanager-file-location.png)
*Task Manager shows "Notepad"; the file location shows `C:\LabTemp`.*

The artifact showed the entry as **disabled**, while Windows was treating it as enabled. I read the VQL to find out why.

![The VQL for the Enabled column](assets/velociraptor/shot-10-startupitems-vql-enabled.png)
*The VQL behind the `Enabled` column.*

My reading: the `Enabled` value there means "does a StartupApproved record exist for this entry", so an entry with no such record shows as disabled even though Windows runs it. I checked it in Task Manager, which showed the entry as enabled. The lesson is general: **when an artifact column looks wrong, read the VQL** before trusting or dismissing it.

## 8. Failed logons with EvtxHunter

The Windows event log keeps **4625** (failed logon). I made three failed logons with a made-up user:

```powershell
net use \\localhost\IPC$ /user:labfake BadPass123
```

I ran it three times, at about 03:05:00, 03:05:08 and 03:05:27 local time (EDT).

I used the `Windows.EventLogs.EvtxHunter` artifact. These are the parameters I used or learned:

| Parameter | What it does |
|---|---|
| `EvtxGlob` | Which log files to read |
| `IdRegex` | Event ID to match, here `4625` |
| `IocRegex` | Text to find in the message or event data, here `labfake` |
| `WhitelistRegex` | Text to exclude |
| `PathRegex`, `ChannelRegex`, `ProviderRegex` | Filter by file, channel or provider |
| `DateAfter`, `DateBefore` | Limit the time window |

I made one mistake: I first put `4625` in `IocRegex` instead of `IdRegex`. `IocRegex` searches the text, so it did not match as I intended. Putting `4625` in `IdRegex` and `labfake` in `IocRegex` fixed it.

I also set `DateAfter` and `DateBefore` around the test. Scoping a search keeps it quick and light on the endpoint, which matters when you run it across many machines.

![EvtxHunter parameters](assets/velociraptor/shot-11-evtxhunter-parameters.png)
*EvtxHunter parameters with ID, IOC text and a date window.*

![EvtxHunter results](assets/velociraptor/shot-12-evtxhunter-results.png)
*Results.*

![The three failed logon events](assets/velociraptor/shot-13-evtxhunter-three-events.png)
*The three events.*

### Reading the fields

- **Status and SubStatus** are shown in **decimal**. `3221225581` is `0xC000006D` (the logon failed), and the SubStatus `3221225572` is `0xC0000064` (the user name does not exist). Convert to hex before looking them up.
- **LogonType 3** is a network logon.
- **Subject** is `S-1-0-0` with `-` for the account. For a failed network logon nobody is logged on yet, so this is normal.
- **FailureReason** `%%2313` is the code for "unknown user name or bad password".

### Time zones

The lab VM showed local time, Velociraptor shows UTC:

| What | Local (EDT) | UTC |
|---|---|---|
| Attempt 1 | 03:05:00 | 07:05:00 |
| Attempt 2 | 03:05:08 | 07:05:08 |
| Attempt 3 | 03:05:27 | 07:05:27 |

(EDT is UTC-4.)

### One thing I could not explain

The `EventRecordID` values were 13172, 13174 and 13176. The IDs **in between** (13173 and 13175) are events that my filter did not show. I did not look at what they are. In a real investigation a gap like this is a prompt to check the neighbouring events, so I am listing it as an open question.

## 9. Collection vs hunt

My own answer after trying both: a **collection** collects evidence from one host. A **hunt** runs the same artifact on many hosts and keeps collecting from every host that checks in until it expires.

I created a hunt from the same EvtxHunter settings.

![Hunt configuration](assets/velociraptor/shot-14-hunt-configure.png)
*Hunt configuration.*

A new hunt is created **paused** unless you tick "Start Hunt Immediately". That is a sensible default, because a hunt runs on every client in scope.

![Hunt Manager](assets/velociraptor/shot-15-hunt-manager.png)
*Hunt Manager (the crosshair icon in the sidebar).*

I had one confusion here. The **binoculars** icon is **Client Events**, which is continuous monitoring on a client, for example `Generic.Client.Stats`. **Hunt Manager** is the crosshair. "Add to hunt" in a collection is a separate button again.

## 10. What I learned

- **Artifact**: a named recipe wrapping VQL. **Collection**: run on one client. **Hunt**: run across many. **Client events**: continuous. **Server artifacts**: run on the server itself.
- Read the **Requests** tab. It shows exactly what the artifact ran, and it explains odd columns.
- A signature or a clean hash does not make a file safe in context. Check name, path, parent and neighbours.
- Per-user persistence (HKCU Run) is easy to plant and hard to notice in Task Manager.
- Scope hunts with parameters so they stay light.

## 11. Mapping to ATT&CK (my reading)

| Finding | Technique |
|---|---|
| Notepad renamed to `invoice.exe` | T1036 Masquerading |
| Run key `LabUpdater` | T1547.001 Registry Run Keys / Startup Folder |
| Service `LabSvc` | T1543.003 Windows Service |
| Defender exclusion | T1562.001 Impair Defenses: Disable or Modify Tools |
| Failed logons with a made-up user | T1110 Brute Force (a lab approximation, three attempts is not a real brute force) |

## 12. Limits

- One VM, one client, with artifacts I planted myself. Real environments have noise.
- I did not check `RunMRU` in Velociraptor, even though I planted it.
- I did not work out what records 13173 and 13175 are.
- I did not work out what the hunt's "Scheduled" state means exactly.
- I am a learner. If I got a detail wrong, the official documentation is the authority.

Continue with [part 2: the offline collector](article.html?slug=velociraptor-offline-collector-registry-explorer).

Sources: [Velociraptor documentation](https://docs.velociraptor.app/), [MITRE ATT&CK](https://attack.mitre.org/).
