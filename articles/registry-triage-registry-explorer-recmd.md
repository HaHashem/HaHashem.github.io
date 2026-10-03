> **Lab write-up.** Everything below was done on a lab machine with harmless test artifacts (Notepad renamed and registered as "malware"). Paths, names and values are lab values. The method comes from public documentation and the tools' own guides. No employer or incident data is included. Always work on **copies** of the evidence.

## 1. Why the registry matters after a ransomware infection

Ransomware is loud at the end (encrypted files, a note) but it usually leaves quiet traces earlier: how it started, how it stays, what it turned off. Much of that lives in the Windows registry:

- **How it started.** Run dialog history, recently used files, programs that ran from odd folders.
- **How it persists.** Run keys, services, scheduled tasks, Winlogon values.
- **What it switched off.** Defender exclusions, security policies, remote-access settings.

The registry also keeps **timestamps**. Every key records when it was last changed, which helps build a timeline when logs are missing or cleared.

The tools here are free, from Eric Zimmerman: **Registry Explorer** (a GUI for reading hives), **RECmd** (the command-line version that runs batch rules over many hives) and **Timeline Explorer** (to sort and filter the CSV output).

## 2. The lab

On a throwaway Windows VM, I created the kind of artifacts an intruder would leave. Run these in an **Administrator** PowerShell, logged in as the user you will examine. Nothing here is malicious: every "payload" is Notepad.

```powershell
# a staging folder and a "payload" with a misleading name
mkdir C:\LabTemp
copy C:\Windows\System32\notepad.exe C:\LabTemp\invoice.exe
Start-Process C:\LabTemp\invoice.exe

# persistence 1: a Run key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabUpdater /t REG_SZ /d "C:\LabTemp\invoice.exe" /f

# persistence 2: a service (run as Administrator)
sc.exe create LabSvc binPath= "C:\LabTemp\invoice.exe" start= auto

# defense evasion: a Defender exclusion (run as Administrator)
Add-MpPreference -ExclusionPath "C:\LabTemp"
```
Then press **Win+R**, type `notepad` and press Enter, so the Run dialog history has an entry.

![The lab setup commands run in PowerShell](assets/registry/shot-01-lab-setup.png)
*The lab setup commands run in PowerShell.*

When you finish the lab, clean up (section 9).

## 3. Collect the hives

**Restart the machine first.** Windows keeps ShimCache in memory and writes it to the registry at shutdown or restart. If you collect hives right after running the lab, the new `invoice.exe` entry will not be there yet. (On a real incident, this is one reason a memory capture or a shutdown-time decision matters.)

A live registry is in use and changing. For the lab I exported the hives I needed. In a real case you would use a forensic image or a collection tool (such as KAPE) so you also get the transaction logs.

```powershell
mkdir C:\Lab\hives
reg save HKLM\SYSTEM   C:\Lab\hives\SYSTEM.hiv   /y
reg save HKLM\SOFTWARE C:\Lab\hives\SOFTWARE.hiv /y
reg save "HKU\$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)" C:\Lab\hives\NTUSER.hiv /y
```
![Saving the SYSTEM, SOFTWARE and user hives with reg save](assets/registry/shot-08-collect-hives.png)
*Saving the three hives and confirming the files exist.*

The third command saves the current user's hive (the equivalent of `NTUSER.DAT`) by its SID. `reg save` writes a clean, consistent copy. When you instead copy hive files from a disk image, they can contain changes that have not been merged yet. Those changes are stored in the `.LOG1` and `.LOG2` files next to the hive. **Always copy these too.** Registry Explorer offers to replay them when you open a dirty hive, and you should say yes, because it can recover recent changes you would otherwise miss.

## 4. Read the hives in Registry Explorer

Open **Registry Explorer**, then **File → Load hive** and choose a hive. Two features save time:

- **Available bookmarks** (a tab in the left panel). Shortcuts to the keys investigators check most, grouped by category. Click one and the tool jumps to the right key and decodes the data.
- **Find** (Ctrl+F). Search by name, value, data or last-write time.

![Registry Explorer with the Available bookmarks tab](assets/registry/shot-02-bookmarks.png)
*Registry Explorer with the Available bookmarks tab.*

### 4.1 Persistence: the Run key

In `NTUSER.hiv`, open `Software\Microsoft\Windows\CurrentVersion\Run`. The `LabUpdater` value points at `C:\LabTemp\invoice.exe`.

What makes it suspicious: a vague name, a user-writable folder, an executable pretending to be a document. The **last write time** of the key tells you when something was added, though it covers the whole key, not one value. In the lab it read `08:33:10` UTC, which is 04:33 local time, the minute I ran `reg add`. Registry Explorer shows UTC, so convert before comparing it with other sources.

![The Run key with the LabUpdater value and its last write time](assets/registry/shot-03-run-key.png)
*The Run key with the LabUpdater value and its last write time.*

### 4.2 Persistence: the service

In `SYSTEM.hiv`, open `ControlSet001\Services\LabSvc`. Check `ImagePath`, `Start` (2 means automatic) and `ObjectName` (the account it runs as). Real malware services often use random names and run as `LocalSystem`.

![LabSvc service key with ImagePath](assets/registry/shot-04a-service.png)
*The LabSvc service key with its ImagePath.*

### 4.3 Defense evasion: Defender exclusions

In `SOFTWARE.hiv`, open `Microsoft\Windows Defender\Exclusions\Paths`. The `C:\LabTemp` exclusion appears as a value name. Attackers add exclusions so their tools are not scanned. Also check `Policies\Microsoft\Windows Defender` for `DisableAntiSpyware` and real-time protection switches. On a protected system, Tamper Protection may block some of these changes, so their absence is not proof of safety.

![Defender exclusion for C:\LabTemp](assets/registry/shot-04b-defender-exclusion.png)
*The Defender exclusion that hides the staging folder.*

**A timestamp trap here too.** I added the exclusion at about 04:33 local time, but this key's last write time is `08:41:01` UTC (04:41 local), just after I restarted the VM. Something rewrote the key during startup, most likely Defender itself. So a key's last write time tells you when it was **last changed**, not when the attacker first added the value. Treat it as a lead and confirm it with other artifacts, such as logs or the Run key and service times above.


## 5. What ran, and when

Persistence tells you what was planted. These artifacts tell you what actually executed.

| Artifact | Where | What it gives you | Limits |
|---|---|---|---|
| **ShimCache** (AppCompatCache) | `SYSTEM` hive | File paths seen by the system, and the file's **last-modified time** | The timestamp is the **file's modified time, not when it ran**. On modern Windows it is **not proof of execution** by itself. Written to the registry at shutdown or restart. |
| **BAM/DAM** | `SYSTEM\...\Services\bam\State\UserSettings\<SID>` | Last execution time per executable and user | Newer Windows 10 and 11 only, and holds limited history. |
| **UserAssist** | `NTUSER\...\Explorer\UserAssist` | Programs launched through the shell, with run counts and last run time. Names are ROT13-encoded; Registry Explorer decodes them. | GUI launches only. |
| **RunMRU** | `NTUSER\...\Explorer\RunMRU` | What was typed into the Win+R dialog | Important for phishing lures that tell users to paste a command (for example ClickFix). |
| **Amcache** | `C:\Windows\appcompat\Programs\Amcache.hve` | File path, size and **SHA1 hash** of executables | A separate hive that must be collected as a file, not with `reg save`. |

For the lab I used the bookmarks for **ShimCache** and **RunMRU/UserAssist** in `SYSTEM.hiv` and `NTUSER.hiv`. `invoice.exe` shows up in ShimCache, and `notepad` shows in RunMRU.

![ShimCache entry for C:\LabTemp\invoice.exe](assets/registry/shot-05-shimcache.png)
*ShimCache entry for C:\LabTemp\invoice.exe.*

**Read the timestamp carefully.** The entry sits at position 0 (the most recent addition), but its Modified Time is **2020-05-11**, years before the lab. That is not when I ran it. It is the file's own last-modified time, copied from Notepad when I made `invoice.exe`. The same date appeared in `dir` earlier. If I had read it as an execution time, I would have put the activity in 2020. The position in the list and the other artifacts below are what place it in this session.

![RunMRU showing the notepad command typed into Win+R](assets/registry/shot-06-runmru-userassist.png)
*RunMRU showing the notepad command typed into Win+R.*

**Timing caveat.** RunMRU keeps an ordered list of what was typed, but only the **most recent** entry gets a usable time, taken from the key's last write time (here `19:14:25` UTC, 15:14 local). Older entries have no timestamp of their own. Also, the Run dialog had to be used **before** I saved the hive. My first copy showed an empty RunMRU, so I did the step, saved a fresh copy (`NTUSER2.hiv`) and loaded that. A hive is a snapshot of one moment, just like an exported event log.

A strong finding combines them: a file in a user-writable folder (ShimCache), executed at a certain time (BAM or UserAssist), now registered to start automatically (Run key or service). One artifact alone is a lead, not a conclusion.

## 6. Ransomware-specific keys to check

| Key or value | Why it matters |
|---|---|
| `SOFTWARE\Microsoft\Windows Defender\Exclusions\*` and `SOFTWARE\Policies\Microsoft\Windows Defender` | Defender exclusions and disabled protection |
| `SYSTEM\CurrentControlSet\Control\SafeBoot` | Some families boot into Safe Mode to avoid security tools |
| `SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` | `0` means RDP is enabled, a common step before spreading |
| `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | `1` makes Windows keep plain-text-recoverable credentials in memory |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` | `1` lets local admin accounts log on remotely at full privilege |
| `NTUSER\Control Panel\Desktop\Wallpaper` | Some ransomware changes the wallpaper to show its note |
| `NTUSER\...\Explorer\TypedPaths` and `RecentDocs` | Folders and files the user browsed, which shows exposure and lures |

## 7. Do it across many hives: RECmd

Registry Explorer is for one hive at a time. **RECmd** runs ready-made rules across a folder of hives and writes CSV files.

```powershell
RECmd.exe -d C:\Lab\hives --bn BatchExamples\Kroll_Batch.reb --csv C:\Lab\out
```
- `-d` is the directory of hives.
- `--bn` is the batch file of rules. Zimmerman's download includes example batches such as `Kroll_Batch.reb`.
- `--csv` is where results go.

Open the output CSV in **Timeline Explorer** and sort by the last-write or timestamp column to build a rough timeline. Filter on `LabTemp` to see everything that touches the staging folder.

![RECmd output opened in Timeline Explorer, filtered on LabTemp](assets/registry/shot-07-recmd-timeline.png)
*RECmd output opened in Timeline Explorer, filtered on LabTemp.*

One search across about 9,600 rows leaves five: the Run key, the Defender exclusion, the ShimCache entry and the service. The Run key appears twice only because my lab folder held two copies of the user hive (I saved a second one after the first lacked the Run dialog history). In a real case, duplicate rows like this usually mean the same artifact was collected more than once, so check the source file column before counting them as separate findings.

## 8. Limits and false positives

- **Key last-write times** change when any value under the key changes. They do not tell you which value or who changed it.
- **ShimCache is not proof of execution.** Corroborate with BAM, UserAssist, Amcache, Prefetch and event logs.
- **Attackers can clean up.** Deleted keys can sometimes be recovered from unallocated space or transaction logs, but not always. Absence of evidence is not evidence of absence.
- **Legitimate software uses all of these locations.** Judge by path, signature, timing and context, not by the location alone.
- **File timestamps can mislead.** In the lab, the copied `invoice.exe` shows a last-write date from Notepad's original build, because a copy keeps the source's modified time while its created time is the copy time. Compare timestamps across artifacts instead of trusting one.
- **Time zones.** Registry timestamps are in UTC. Convert before building a timeline with other sources.
- **Work on copies**, and record hashes of what you collected.

## 9. Clean up the lab

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabUpdater /f
sc.exe delete LabSvc
Remove-MpPreference -ExclusionPath "C:\LabTemp"
Remove-Item C:\LabTemp -Recurse -Force
```

## 10. Key takeaways

1. The registry shows **how it started, how it stays, and what it turned off**, with timestamps.
2. Collect hives **with their transaction logs** and let Registry Explorer replay them.
3. Use **bookmarks** in Registry Explorer to jump to the keys that matter, and **RECmd with a batch file** to scale to many hosts.
4. Treat each artifact as a lead. **Combine** presence (ShimCache), execution (BAM, UserAssist, Amcache) and persistence (Run keys, services).
5. Know the limits: last-write times cover the whole key, and ShimCache alone does not prove a program ran.
