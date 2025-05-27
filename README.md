# BitSentinelCore Incident Report: Threat Hunting Timeline

## Summary

This investigation focuses on malicious activity observed on host `anthony-001`, initiated by the execution of a fake antivirus program named `BitSentinelCore.exe`. Through KQL-based hunting in Microsoft Defender for Endpoint, we uncovered a complete execution chain involving local compilation, persistence mechanisms, behavioral triggers, and user interaction.

---

## Step 1: Initial Binary Discovery

**Query:**

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName startswith "A" or FileName startswith "B" or FileName startswith "C"
| summarize Count = count() by FileName, InitiatingProcessFileName
| order by Count desc
```

### Findings:

* Identified `BitSentinelCore.exe` as the suspicious binary.
* Mimics legitimate AV naming (e.g., SentinelOne).
* Spawns `cmd.exe` and `conhost.exe` — indicates scripting.
* Launched by `explorer.exe`, suggesting user execution.

**Conclusion:**
`BitSentinelCore.exe` is the initiating malware binary.

---

## Step 2: Compilation Confirmation

**Query:**

```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp asc
```

### Findings:

* Dropped via `csc.exe` from `%Temp%` using a `.cmdline` file.

**Conclusion:**
Payload was compiled locally on the host.

---

## Step 3: Execution and Persistence Establishment

**Query:**

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine has "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```

### Findings:

* Executed three times manually, beginning at `2025-05-07T02:00:36.794406Z`.
* Triggered `cmd.exe` → `schtasks.exe` chain to install persistence task `UpdateHealthTelemetry`.

**Conclusion:**
Manual execution initiated full compromise chain.

---

## Step 4: LNK File-Based Trigger Discovery

**Query:**

```kql
DeviceFileEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessFileName == "explorer.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

### Findings:

* `systemreport.lnk` created by `explorer.exe` in `Recent` folder.
* Indicates user interaction — likely clicked malicious shortcut.

**Conclusion:**
`systemreport.lnk` acted as behavioral trigger for keylogging activity.

---

## Step 5: Registry-Based Persistence

**Query:**

```kql
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where RegistryKey has_any ("Run", "Input", "Keyboard", "Hook")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### Findings:

* Registry key added:

  * Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  * Name: `BitSecSvc`
  * Data: `"C:\ProgramData\BitSentinelCore.exe"`

**Conclusion:**
Persistence via `Run` key ensures execution at login.

---

## Step 6: Scheduled Task Creation

**Query:**

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where ProcessCommandLine has "schtasks"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

### Findings:

* Task: `UpdateHealthTelemetry`
* Scheduled daily at 2:00 PM

**Conclusion:**
Second layer of persistence, disguised as legitimate telemetry.

---

## Step 7: Process Relationship Chain

**Query:**

```kql
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName in ("BitSentinelCore.exe", "cmd.exe", "schtasks.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### Result:

```
BitSentinelCore.exe -> cmd.exe -> schtasks.exe
```

**Conclusion:**
A clean execution chain confirming how persistence was deployed.

---

## 📅 Forensic Timeline

| Timestamp (UTC)          | Event Type             | Description                                                           |
| ------------------------ | ---------------------- | --------------------------------------------------------------------- |
| 2025-05-07T02:00:36.794Z | Initial Execution      | `BitSentinelCore.exe` run by user `4nth0ny!`                          |
| 2025-05-07T02:02:14Z     | File Created           | `ThreatMetrics` dropped by `BitSentinelCore.exe` (decoy)              |
| 2025-05-07T02:02:14Z     | Registry Modification  | Persistence via `HKCU\Run\BitSecSvc`                                  |
| 2025-05-07T02:02:15Z     | Scheduled Task Created | `UpdateHealthTelemetry` → daily at 2:00 PM                            |
| 2025-05-07T02:06:51Z     | Shortcut Created       | `systemreport.lnk` created by `explorer.exe` → true keylogger trigger |

---

## Final Conclusion

`BitSentinelCore.exe` was compiled and executed locally, then established persistence through both registry and scheduled task. A secondary behavioral trigger (`systemreport.lnk`) suggests a decoy document or shortcut was used to mask user-facing keylogger activation. All malicious activity traces back to the initial execution of the binary at `2025-05-07T02:00:36.794406Z`.

This report documents a complete attack chain, behavioral indicators, and persistence mechanisms used by the adversary.
