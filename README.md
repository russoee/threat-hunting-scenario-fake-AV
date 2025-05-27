# Fake AV Threat Hunt 🕵️‍♂

**A forensic threat hunting investigation of `BitSentinelCore.exe` — a fake antivirus used to establish persistence via registry keys, scheduled tasks, and deceptive shortcut files.**

This hunt was performed in a Microsoft Defender for Endpoint lab environment as part of an APT simulation challenge. The malware chain was tracked from initial execution to persistence mechanisms and behavioral triggers, uncovering how attackers maintain long-term access without detection.

---

##  Key Objectives

- Identify the initial malicious binary and how it was delivered
- Trace all persistence mechanisms used by the attacker
- Determine the behavioral trigger for keylogging activity
- Build a forensic timeline of execution events

---

##  Techniques Observed

- Local compilation of malware via `csc.exe`
- Registry Run key modification (`HKCU\\...\\Run`)
- Scheduled task creation using `schtasks.exe`
- Decoy `.lnk` file (`systemreport.lnk`) to re-trigger malware

---

##  Contents

- `FakeAV_Investigation_Report.md` – Full report with queries, analysis, and timeline
- `screenshots/` – Visual evidence from Defender telemetry
- `README.md` – This file

---

##  Flag-Worthy Highlights

- `BitSentinelCore.exe` execution timestamp: `2025-05-07T02:00:36.794406Z`
- Registry key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BitSecSvc`
- Scheduled task: `UpdateHealthTelemetry`
- True behavioral keylogger trigger: `systemreport.lnk`

---

## Screenshots

Each phase of the investigation is supported by Defender query results and screenshots — see the `screenshots/` directory or embedded visuals in the main report.

---


