# Threat Hunting Case Study: BitSentinelCore Fake Antivirus Attack

This project documents a full threat hunting investigation using Microsoft Defender for Endpoint and Kusto Query Language (KQL) to uncover a simulated malware scenario. It follows the attacker’s actions from compiling and executing a fake antivirus binary to achieving stealthy persistence and triggering keylogging behavior through deceptive shortcut files.

📄 **Full case write-up:** FakeAV\_InvestigationReport.md

---

## Scenario Summary

A malicious binary named `BitSentinelCore.exe` was locally compiled on the host using `csc.exe`. The user (4nth0ny!) unknowingly launched the file, triggering a chain of persistence mechanisms:

* Registry Run key (`HKCU\...\Run\BitSecSvc`)
* Scheduled task (`schtasks` with UpdateHealthTelemetry)
* Decoy file drop (`ThreatMetrics`)
* Shortcut-based reactivation (`systemreport.lnk`)

This project reconstructs the entire attack chain and highlights the techniques used to maintain access and avoid detection.

---

## Tools & Techniques

* Microsoft Defender for Endpoint
* Kusto Query Language (KQL)
* Process and file event correlation
* Persistence detection via registry and task scheduler
* Behavioral analysis of `.lnk` files

---

## MITRE ATT\&CK Mapping

* **T1059.003** (Command and Scripting Interpreter: Windows Command Shell)
* **T1547.001** (Boot or Logon Autostart Execution: Registry Run Keys)
* **T1053.005** (Scheduled Task/Job: Scheduled Task)
* **T1204.002** (User Execution: Malicious File)
* **T1023** (Shortcut Modification)

---

## Skills Demonstrated

* Threat hunting methodology
* Endpoint behavioral analysis
* Detection of stealthy persistence mechanisms
* Incident timeline reconstruction
* KQL query creation and investigative logic

---

This project is for educational demonstration purposes and simulates a realistic malware-based intrusion workflow using living-off-the-land techniques and deceptive file triggers.
