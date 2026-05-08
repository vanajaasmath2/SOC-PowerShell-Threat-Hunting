# 🔎 Suspicious PowerShell Execution Investigation

## 📌 Project Overview
This project focuses on detecting, analyzing, and investigating suspicious PowerShell execution activity using Windows Event Logs and Splunk. The investigation simulates a SOC (Security Operations Center) analyst workflow for identifying potentially malicious PowerShell commands commonly used in fileless attacks and malware execution.

---

# 🎯 Objectives
- Monitor PowerShell activity using Windows Event Logs
- Detect suspicious PowerShell execution patterns
- Analyze encoded and obfuscated commands
- Decode Base64 PowerShell payloads
- Identify Indicators of Compromise (IOCs)
- Map findings to MITRE ATT&CK techniques

---

# 🛠️ Tools Used
- Splunk
- Splunk Universal Forwarder
- Windows Event Viewer
- PowerShell
- CyberChef
- MITRE ATT&CK Framework

---

# 🧪 Investigation Scenario
A Windows endpoint generated alerts related to unusual PowerShell execution. The objective was to investigate whether the activity indicated malicious behavior such as:
- Encoded PowerShell commands
- Hidden execution
- Remote payload download
- Fileless malware techniques

---

# 📂 Data Collection

## Windows Event Logs
Enabled:
- Event ID 4688 – Process Creation

## Logging Configuration
Enabled command-line logging using Group Policy:
Computer Configuration → Administrative Templates → System → Audit Process Creation

---

# 🔍 Splunk Detection Queries

## Detect PowerShell Execution
```spl
index=* EventCode=4688 powershell
