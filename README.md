# 🚨 Sigma Detection Rule: PowerShell Encoded Commands (MITRE T1059.001)


---

## 📖 Overview

This project delivers a **production-ready Sigma detection rule** for identifying suspicious or malicious PowerShell usage involving base64-encoded commands and LOLBins (living-off-the-land binaries) for downloads. The detection is mapped directly to [MITRE ATT&CK T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) and [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/).

**Detection Goals:**
- Find obfuscated/encoded PowerShell usage
- Identify PowerShell downloads (Invoke-WebRequest/IEX with http)
- Minimize false positives via tunable whitelisting

---

## 🏹 MITRE ATT&CK Coverage

- **T1059.001**: PowerShell
- **T1105**: Ingress Tool Transfer

---

## 📦 Project Contents

- [`rules/detect-pwsh-encoded.yml`](rules/detect-pwsh-encoded.yml) – Sigma detection rule (core detection logic)
- [`es_query.json`](es_query.json) – ElasticSearch SIEM query (Winlogbeat format)
- [`splunk_query.txt`](splunk_query.txt) – Splunk SIEM query (SPL syntax)
- LICENSE – MIT License

---

## 🚀 Quick Start

### 1. **Sigma Rule Location**
See: [`rules/detect-pwsh-encoded.yml`](rules/detect-pwsh-encoded.yml)

### 2. **Convert to SIEM Query**

#### **ElasticSearch / Winlogbeat**

index=winlogbeat OR index=sysmon
(Image="\powershell.exe")
(CommandLine="-enc*" OR (CommandLine="Invoke-WebRequest" CommandLine="http") OR (CommandLine="iex" CommandLine="http"))
| where NOT (ParentImage="\System32\services.exe" OR ParentImage="\svchost.exe")
| table _time, User, Image, ParentImage, CommandLine


---

## 📝 Sample Detection Event

Example of a suspicious process creation log (this would trigger an alert):

{
"TimeCreated": "2025-09-08T18:10:02",
"User": "bob.evans",
"Image": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
"ParentImage": "C:\Windows\explorer.exe",
"CommandLine": "powershell.exe -enc dABoAGkAcwAgAGkAcwAgAGEAIAB0AGUAcwB0AA=="
}



---

## 🎛️ False Positives & Tuning Tips

- Check ParentImage and User fields—add whitelisting for known IT automation, deployment tools, or sysadmin accounts.
- Adjust detection to suit your environment’s normal PowerShell/script usage.
- Regularly review new hits to fine-tune rule for maximum signal / minimum noise.

---

## 📚 References

- [MITRE ATT&CK T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [SANS: Defeating PowerShell Attack Methods](https://www.sans.org/blog/defeating-powershell-attack-methods/)
- [sigmahq.io](https://github.com/SigmaHQ/sigma)

---

## 👤 About

**Author:** Daksha Mudumbai  
**Contact:** [mudumbaid@gmail.com](mailto:mudumbaid@gmail.com)  

*Feel free to fork, open issues, or reach out if you want to collaborate or discuss SIEM detection engineering!*


---
