# 🚨 Sigma Detection Rule: PowerShell Encoded Commands – MITRE T1059.001

## Overview

This repository contains a handcrafted Sigma detection rule designed to detect suspicious and potentially malicious use of PowerShell with base64-encoded commands and living-off-the-land binaries (LOLBins), mapped to MITRE ATT&CK T1059.001 (PowerShell).

**Key Features:**
- Detects encoded PowerShell commands
- Detects PowerShell invoking network-based scripts/downloaders (Invoke-WebRequest, IEX + http)
- Whitelists known benign parent processes to minimize false positives
- Helps organizations defend against ransomware, fileless malware, and post-exploitation activities

---

## MITRE ATT&CK Mapping

- **T1059.001: PowerShell**  
- **T1105: Ingress Tool Transfer**

---

## How To Use

### 1. Sigma Rule Location

- See: `rules/detect-pwsh-encoded.yml`

### 2. Convert to SIEM Queries

#### **ElasticSearch/Winlogbeat**


# sigma-detection-pwsh-encoded-mitre-t1059.001
