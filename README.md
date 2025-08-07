# 🚨 Custom Wazuh Rules and Configuration for Enhanced Threat Detection

Welcome to this open-source contribution aimed at **enhancing Wazuh's threat detection** capabilities through custom rules and tailored configurations.

This repository contains:

- 🛡️ `local_rules.xml`: Custom detection rules for real-world attacks and misconfigurations.
- ⚙️ `ossec.conf`: A robust and heavily modified Wazuh manager configuration for improved visibility, integration, and response.
- 🤖 Experimental AI-based anomaly detection (preview feature).
  
> 📘 This project was created to **contribute back to the cybersecurity community**, helping blue teams, SOC analysts, and students like me detect threats faster and better with Wazuh.

---

## 📁 Repository Structure

| File | Description |
|------|-------------|
| `local_rules.xml` | Custom detection rules for malware, suspicious processes, obfuscated PowerShell, reverse shells, and more. |
| `ossec.conf` | Comprehensive Wazuh manager configuration enabling features like VirusTotal integration, active response, file integrity monitoring, and experimental AI. |

---

## 📌 Highlights

### ✅ Custom Detection Rules (`local_rules.xml`)

These rules are handcrafted to detect high-impact attack patterns using Wazuh’s rule engine:

- **SSH Authentication Failures** from suspicious IPs
- **Windows Malware Behavior** like:
  - Meterpreter or reverse TCP shells
  - Obfuscated PowerShell payloads
  - Unusual process creation chains
  - Suspicious network connections
- **Threat Intelligence Integration**:
  - Automatic **VirusTotal scanning** of detected malware (EICAR, etc.)
- **MITRE ATT&CK Mappings** included for threat hunting

---

### ⚙️ Hardened Wazuh Configuration (`ossec.conf`)

This configuration improves Wazuh’s overall capability and integration:

- 🔍 **File Integrity Monitoring** (FIM) enabled with high sensitivity
- 🧠 **AI Threat Detection Module** (experimental)
- 🔬 **CIS Benchmark Scanning**, **Vulnerability Detection**, **Rootkit Scanning**
- 📡 **Syslog, Snort, pfSense, journald, auditd, and netstat** monitoring
- 📬 Email alerts (disabled by default, but ready to configure)
- 🔐 **Active Response Automation** for account disabling, IP banning, etc.
- 🔗 **Cluster-ready** setup for scalable deployments
- 📈 JSON and plain logging, remote syslog forwarding, and Elasticsearch output

---


