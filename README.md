# AI-Assisted SOC Platform

A production-grade security operations platform built on
Raspberry Pi 5 from scratch. Designed to demonstrate
real-world SOC capabilities including multi-sensor network
monitoring, endpoint detection engineering, behavioral
threat hunting, and AI-assisted alert triage with automated
MITRE ATT&CK mapping.

---

## Platform Stack

### Core Infrastructure
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM backend and visualization
- Suricata IDS — network layer detection and alerting
- Filebeat — Linux log shipping
- Zeek — network protocol analysis and flow logging

### Endpoint Detection
- Sysmon (SwiftOnSecurity config) — endpoint behavioral telemetry
- Winlogbeat — Windows log shipping and Security event forwarding
- Windows Security Auditing — advanced audit policy configuration

### Network Sensors
- Alfa AWUS036ACS — dedicated wireless monitor adapter
- TP-Link TL-SG108E — managed switch with port mirroring

### Attack Simulation
- Kali Linux VM — offensive simulation environment
- Windows host — monitored endpoint target

---

## Detection Architecture — Three Layers

### Layer 1 — Wireless Sensor
- Alfa adapter in monitor mode
- Passive 802.11 frame capture
- Beacon frames, probe requests, probe responses
- Wireless device tracking and visibility

### Layer 2 — Network IDS
- Suricata watching all switch-mirrored traffic
- Signature-based and anomaly detection
- Alert generation to Elasticsearch via Filebeat
- Zeek protocol analysis and connection logging

### Layer 3 — Endpoint EDR
- Sysmon Event IDs: 1, 3, 10, 11, 12, 13
- Windows Security Event IDs: 4624, 4625, 4688,
  4698, 4720, 7045
- PowerShell execution logging
- LOLBin activity monitoring
- Process creation chain visibility
- Persistence mechanism detection



Wireless (Alfa) ─────────────────────┐
▼
Network Traffic → Switch (mirror) → Suricata → eve.json → Filebeat ─┐
▼
Windows Endpoint → Sysmon + Winlogbeat ──────────────────────────────┤
▼
Elasticsearch
│
▼
Kibana
│
┌───────────────────────┤
▼                       ▼
Executive Dashboard    Analyst Dashboard

---

## Current Capabilities

### Network Detection
- Multi-sensor monitoring: wired IDS + wireless 802.11 capture
- Behavioral threat hunting: beaconing, lateral movement,
  exfiltration, DNS anomalies
- Real-time IDS alert correlation and signature monitoring
- Geographic traffic visualization and external connection tracking
- Protocol distribution analysis and anomaly detection
- SSH authentication monitoring and brute force detection

### Endpoint Detection
- Process creation and parent-child chain analysis
- LOLBin abuse detection: powershell.exe, cmd.exe,
  rundll32.exe, certutil.exe, regsvr32.exe, mshta.exe, wmic.exe
- Encoded PowerShell detection and command-line visibility
- Persistence mechanism monitoring: scheduled tasks,
  service installs, new account creation
- Authentication success and failure tracking
- Windows Security audit event ingestion

### Dashboard Design
Platform serves two distinct audiences simultaneously:

**Executive Overview** — KPI panels for security leadership
- DNS requests, external connections, total network traffic
- Total alerts, potential beaconing activity
- Unique foreign countries, active source hosts
- Targeted assets, live event count, observed protocols

**Analyst Investigation** — Live investigation workflows
- Live network events table with full field visibility
- SSH activity monitor
- Alert feeds and threat signature tracking
- Endpoint process and authentication tables
- Pivot-ready investigation surfaces

**Attack Chain Correlation** — Multi-stage attacker behavior visibility
- Attack timeline correlation
- Top triggered detection rules
- Most targeted hosts
- Users generating security alerts
- Alert type distribution
- Live alert feed monitoring

---

## Dashboard Architecture

### SOC Dashboard
Executive-level security visibility providing:
- Total alerts and event volume
- Active hosts and targeted assets
- External connection monitoring
- Protocol distribution analysis
- Network activity overview

### Threat Hunting Dashboard
Expanded hunting platform tracking:
- Beaconing detection patterns
- Uncommon TCP service activity
- Suricata alert visibility and severity
- Destination port analysis
- Host activity behavioral analysis
- Network anomaly detection

### Endpoint Threat Hunting Dashboard
Expanded endpoint visibility tracking:
- Process creation activity
- Authentication events
- Failed logon monitoring
- Persistence-related activity
- Endpoint behavioral telemetry
- Windows security event analysis

### SOC Detection & Rule Monitoring Dashboard
Expanded detection engineering platform tracking:
- Rule execution health
- Detection reliability
- Alert generation performance
- Rule scheduling delays
- Detection tuning effectiveness
- False positive reduction efforts

### Attack Chain Correlation Dashboard
Expanded attack correlation platform tracking:
- Multi-stage attacker behavior visibility
- Correlated detection timeline activity
- Persistence and privilege escalation events
- Most targeted hosts and users
- Alert distribution analysis
- Live SOC alert monitoring and triage
  
## Threat Hunting Coverage

### Network — Organized by MITRE ATT&CK Tactic
| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Reconnaissance | T1595 | Port scan detection, rare external connections |
| Discovery | T1046 | Network service scanning patterns |
| Lateral Movement | T1021 | East-west traffic, rare internal ports |
| Command & Control | T1071 | Beaconing detection, non-standard TCP |
| Exfiltration | T1041 | Byte volume analysis, external data transfer |
| Credential Access | T1110 | SSH brute force, authentication failures |

### Endpoint — Organized by MITRE ATT&CK Tactic
| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Execution | T1059.001 | Encoded PowerShell, command-line logging |
| Execution | T1218 | LOLBin abuse monitoring |
| Persistence | T1053.005 | Scheduled task creation (Event 4698) |
| Persistence | T1543.003 | Service installation (Event 7045) |
| Persistence | T1136.001 | New account creation (Event 4720) |
| Credential Access | T1003 | LSASS access (Sysmon EID 10) |
| Defense Evasion | T1055 | Process injection detection |

---

## Daily Build Log

| Day | Focus | Key Achievement |
|-----|-------|----------------|
| 1 | Infrastructure | Full SOC pipeline built from scratch |
| 2 | Sensors | Wireless monitoring, professional dashboards |
| 3 | Troubleshooting | SSL/TLS resolution, Kibana restored |
| 4 | Validation | Interface routing fixed, pipeline confirmed |
| 5 | Threat Hunting | Threat Hunting Dashboard and behavioral analytics platform built |
| 6 | Executive Layer | SOC Dashboard and Dual-audience dashboard architecture |
| 7 | Detection Tuning | KQL noise reduction, signal optimization |
| 8 | Endpoint Layer | Endpoint Threat Hunting Dashboard and Sysmon + Winlogbeat integration, three-layer detection |
| 9 | EDR Visibility | LOLBin detection, attacker tradecraft simulation |
| 10 | Detection Engineering | 7 custom ATT&CK mapped rules, Rule Monitoring Dashboard, Attack Chain Correlation Dashboard |
| 11 | Attack Simulation & Validation | Multi-stage attack simulation, detection validation, attack-chain correlation testing, post-attack dashboard analysis |
---

## Attacker Tradecraft Simulated and Detected

- Nmap reconnaissance scans
- SSH brute force attempts
- Encoded PowerShell execution
- Scheduled task persistence creation
- LOLBin invocation patterns
- Suspicious process chain execution
- Network beaconing patterns
- Living-Off-The-Land binary abuse

Each simulation validated that the detection platform
correctly surfaces the technique in Kibana dashboards.

---

## Coming Next


### Day 12 — Claude AI Triage Engine
- Python script polling Elasticsearch for alerts
- Suricata network alerts + Sysmon endpoint alerts
- Claude API analyzes each alert with full context
- Returns: verdict, ATT&CK mapping, response recommendation
- Flask dashboard displays AI triage in real time

### Day 13 — Portfolio Launch
- Demo video: full attack-to-triage kill chain recording
- GitHub polish and final documentation

---

## Future Roadmap — Agentic AI Evolution

### Phase 2 — Autonomous Investigation Agent
Replace single Claude API call with multi-step
autonomous investigation agent:
- Automatic VirusTotal hash lookups
- Threat intelligence feed enrichment
- Automatic SIEM pivot and host history correlation
- Cross-host event correlation
- Confidence-scored investigation reports


---

## Key Concepts Demonstrated

- Multi-sensor SOC architecture design
- Detection engineering across network and endpoint layers
- SIEM pipeline construction and troubleshooting
- Behavioral threat hunting methodology
- Signal-to-noise optimization through KQL tuning
- EDR-style endpoint visibility without commercial tooling
- Executive and analyst dual-audience dashboard design
- Attacker tradecraft simulation and detection validation
- Living-Off-The-Land binary detection philosophy
- AI-assisted security operations workflow design
