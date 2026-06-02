# AI-Assisted SOC Platform

A production-grade multi-sensor Security Operations Center (SOC) platform built from scratch on a Raspberry Pi 5. The environment combines wireless monitoring, network intrusion detection, endpoint telemetry, attack simulation, detection engineering, and AI-assisted security operations into a unified Elastic SIEM platform.

The platform provides correlated visibility across three independent detection layers:

- Wireless Monitoring (Alfa AWUS036ACS)
- Network IDS Monitoring (Suricata + Zeek via SPAN Port Mirroring)
- Endpoint Detection & Response (Sysmon + Winlogbeat)

The environment was validated through a multi-stage attack simulation covering Reconnaissance, Execution, Persistence, and Privilege Escalation techniques mapped to MITRE ATT&CK.

---

## Quick Navigation

- Multi-Sensor Architecture
- Detection Engineering
- Threat Hunting Dashboards
- Attack Simulation & Validation
- MITRE ATT&CK Coverage
- AI Triage Roadmap

---
  

## Current Project Metrics

- 3 Independent Detection Layers
- Wireless + Network + Endpoint Visibility
- Managed Switch SPAN Monitoring
- 5 Security Dashboards
- 7 Custom Detection Rules
- Multi-Stage Attack Simulation Completed
- MITRE ATT&CK Mapped Detections
- End-to-End Attack Chain Correlation
- Detection Validation Completed
- AI-Assisted SOC Roadmap

This platform was designed to emulate a modern SOC by combining wireless visibility, network intrusion detection, endpoint telemetry, custom detection engineering, attack simulation, and AI-assisted security operations into a unified security monitoring environment.
  
---

## Multi-Sensor Security Architecture

The platform combines three independent security monitoring layers into a single Elastic SIEM environment.

```text
Wireless Sensor (Alfa Adapter)
            │
            ▼
Network IDS (Suricata + Zeek)
            │
            ▼
Endpoint Telemetry (Sysmon + Winlogbeat)
            │
            ▼
Elasticsearch + Kibana
            │
            ▼
Detection Engineering
Threat Hunting
Attack Correlation
AI-Assisted Triage
```

---

## Platform Stack

### Detection Layers

#### Wireless Layer
- 802.11 monitoring
- Device discovery
- Wireless visibility

#### Network Layer
- SPAN-port traffic monitoring
- Suricata IDS
- Zeek protocol analysis
- Behavioral network detection

#### Endpoint Layer
- Sysmon telemetry
- Windows Security Events
- Process monitoring
- Persistence detection
- Privilege escalation monitoring

This architecture enables attack visibility across wireless, network, and endpoint activity while supporting full attack-chain correlation.

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


```text
Wireless Sensor (Alfa) ──────────────┐
                                     │
Network IDS (Suricata + Zeek) ───────┼──► Elasticsearch + Kibana
                                     │
Endpoint Telemetry (Sysmon) ─────────┘
                                              │
                                              ▼
                              Detection Engineering
                              Threat Hunting
                              Attack Correlation
                              AI-Assisted Triage
```

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

---

## Dashboard Inventory

1. SOC Dashboard — Executive monitoring and network visibility
2. Threat Hunting Dashboard — Behavioral analytics and anomaly hunting
3. Endpoint Threat Hunting Dashboard — Endpoint telemetry and persistence monitoring
4. SOC Detection & Rule Monitoring Dashboard — Detection engineering and rule health
5. Attack Chain Correlation Dashboard — Multi-stage attack visibility and alert correlation

---

## Custom Detection Rules

- Suspicious Encoded PowerShell
- Suspicious Scheduled Task Creation
- Registry Run Key Persistence
- Malicious Service Creation Detection
- Excessive Failed Logons
- New Local User Created
- User Added to Administrator Group

---

## Attack Simulation & Detection Validation

The platform was validated through a multi-stage attack simulation designed to emulate realistic attacker behavior across multiple MITRE ATT&CK tactics.

### Simulated Attack Chain

| Attack Phase | Technique | ATT&CK Technique | Detection Status |
|-------------|------------|------------------|------------------|
| Reconnaissance | Nmap Service Discovery | T1046 | Detected |
| Execution | Scheduled Task Creation | T1053.005 | Detected |
| Execution | Service Creation | T1543.003 | Detected |
| Persistence | Registry Run Key | T1547.001 | Detected |
| Privilege Escalation | New Local User Creation | T1136.001 | Detected |
| Privilege Escalation | User Added to Administrators | T1098 | Detected |

### Detection Validation Results

Successfully validated:

**A total of 41 alerts were generated during testing, including high-severity persistence and privilege escalation detections.**

- Suspicious Scheduled Task Creation
- Malicious Service Creation Detection
- Registry Run Key Persistence
- New Local User Created
- User Added to Administrator Group

Evidence, screenshots, dashboard correlation, and post-incident analysis are documented under:

Dashboards/Post_Attack_Visualization/

This testing confirmed end-to-end visibility from attacker activity to alert generation, dashboard correlation, investigation, and detection validation.

---

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
| 11 | Operational Validation | Multi-stage attack simulation, detection validation, MITRE ATT&CK coverage verification, attack-chain correlation, post-incident analysis |

---

## Attacker Tradecraft Simulated and Detected

### Reconnaissance
- Nmap host discovery
- Port scanning
- Service enumeration

### Execution
- Scheduled task creation
- Windows service creation
- Encoded PowerShell execution

### Persistence
- Registry Run Key persistence
- Scheduled task persistence

### Privilege Escalation
- New local user creation
- User added to Administrators group

### Endpoint Activity
- LOLBin invocation
- Process creation tracking
- Authentication monitoring

### Network Activity
- Beaconing detection
- SSH authentication analysis
- Protocol anomaly detection

Each technique was validated through custom detection rules, Elastic Security alerts, dashboard correlation, and MITRE ATT&CK mapping.

---

## Coming Next

### Day 12 — AI Alert Triage Engine

- Python script polling Elasticsearch for alerts
- Suricata network alerts + Sysmon endpoint alerts
- AI-generated alert summaries
- Automated ATT&CK mapping
- Analyst response recommendations
- Investigation guidance

### Day 13 — Portfolio Launch & Architecture Documentation

- Full architecture diagram
- Demo video
- GitHub polish
- LinkedIn publication
- Recruiter-ready documentation

### Day 14 — Advanced EDR Threat Hunting Platform

- Process tree analysis
- Parent-child process correlation
- PowerShell investigation dashboard
- Endpoint timeline analysis
- Advanced EDR visibility
  
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
