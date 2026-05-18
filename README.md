# AI-Assisted SOC Platform

A production-grade security operations platform built on
Raspberry Pi 5 from scratch. Designed to demonstrate
real-world SOC capabilities including multi-sensor network
monitoring, behavioral threat hunting, and AI-assisted
alert triage with automated MITRE ATT&CK mapping.

---

## Platform Stack
- Raspberry Pi 5 8GB
- Elasticsearch + Kibana (SIEM)
- Suricata IDS
- Filebeat log shipping
- Alfa AWUS036ACS wireless monitor adapter
- TP-Link TL-SG108E managed switch with port mirroring
- Kali Linux attack simulation environment

---

## Current Capabilities
- Multi-sensor monitoring: wired IDS + wireless 802.11 capture
- Behavioral threat hunting: beaconing, lateral movement,
  exfiltration, DNS anomalies
- Executive and analyst dual-audience dashboards
- Real-time IDS alert correlation and signature monitoring
- Geographic traffic visualization and external connection tracking
- SSH authentication monitoring
- Live network telemetry investigation tables

---

## Architecture
- eth0 → Primary wired interface → managed switch (port mirroring)
wlan1 (Alfa) → Monitor mode → 802.11 frame capture
Suricata → eve.json → Filebeat → Elasticsearch → Kibana

---

## Dashboard Design
Platform serves two distinct audiences:

**Executive Overview** — KPI panels for security leadership:
foreign countries, targeted assets, beaconing activity,
alert volumes, protocol distribution

**Analyst Investigation** — Live event tables, SSH monitoring,
alert feeds, threat signature tracking, pivot-ready workflows

---

## Threat Hunting Panels
Organized by MITRE ATT&CK tactic:
- Reconnaissance: port scan detection, rare external connections
- Lateral Movement: east-west traffic, rare internal ports
- Command & Control: beaconing detection, non-standard TCP
- Exfiltration: byte volume analysis, external data transfer
- Credential Access: SSH brute force, authentication failures

---

## Daily Build Log
| Day | Focus | Key Achievement |
|-----|-------|-----------------|
| 1 | Infrastructure | Full SOC pipeline built from scratch |
| 2 | Sensors | Wireless monitoring, professional dashboards |
| 3 | Troubleshooting | SSL/TLS resolution, Kibana restored |
| 4 | Validation | Interface routing fixed, pipeline confirmed |
| 5 | Threat Hunting | Behavioral analytics platform built |
| 6 | Executive Layer | Dual-audience dashboard architecture |

---

## Coming Next
- Attack simulation and detection validation
- Claude AI alert triage engine
- Automated MITRE ATT&CK mapping
- AI-powered investigation dashboard
- Demo video walkthrough
