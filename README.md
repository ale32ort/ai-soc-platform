# AI-Assisted SOC Platform

A home-lab Security Operations Center (SOC) built on a Raspberry Pi 5 to emulate enterprise security monitoring, detection engineering, threat hunting, and incident response workflows.

The platform combines network intrusion detection, endpoint telemetry, Elastic Security detections, automated AI-assisted alert triage, Splunk integration, and real-time analyst notifications into a unified security operations environment.

## Highlights

* Built a multi-sensor SOC using Elastic Stack, Suricata, Zeek, Sysmon, and Winlogbeat
* Developed a Python-based AI triage engine that enriches Elastic Security detections with MITRE ATT&CK mapping, risk scoring, and analyst recommendations
* Integrated Splunk HEC forwarding for centralized alert correlation and reporting
* Implemented Telegram alerting for high-severity detections
* Created and validated 7 custom detection rules mapped to MITRE ATT&CK techniques
* Designed 5 dashboards for executive visibility, threat hunting, detection engineering, endpoint monitoring, and attack-chain correlation
* Conducted a multi-stage attack simulation covering reconnaissance, execution, persistence, and privilege escalation techniques
* Generated and validated 41 detection events across network and endpoint telemetry sources

---

## Project Overview

This project was designed to demonstrate practical SOC analyst and detection engineering skills through the construction of a complete security monitoring environment from scratch.

The platform provides visibility across three independent detection layers:

### Layer 1 — Wireless Monitoring

* Alfa AWUS036ACS wireless adapter
* Passive 802.11 monitoring
* Wireless device discovery and visibility

### Layer 2 — Network Detection

* Suricata IDS
* Zeek network telemetry
* SPAN port traffic monitoring
* Network-based threat detection and analysis

### Layer 3 — Endpoint Detection

* Sysmon endpoint telemetry
* Windows Security auditing
* Winlogbeat log forwarding
* Behavioral and persistence detection

All telemetry is centralized in Elasticsearch and Kibana, where Elastic Security detection rules generate alerts that are automatically analyzed by the AI triage engine.

---

## AI Triage Workflow

Windows Endpoint / Network Sensors
→ Elastic Security Detection Rules
→ AI Triage Engine (Python)
→ Claude Analysis
→ MITRE ATT&CK Mapping
→ Risk Scoring
→ Elasticsearch
→ Splunk HEC
→ Telegram Alerting

The triage engine automatically:

1. Retrieves Elastic Security detection alerts
2. Enriches alerts with contextual information
3. Generates AI-assisted analyst assessments
4. Maps activity to MITRE ATT&CK
5. Calculates risk scores
6. Produces executive summaries
7. Forwards results to Splunk
8. Sends notifications for high-risk alerts

---

## Technologies

### SIEM & Security Monitoring

* Elasticsearch
* Kibana
* Elastic Security
* Splunk

### Network Security

* Suricata
* Zeek
* Filebeat

### Endpoint Detection

* Sysmon
* Winlogbeat
* Windows Advanced Auditing

### Automation & Development

* Python
* Claude API
* Telegram Bot API

### Infrastructure

* Raspberry Pi 5
* Managed Switch (SPAN Port Mirroring)
* Kali Linux
* Windows Endpoint

---

## Key Skills Demonstrated

* Security Operations Center (SOC) Design
* Detection Engineering
* Threat Hunting
* Elastic Security Administration
* SIEM Architecture
* Endpoint Detection & Response (EDR)
* Network Security Monitoring
* MITRE ATT&CK Mapping
* Attack Simulation & Validation
* Python Automation
* AI-Assisted Security Operations
* Splunk Integration
* Incident Triage Workflows
* Security Dashboard Development

