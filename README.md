# AI-Assisted SOC Platform

A production-grade multi-sensor Security Operations Center (SOC) platform
built from scratch on a Raspberry Pi 5. The environment combines wireless
monitoring, network intrusion detection, endpoint telemetry, attack simulation,
detection engineering, and AI-assisted security operations into a unified
Elastic SIEM platform with automated Claude AI triage, Splunk HEC forwarding,
and real-time Telegram alerting.

The platform provides correlated visibility across three independent detection
layers and a fully automated detection-to-notification pipeline:

- Wireless Monitoring (Alfa AWUS036ACS)
- Network IDS Monitoring (Suricata + Zeek via SPAN Port Mirroring)
- Endpoint Detection and Response (Sysmon + Winlogbeat)
- AI-Assisted Alert Triage (Claude API + Elastic Security)

The environment was validated through a multi-stage attack simulation covering
Reconnaissance, Execution, Persistence, and Privilege Escalation techniques
mapped to MITRE ATT&CK.

---

## Quick Navigation

- Multi-Sensor Architecture
- AI Triage Engine
- Detection Engineering
- Threat Hunting Dashboards
- Attack Simulation and Validation
- MITRE ATT&CK Coverage
- Agentic AI Roadmap

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
- AI Triage Engine Operational
- Splunk HEC Forwarding Active
- Real-Time Telegram Alerting Active
- First Production AI Alert Delivered

---

## AI Triage Engine Architecture

The AI triage engine runs as a persistent service on the Raspberry Pi 5.
It queries Elastic Security detection alerts, enriches each alert with
Claude AI analysis, computes a risk score, and forwards results to
Elasticsearch, Splunk, and Telegram.

```
Windows Endpoint (Sysmon + Winlogbeat)
              |
              v
    Elastic Security Detection Rules
              |
              v
  .alerts-security.alerts-default
              |
              v
       AI Triage Engine (Python)
         /        |        \
        v         v         v
    Claude      Splunk    Telegram
    API         HEC       (HIGH/CRITICAL)
        \         |
         v        v
     MITRE Map  ai-soc
     Risk Score  index
     Exec Summary
        |
        v
  soc-triage-results
        |
        v
  Kibana SOC Triage
  Results Data View
```

### What the AI triage engine does per alert

1. Fetches confirmed Elastic Security detections
2. Pre-filters noisy and low-value events (cost control)
3. Checks Claude response cache — 24 hour TTL
4. Sends enriched alert context to Claude API
5. Receives verdict, ATT&CK mapping, risk score, executive summary
6. Writes enriched result to soc-triage-results Elasticsearch index
7. Forwards to Splunk HEC ai-soc index
8. Queues failed Splunk events to splunk_retry_queue.jsonl for retry
9. Sends Telegram notification for HIGH and CRITICAL verdicts only
10. Marks alert as seen only after Elasticsearch write succeeds

### AI triage output fields per alert

| Field | Description |
|-------|-------------|
| ai_verdict | TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_INVESTIGATION |
| ai_severity | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| risk_score | Numeric 0-100 based on six weighted factors |
| executive_summary | One plain-English sentence for dashboards |
| mitre_technique | ATT&CK technique ID and name |
| mitre_tactic | ATT&CK tactic name |
| recommended_action | Analyst response recommendation |
| confidence | HIGH / MEDIUM / LOW |
| false_positive_likelihood | HIGH / MEDIUM / LOW |
| pipeline_version | Engine version from environment |

### Risk score breakdown (0-100)

| Factor | Max points |
|--------|-----------|
| Severity — CRITICAL 35, HIGH 25, MEDIUM 15, LOW 5 | 35 |
| Verdict — TRUE_POSITIVE 25, NEEDS_INVESTIGATION 15 | 25 |
| Confidence — HIGH 15, MEDIUM 8, LOW 3 | 15 |
| False positive likelihood inverted — LOW 10, MEDIUM 5 | 10 |
| High-value MITRE technique bonus | 10 |
| Endpoint source bonus (winlogbeat) | 5 |

### Splunk search queries

All AI verdicts:
```
index="ai-soc" | table _time, host, alert_name, ai_verdict, ai_severity, risk_score, mitre_technique, executive_summary, recommended_action
```

True positives only:
```
index="ai-soc" ai_verdict="TRUE_POSITIVE" | table _time, host, alert_name, risk_score, executive_summary
```

High risk alerts:
```
index="ai-soc" risk_score>75 | sort -risk_score
```

ATT&CK frequency:
```
index="ai-soc" | stats count by mitre_technique | sort -count
```

---

## Multi-Sensor Security Architecture

```
Wireless Sensor (Alfa Adapter)
            |
            v
Network IDS (Suricata + Zeek)
            |
            v
Endpoint Telemetry (Sysmon + Winlogbeat)
            |
            v
Elasticsearch + Kibana
            |
            v
Elastic Security Detection Rules
            |
            v
AI Triage Engine
Detection Engineering
Threat Hunting
Attack Correlation
```

---

## Platform Stack

### Core Infrastructure
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM backend and visualization
- Elastic Security — detection rule engine and alert source
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

### AI and Forwarding
- Claude API (claude-sonnet-4-20250514) — alert triage and ATT&CK mapping
- Python triage engine — polling, enrichment, deduplication, retry queue
- Flask dashboard — live AI verdict display at port 5000
- Splunk HEC — enterprise SIEM forwarding to ai-soc index
- Telegram Bot — real-time analyst notifications for HIGH and CRITICAL

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
- Windows Security Event IDs: 4624, 4625, 4688, 4698, 4720, 7045
- PowerShell execution logging
- LOLBin activity monitoring
- Process creation chain visibility
- Persistence mechanism detection

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
- LOLBin abuse detection: powershell.exe, cmd.exe, rundll32.exe,
  certutil.exe, regsvr32.exe, mshta.exe, wmic.exe
- Encoded PowerShell detection and command-line visibility
- Persistence mechanism monitoring: scheduled tasks, service installs,
  new account creation
- Authentication success and failure tracking
- Windows Security audit event ingestion

### AI-Assisted Operations
- Automated triage of confirmed Elastic Security detections
- Claude AI verdict: TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_INVESTIGATION
- Automated MITRE ATT&CK technique and tactic mapping
- Risk scoring 0-100 across six weighted factors
- Plain-English executive summary per alert
- Analyst response recommendation per alert
- Splunk HEC forwarding with retry queue for resilience
- Telegram real-time notification for HIGH and CRITICAL verdicts

### Dashboard Design

Executive Overview — KPI panels for security leadership:
- DNS requests, external connections, total network traffic
- Total alerts, potential beaconing activity
- Unique foreign countries, active source hosts
- Targeted assets, live event count, observed protocols

Analyst Investigation — Live investigation workflows:
- Live network events table with full field visibility
- SSH activity monitor
- Alert feeds and threat signature tracking
- Endpoint process and authentication tables
- Pivot-ready investigation surfaces

---

## Dashboard Architecture

### SOC Dashboard
Executive-level security visibility:
- Total alerts and event volume
- Active hosts and targeted assets
- External connection monitoring
- Protocol distribution analysis
- Network activity overview

### Threat Hunting Dashboard
Behavioral hunting platform:
- Beaconing detection patterns
- Uncommon TCP service activity
- Suricata alert visibility and severity
- Destination port analysis
- Host activity behavioral analysis
- Network anomaly detection

### Endpoint Threat Hunting Dashboard
Endpoint visibility and persistence tracking:
- Process creation activity
- Authentication events
- Failed logon monitoring
- Persistence-related activity
- Endpoint behavioral telemetry
- Windows security event analysis

### SOC Detection and Rule Monitoring Dashboard
Detection engineering health:
- Rule execution health
- Detection reliability
- Alert generation performance
- Rule scheduling delays
- Detection tuning effectiveness
- False positive reduction

### Attack Chain Correlation Dashboard
Multi-stage attack visibility:
- Correlated detection timeline
- Persistence and privilege escalation events
- Most targeted hosts and users
- Alert distribution analysis
- Live SOC alert monitoring

---

## Custom Detection Rules

All seven rules are deployed in Elastic Security with MITRE ATT&CK
tagging and severity classification. Each rule was validated through
controlled attack simulation.

| Rule | Event ID | MITRE Technique | Severity |
|------|----------|----------------|----------|
| Suspicious Encoded PowerShell | 4688/4104 | T1059.001 | High |
| Suspicious Scheduled Task Creation | 4698 | T1053.005 | Medium |
| Registry Run Key Persistence | Sysmon 13 | T1547.001 | High |
| Malicious Service Creation Detection | 7045 | T1543.003 | High |
| Excessive Failed Logons | 4625 | T1110 | Medium |
| New Local User Created | 4720 | T1136.001 | High |
| User Added to Administrator Group | 4732 | T1078.003 | Critical |

---

## Attack Simulation and Detection Validation

Validated through a multi-stage attack simulation emulating realistic
attacker behavior across multiple MITRE ATT&CK tactics.

| Attack Phase | Technique | ATT&CK ID | Detection |
|-------------|-----------|-----------|-----------|
| Reconnaissance | Nmap Service Discovery | T1046 | Detected |
| Execution | Scheduled Task Creation | T1053.005 | Detected |
| Execution | Service Creation | T1543.003 | Detected |
| Persistence | Registry Run Key | T1547.001 | Detected |
| Privilege Escalation | New Local User Creation | T1136.001 | Detected |
| Privilege Escalation | User Added to Administrators | T1098 | Detected |

41 alerts generated during testing including high-severity persistence
and privilege escalation detections. Evidence, screenshots, dashboard
correlation, and post-incident analysis documented under:
Dashboards/Post_Attack_Visualization/

---

## Threat Hunting Coverage

### Network — MITRE ATT&CK mapped
| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Reconnaissance | T1595 | Port scan, rare external connections |
| Discovery | T1046 | Network service scanning |
| Lateral Movement | T1021 | East-west traffic, rare internal ports |
| Command and Control | T1071 | Beaconing, non-standard TCP |
| Exfiltration | T1041 | Byte volume analysis |
| Credential Access | T1110 | SSH brute force, auth failures |

### Endpoint — MITRE ATT&CK mapped
| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Execution | T1059.001 | Encoded PowerShell |
| Execution | T1218 | LOLBin abuse |
| Persistence | T1053.005 | Scheduled task (Event 4698) |
| Persistence | T1543.003 | Service installation (Event 7045) |
| Persistence | T1136.001 | New account creation (Event 4720) |
| Credential Access | T1003 | LSASS access (Sysmon EID 10) |
| Defense Evasion | T1055 | Process injection |

---

## Daily Build Log

| Day | Focus | Key Achievement |
|-----|-------|----------------|
| 1 | Infrastructure | Full SOC pipeline built from scratch |
| 2 | Sensors | Wireless monitoring, professional dashboards |
| 3 | Troubleshooting | SSL/TLS resolution, Kibana restored |
| 4 | Validation | Interface routing fixed, pipeline confirmed |
| 5 | Threat Hunting | Behavioral analytics platform built |
| 6 | Executive Layer | SOC Dashboard, dual-audience architecture |
| 7 | Detection Tuning | KQL noise reduction, signal optimization |
| 8 | Endpoint Layer | Sysmon + Winlogbeat, three-layer detection |
| 9 | EDR Visibility | LOLBin detection, attacker tradecraft simulation |
| 10 | Detection Engineering | 7 rules, ATT&CK mapped, rule health monitoring |
| 11 | Operational Validation | Multi-stage attack simulation, detection validation, attack-chain correlation |
| 12 | AI Integration | Elastic Security alert triage, Claude API, Splunk HEC, Telegram delivery |

---

## Environment Variables
.env.example with required environment variable template


```
ANTHROPIC_API_KEY=sk-ant-your-key
ELASTIC_URL=https://localhost:9200
ELASTIC_USER=elastic
ELASTIC_PASSWORD=your-password
SPLUNK_HEC_URL=https://splunk-host:8088/services/collector/event
SPLUNK_HEC_TOKEN=your-token
SPLUNK_INDEX=ai-soc
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id
POLL_INTERVAL=60
TRIAGE_INDEX=soc-triage-results
SEEN_INDEX=soc-triage-seen
SOC_SKIPPED_INDEX=soc-triage-skipped
SPLUNK_RETRY_QUEUE=splunk_retry_queue.jsonl
CLAUDE_CACHE_FILE=claude_cache.json
CLAUDE_CACHE_TTL_HOURS=24
PIPELINE_VERSION=1.0.0
```

---

## Running the Triage Engine

Normal mode:
```bash
source triage-env/bin/activate
python3 triage_engine.py
```

Test mode — validates Splunk, fields, risk score without calling Claude:
```bash
python3 triage_engine.py --test
```

Watch live logs:
```bash
sudo journalctl -u soc-triage -f
```

---

## Future Roadmap — Agentic AI Evolution

### Phase 2 — Autonomous Investigation Agent
Replace single Claude API call with multi-step autonomous agent:
- Automatic VirusTotal hash lookups
- Threat intelligence feed enrichment
- Automatic SIEM pivot and host history correlation
- Cross-host event correlation
- Confidence-scored investigation reports

### Phase 3 — Local Sovereign AI
Replace cloud API with locally-hosted Hermes model:
- Zero external dependencies
- Air-gap capable architecture
- Classified environment ready
- No data leaves the network
- Full sovereign AI security operations

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
- Automated alert enrichment and MITRE ATT&CK mapping
- Risk scoring and executive summary generation
- Enterprise SIEM forwarding via Splunk HEC
- Real-time analyst notification via Telegram
- Retry queue resilience for downstream integrations
- Claude response caching for API cost control
- Pipeline versioning for operational tracking

---

## Repository

github.com/ale32ort/ai-soc-platform

Full build history, daily recaps, detection rule source,
triage engine code, and dashboard screenshots documented
across 12 days of commit history.
