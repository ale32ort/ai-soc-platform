# Day 12 — AI SOC Triage Engine: Elastic Security Integration + Telegram Alerting

## Objective
Integrate Elastic Security detection alerts directly into the AI
triage engine, enable automated Claude analysis of confirmed
detections, and configure real-time Telegram notifications for
high-severity events.

---

## Major Accomplishments

### 1. Migrated AI Triage to Elastic Security Alerts
Redesigned the triage engine alert source from raw telemetry
to confirmed Elastic Security detection alerts.

Before:
- Queried filebeat-* and winlogbeat-* raw event streams
- AI engine performed detection logic itself

After:
- Queries .alerts-security.alerts-default
- Elastic Security detection rules run first
- AI engine triages confirmed detections only

Why this matters: The division of labor is now architecturally
correct. Elastic detects. Claude triages. Each layer does
exactly one job. This mirrors how production SOC platforms
like Splunk ES and Microsoft Sentinel operate.

---

### 2. Enhanced Claude Prompt for Elastic Security Context
Updated prompt builder to extract Elastic Security alert fields:

- Rule Name
- Alert Severity
- Elastic Risk Score
- Alert Reason
- Host Name
- Username
- Source IP
- Original Event Code
- Rule Description

Example prompt context generated:
```
ALERT TYPE: Elastic Security Detection
RULE NAME: Excessive Failed Logons
ELASTIC SEVERITY: high
ELASTIC RISK SCORE: 80
HOST: tito
USER: testadmin
```

Richer context produces higher-quality Claude triage decisions
with more accurate MITRE mapping and response recommendations.

---

### 3. Validated Detection Rules End-to-End

#### Excessive Failed Logons
- Trigger: Repeated Windows Event ID 4625
- Elastic rule fires on threshold breach
- AI triage receives enriched alert
- MITRE mapping: T1110.001 — Password Guessing
- Claude verdict and response recommendation generated

#### Malicious Service Creation
- Trigger: Windows Event ID 7045
- Elastic rule fires on service installation
- AI triage receives enriched alert
- MITRE mapping: T1543.003 — Create or Modify System Process
- Claude verdict and response recommendation generated

---

### 4. Created SOC Triage Results Data View in Kibana
Built dedicated Kibana Data View: SOC Triage Results
Connected to: soc-triage-results*

Enables:
- Searching all AI verdicts
- Reviewing MITRE technique mappings
- Reviewing Claude analysis text
- Building future AI triage dashboards

---

### 5. Validated Full End-to-End Pipeline

Confirmed working pipeline:
```
Windows Event
      ↓
Sysmon + Winlogbeat
      ↓
Elastic Security Detection Rule
      ↓
.alerts-security.alerts-default
      ↓
AI Triage Engine (Python)
      ↓
Claude API (analysis + MITRE mapping)
      ↓
Risk Scoring (0-100)
      ↓
Elasticsearch soc-triage-results
      ↓
Splunk HEC ai-soc index
      ↓
Telegram (HIGH/CRITICAL only)
```

Verified in engine logs:
```
Verdict: NEEDS_INVESTIGATION
Severity: HIGH
Risk: 63/100
MITRE: T1543.003
```

---

### 6. Configured and Debugged Telegram Alerting

Configured Telegram bot and chat ID for real-time notifications.

Failure 1: 404 Not Found
- Root cause: Incorrect bot token format
- Resolution: Corrected token from BotFather

Failure 2: 400 Bad Request — can't parse entities
- Root cause: parse_mode="Markdown" rejected malformed
  special characters in alert fields
- Resolution: Removed Markdown parse mode from payload
- Result: Plain text delivery confirmed working

Key lesson: Production integrations require testing every
failure mode independently. Two distinct errors, two distinct
root causes, two distinct fixes.

---

### 7. First Production AI Alert Delivered

Successfully received first fully automated AI SOC notification:

```
AI SOC -- HIGH
Verdict: NEEDS_INVESTIGATION
Alert: Windows Event 7045
Host: tito
MITRE: T1543.003
Create or Modify System Process: Windows Service
```

This is the first time the complete detection-to-notification
workflow ran end to end without manual intervention.
Detection rule fired → Claude analyzed → Telegram delivered.

---

<<<<<<< HEAD
=======
### 8. Productionized AI Triage Engine

Created a dedicated systemd service (ai-triage.service) to automatically start the AI triage engine during system boot.

Benefits:
- No manual execution required
- Automatic restart after reboot
- Continuous alert monitoring
- Persistent SOC operation

Verification:
- Service enabled with systemctl enable ai-triage
- Confirmed active (running) status
- Successfully polling Elastic Security alerts after startup

---

>>>>>>> 396ef9d (Day 12 - AI triage engine integration and automated service deployment)
## Current Architecture

```
Windows Endpoint (Sysmon + Winlogbeat)
              ↓
    Elastic Security Detection Rules
              ↓
  .alerts-security.alerts-default
              ↓
       AI Triage Engine (Python)
         ↙        ↓        ↘
    Claude      Splunk    Telegram
      ↓          HEC      (HIGH/CRITICAL)
  MITRE Map     ai-soc
  Risk Score
  Exec Summary
      ↓
  soc-triage-results
      ↓
  Kibana Dashboard
```

---

## Lessons Learned

Detection alerts are more useful than raw telemetry for AI
triage. Elastic Security alert fields differ significantly
from Winlogbeat event fields — the prompt builder required
a dedicated parsing branch for each source type.

Telegram Markdown formatting silently breaks delivery when
alert fields contain special characters. Plain text is more
reliable for production alerting pipelines.

Cached Claude responses dramatically reduce analysis time
for repeated alert patterns. The cache hit rate increases
significantly once the engine has been running for 24 hours.

Real SOC workflows require alert enrichment before analyst
review. The architectural shift from raw telemetry to
detection-validated alerts reflects how enterprise platforms
like Splunk ES, Microsoft Sentinel, and CrowdStrike operate.

---

## Skills Practiced
- Elastic Security alert schema and field mapping
- Multi-source prompt engineering for AI triage
- Telegram bot configuration and API debugging
- Production error diagnosis — 404 vs 400 failure modes
- End-to-end pipeline validation and logging
- SOC alert enrichment workflow design
- Kibana Data View creation and management

---

## Current Full Stack
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM and visualization
- Elastic Security — detection rule engine and alert source
- Suricata IDS — network layer detection
- Filebeat — Linux log shipping
- Zeek — network protocol analysis
- Alfa AWUS036ACS — wireless monitoring
- TP-Link TL-SG108E — managed switch with port mirroring
- Sysmon (SwiftOnSecurity) — endpoint behavioral telemetry
- Winlogbeat — Windows log shipping
- Claude API — AI alert triage and MITRE mapping
- Splunk HEC — enterprise SIEM forwarding
- Telegram Bot — real-time analyst notifications
- Kali Linux VM — attack simulation
- Windows host — monitored endpoint

---

## Biggest Win
Delivered the first fully automated detection-to-notification
workflow without manual intervention.

A Windows service installation triggered an Elastic Security
detection rule. The AI triage engine fetched the alert,
sent it to Claude for analysis, computed a risk score of
63/100, mapped it to T1543.003, and delivered a HIGH severity
notification to Telegram — all automatically.

That is not a home lab. That is a production SOC workflow.

---

## Day 13 Plan — Portfolio Launch
- Record 3-4 minute demo video with OBS Studio
- Show full kill chain: attack → Elastic detection →
  Claude triage → Splunk → Telegram notification
- Polish GitHub README with final architecture diagram
- Update resume with pipeline_version and Splunk integration
- LinkedIn portfolio post with GitHub link and video
