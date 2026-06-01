# Day 9 — Endpoint Threat Hunting Dashboard + EDR-Style Visibility

## Objective
Transform the endpoint telemetry pipeline into a functioning
threat hunting and detection engineering workspace using
Windows Security auditing, Winlogbeat, and Kibana dashboards
focused on attacker tradecraft visibility.

---

## Major Accomplishments

### 1. Expanded Windows Security Event Coverage

Validated and visualized critical Windows Security Event IDs
inside Kibana through Winlogbeat ingestion.

| Event ID | Detection Purpose |
|----------|------------------|
| 4688 | Process creation monitoring |
| 4624 | Successful logon tracking |
| 4625 | Failed logon / brute force detection |
| 4698 | Scheduled task creation (persistence) |
| 4720 | New user account creation |
| 7045 | Service installation monitoring |

---

### 2. Built Endpoint Threat Hunting Dashboard
Created dedicated Windows endpoint monitoring dashboard
organized by detection layer and telemetry layer —
mirroring the architecture of enterprise platforms
including Elastic Security, Microsoft Sentinel,
Splunk ES, Defender XDR, and CrowdStrike.

---

## Dashboard Panels Built

### Detection Layer — High Signal Panels

#### Encoded PowerShell Detection
Monitors for obfuscated command execution:
powershell.exe -EncodedCommand

Successfully simulated and detected encoded PowerShell
execution. Validated full pipeline: command execution →
Winlogbeat ingestion → Elastic indexing → Kibana alert.

#### Failed Logon Monitoring
Tracks authentication failures via event.code:4625.
Surfaces brute force attempts and password spraying
indicators in real time.

#### Persistence Mechanism Detection
Monitors scheduled task creation via event.code:4698.
Fields: TaskName, creation time, user context.
Extended to future service installs (7045) and
rogue account creation (4720).

---

### Telemetry Layer — Behavioral Visibility Panels

#### Process Creation Activity
Tracks Windows process execution volume over time.
Query: event.code:4688
Purpose: behavioral baselining, execution spike detection,
suspicious process pattern identification.

#### LOLBin Activity Monitor
Dedicated panel tracking Living-Off-The-Land binaries
commonly abused by attackers:
- powershell.exe
- cmd.exe
- rundll32.exe
- certutil.exe
- regsvr32.exe
- mshta.exe
- wmic.exe

Purpose: attacker tradecraft visibility, LOLBin abuse
detection, threat hunting telemetry.

#### PowerShell Activity Table
Detailed execution monitoring including:
- user.name
- process.command_line
- host.name

Surfaces PowerShell abuse, command-line visibility,
and encoded command preparation.

#### Parent/Child Process Panel
Process lineage visibility using process.parent.name.
Detects suspicious execution chains — Word spawning
PowerShell, cmd spawning unusual children, and other
attacker tradecraft patterns.

#### Successful Logon Monitoring
Authentication baselining via event.code:4624.
Establishes normal user activity patterns for
anomaly detection.

---

### 3. Enabled Advanced Windows Security Auditing
Configured Windows audit policy to generate additional
security telemetry beyond default logging.

Enabled via auditpol:
- Other Object Access Events
- Scheduled Task auditing

Key insight: Not all Windows events are logged by default.
Security visibility requires intentional audit policy
configuration. Enterprise SOC deployments spend significant
time on this exact problem.

---

### 4. Simulated Attacker Tradecraft
Performed controlled attack simulations generating
realistic endpoint telemetry:

Simulations run:
- Encoded PowerShell execution
- Scheduled task creation (persistence technique)
- Suspicious process execution chains
- LOLBin invocation patterns

Each simulation validated:
- Telemetry generation on endpoint
- Winlogbeat ingestion and parsing
- Elasticsearch indexing
- Kibana dashboard visibility

This is detection validation — confirming the platform
catches what it's supposed to catch before relying on
it in a real investigation.

---

## Key Concepts Learned

### Telemetry Architecture
Not all Windows events are logged by default. Security
visibility requires intentional audit policy configuration.
Different event IDs expose different fields — 4698 exposes
TaskName, 7045 exposes ServiceName, 4720 exposes
TargetUserName. Field awareness is critical for accurate
detection logic and dashboard stability.

### Detection vs Investigation Workflow
Dashboards surface important activity and suspicious
behavioral patterns for analyst awareness.
Discover is for raw investigation, forensic analysis,
and deep telemetry inspection.
These are distinct workflows serving distinct purposes —
understanding the difference is foundational SOC methodology.

### LOLBin Detection Philosophy
Living-Off-The-Land attacks use legitimate Windows binaries
to execute malicious actions — evading signature-based
network detection. Endpoint telemetry from Sysmon and
Windows Security logging is the primary detection surface
for these techniques. Network IDS alone is blind to them.

### MITRE ATT&CK Coverage Added Today
| Technique | ID | Detection |
|-----------|-----|-----------|
| PowerShell abuse | T1059.001 | Event 4104/4688 |
| Scheduled task persistence | T1053.005 | Event 4698 |
| New account creation | T1136.001 | Event 4720 |
| Service installation | T1543.003 | Event 7045 |
| LOLBin execution | T1218 | Event 4688 |
| Brute force | T1110 | Event 4625 |

---

## Dashboard Architecture
Organized to mirror enterprise SOC platforms:

### Detection Layer (High Priority)
- Encoded PowerShell alerts
- Failed logon spikes
- Persistence mechanism creation

### Telemetry Layer (Behavioral Context)
- Process creation volume
- LOLBin activity
- PowerShell command-line details
- Parent/child process chains
- Successful authentication baseline

This two-layer architecture matches how Elastic Security,
Microsoft Sentinel, and CrowdStrike organize their
detection interfaces — detection surfaces at top,
supporting telemetry below.

---

## Skills Practiced
- Windows Security auditing configuration
- Winlogbeat telemetry ingestion and field mapping
- Kibana Lens visualization engineering
- Elastic SIEM detection workflow design
- Endpoint telemetry engineering
- PowerShell monitoring and abuse detection
- LOLBin tradecraft detection
- Attacker simulation and detection validation
- Event ID taxonomy and field structure
- Detection vs investigation workflow design

---

## Current Full Stack
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM backend and visualization
- Suricata IDS — network layer detection
- Filebeat — Linux log shipping
- Zeek — network protocol analysis
- Alfa AWUS036ACS — wireless monitoring
- TP-Link TL-SG108E — managed switch with port mirroring
- Sysmon (SwiftOnSecurity config) — endpoint behavioral telemetry
- Winlogbeat — Windows log shipping
- Windows Security Auditing — endpoint event generation
- Kali Linux VM — attack simulation
- Windows host — monitored endpoint

---

## Biggest Win
Built an EDR-style endpoint detection workspace that
surfaces attacker tradecraft — encoded PowerShell,
LOLBin abuse, persistence mechanisms, and suspicious
process chains — using the same detection philosophy
as enterprise platforms costing hundreds of thousands
of dollars annually.

Validated every detection by simulating the attack
and confirming it appeared in the dashboard. That
validation discipline is what separates detection
engineers from people who just build dashboards.

---

## Day 10 Plan — Detection Rules + Claude AI Triage Engine
Next session builds two critical layers:

### Elastic Detection Rules
- Encoded PowerShell alert rule
- LOLBin abuse detection rule
- Brute force threshold alert
- Persistence mechanism alert
- MITRE ATT&CK tagging on all rules
- Severity classification

### Claude AI Triage Engine
- Python script polling Elasticsearch for alerts
- Suricata network alerts + Sysmon endpoint alerts
- Claude API analyzes each alert with full context
- Returns: verdict, explanation, ATT&CK mapping,
  response recommendation
- Flask dashboard displays AI triage alongside raw alert
- Full kill chain visible: attack → detection → AI analysis



