# Day 10 — Detection Engineering & Multi-Layer SOC Expansion

## Objective
Expand the SOC platform from a visibility environment into
a functioning detection engineering practice with formal
alert rules, false positive reduction, rule health monitoring,
and multi-stage attack chain visibility.

---

## Detection Rules Built and Deployed

### 1. Suspicious Encoded PowerShell
Detects obfuscated or encoded PowerShell execution associated
with malware delivery, payload execution, and attacker
tradecraft. Targets -EncodedCommand parameter usage and
base64-encoded command strings.

MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell
Severity: High

### 2. Suspicious Scheduled Task Creation
Detects Windows scheduled task creation via Event ID 4698.
Commonly used for persistence and recurring payload execution.

MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
Severity: Medium

### 3. Registry Run Key Persistence
Detects registry Run key modifications associated with
persistence mechanisms. Monitors HKLM and HKCU Run key
write operations via Sysmon Event ID 13.

MITRE ATT&CK: T1547.001 — Boot or Logon Autostart: Registry Run Keys
Severity: High

### 4. Malicious Service Creation
Detects suspicious Windows service creation via Event ID 7045.
Associated with malware persistence and privilege escalation.

MITRE ATT&CK: T1543.003 — Create or Modify System Process: Windows Service
Severity: High

### 5. Excessive Failed Logons
Detects multiple failed authentication attempts indicating
brute force or password spraying activity. Threshold-based
rule firing on repeated Event ID 4625 from single source.

MITRE ATT&CK: T1110 — Brute Force
Severity: Medium

### 6. New Local User Created
Detects creation of new local user accounts via Event ID 4720.
Indicates potential persistence or unauthorized account creation.

MITRE ATT&CK: T1136.001 — Create Account: Local Account
Severity: High

### 7. User Added to Administrator Group
Detects privilege escalation via local administrator group
membership modification. Event ID 4732 monitoring for
sensitive group changes.

MITRE ATT&CK: T1078.003 — Valid Accounts: Local Accounts
Severity: Critical

---

## Detection Coverage Map

| Tactic | Technique | Rule | Severity |
|--------|-----------|------|----------|
| Execution | T1059.001 | Encoded PowerShell | High |
| Persistence | T1053.005 | Scheduled Task Creation | Medium |
| Persistence | T1547.001 | Registry Run Key | High |
| Persistence | T1543.003 | Service Creation | High |
| Persistence | T1136.001 | New Local User | High |
| Credential Access | T1110 | Excessive Failed Logons | Medium |
| Privilege Escalation | T1078.003 | Admin Group Addition | Critical |

---

## Dashboards Built

### SOC Detection & Rule Monitoring Dashboard
Dedicated detection engineering health dashboard tracking:
- Rule execution performance and timing
- Alert generation rate and volume
- Detection scheduling delay monitoring
- Rule reliability metrics
- Top slowest rules identification
- Detection health indicators

This dashboard mirrors what enterprise SOC teams use to
maintain detection infrastructure — ensuring rules are
firing correctly, performing efficiently, and not generating
excessive false positives.

### Threat Hunting Dashboard
Expanded hunting platform tracking:
- Beaconing detection patterns
- Uncommon TCP service activity
- Suricata alert visibility and severity
- Destination port analysis
- Host activity behavioral analysis
- Network anomaly detection

### Network IDS Monitoring Dashboard
Extended Suricata telemetry visibility:
- External connection tracking
- Potential beaconing activity
- Protocol distribution monitoring
- Active host enumeration
- Network traffic volume analysis
- Threat severity classification

---

## Detection Engineering — False Positive Reduction

Implemented false positive reduction logic by excluding
legitimate parent processes from persistence detection rules.

Example exclusion applied:
- OmenCommandCenter.exe excluded from registry
  persistence rules

This is professional detection engineering methodology.
Raw rules generate noise. Tuned rules generate signal.
The exclusion process — identifying legitimate behavior
that matches detection logic and explicitly excluding it —
is what separates functional detection from alert fatigue.

---

## Attack Chain Visibility

Platform transitioned from isolated event detection to
multi-stage attack chain visibility.

Current detection coverage across kill chain:

| Kill Chain Stage | Coverage |
|-----------------|----------|
| Execution | Encoded PowerShell, LOLBin abuse |
| Persistence | Scheduled tasks, registry keys, services, new accounts |
| Privilege Escalation | Admin group modification |
| Credential Access | Brute force, failed logon thresholds |
| Network | Suricata IDS, beaconing, external connections |

---

## Integrated Telemetry Sources

| Source | Data Type | Coverage |
|--------|-----------|----------|
| Winlogbeat | Windows Security Events | Authentication, account changes |
| Sysmon | Endpoint Behavioral | Process, network, registry, file |
| Suricata IDS | Network Alerts | Signatures, anomalies, protocols |
| Elastic Security | Detection Engine | Rule execution, alert management |
| Kibana | Visualization | Dashboard, investigation, hunting |

---

## Screenshots Committed

- Detection rules view — all rules enabled
- Rule monitoring dashboard
- Threat hunting dashboard
- Network IDS monitoring dashboard
- SOC overview dashboard

---

## Key Concepts Learned

### Detection Engineering Methodology
Rules require tuning after initial deployment. Raw detection
logic matches both malicious and legitimate behavior.
False positive reduction through process exclusions,
threshold tuning, and context filtering transforms noisy
rules into high-fidelity detections.

### Rule Health Monitoring
Detection rules can fail silently — scheduling delays,
indexing issues, and performance problems all degrade
detection capability without obvious indicators.
A dedicated rule monitoring dashboard surfaces these
issues before they create blind spots.

### Multi-Stage Visibility
Individual events are less valuable than correlated
sequences. Seeing encoded PowerShell execution followed
by scheduled task creation followed by registry modification
from the same host in a short timeframe is a complete
attack chain story — far more actionable than any single
alert in isolation.

---

## Skills Practiced
- Elastic Security detection rule authoring
- MITRE ATT&CK technique mapping and tagging
- Severity classification and alert prioritization
- False positive reduction and exclusion logic
- Detection health monitoring dashboard design
- Multi-stage attack chain correlation
- Threshold-based behavioral rule development
- Detection engineering documentation

---

## Current Full Stack
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM and visualization
- Elastic Security — detection rule engine
- Suricata IDS — network layer detection
- Filebeat — Linux log shipping
- Zeek — network protocol analysis
- Alfa AWUS036ACS — wireless monitoring
- TP-Link TL-SG108E — managed switch with port mirroring
- Sysmon (SwiftOnSecurity) — endpoint behavioral telemetry
- Winlogbeat — Windows log shipping
- Kali Linux VM — attack simulation
- Windows host — monitored endpoint

---

## Biggest Win
Built seven production-grade detection rules covering five
MITRE ATT&CK tactics with severity classification and false
positive reduction logic. Built a dedicated rule health
monitoring dashboard to maintain detection infrastructure.

The platform now has a detection engineering practice —
not just dashboards, but formal alerting logic that has
been tuned to reduce noise and validated against real
telemetry. That is the difference between a monitoring
environment and a detection platform.

---

## Day 11 Plan — Attack Simulation + Claude AI Triage Engine

### Attack Simulations
Validate every detection rule by triggering the behavior
and confirming the alert fires:
- Encoded PowerShell execution
- Scheduled task persistence creation
- Registry Run key modification
- Service creation
- Brute force authentication attempts
- New local user creation
- Admin group privilege escalation

### Claude AI Triage Engine
Python script polling Elasticsearch for active alerts.
Claude API analyzes each alert with full context.
Returns: verdict, ATT&CK mapping, response recommendation.
Flask dashboard displays AI triage alongside raw alert.

Combined with validated detection rules, the Claude layer
produces the most compelling demo scenario possible:
known attack technique → validated detection rule fires
→ Claude explains the threat in plain English → analyst
receives actionable response recommendation.

Day 11 is when the platform becomes genuinely unique
in the cleared junior market.
