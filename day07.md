# Day 7 — Threat Hunting Dashboard Tuning & Detection Engineering

## Objective
Transform the SOC dashboard from a general monitoring environment
into a focused threat hunting platform capable of detecting
suspicious activity, reducing noise, and visualizing
attacker behavior patterns.

---

## Major Accomplishments

### 1. SOC Command Dashboard Tuning
Refined and reorganized the primary SOC dashboard to improve
visibility into critical security events.

Improvements made:
- Cleaner panel structure and layout
- Improved color hierarchy for alert severity
- Better traffic categorization
- Increased readability of high-value metrics
- Reduced clutter from informational noise

Panels refined:
- Critical alerts
- External connections
- Suricata activity timeline
- Protocol distribution
- Targeted assets
- Internal hosts
- Geographic traffic origins
- Real-time detections

---

### 2. Built Dedicated Threat Hunting Dashboard
Created a separate threat hunting dashboard focused on
identifying adversary behavior patterns rather than
general network monitoring.

Hunting panels built:
- Beaconing behavior detection
- Suspicious TCP activity
- Uncommon destination ports
- Internal lateral movement
- Multi-port enumeration
- Failed connections
- DNS anomalies
- Data exfiltration patterns
- Rare internal ports
- High-volume internal communicators

---

### 3. KQL Noise Reduction Filters
Developed and applied custom Kibana Query Language filters
to dramatically reduce environmental noise and surface
genuine threat signals.

Noise sources filtered:
- Microsoft telemetry
- MSN traffic
- Xfinity infrastructure
- Office 365 telemetry
- Standard web traffic (ports 80, 443, 53)

Example filters applied:
NOT dns.question.name:(*.microsoft.com OR *.msn.com
OR *.xfinity.com OR *.office.com)
AND NOT destination.port:(53 OR 80 OR 443)

Result: Dramatic improvement in signal-to-noise ratio.
Suspicious traffic became visible after filtering
legitimate baseline activity.

---

### 4. Threat Signals Surfaced After Tuning
After applying noise reduction filters, the dashboard
began surfacing genuine threat indicators:

- Uncommon TCP destination ports
- Suspicious service activity
- Packed executable download signatures
- Suricata hunting rule matches
- Potential beaconing patterns
- Suspicious external IP communications
- Unusual outbound traffic behavior

---

### 5. Detection-Oriented Visualizations Built

#### Beaconing Detection
- Periodic traffic visualization
- Low-volume recurring communication patterns
- Potential command-and-control callback identification

#### Multi-Port Enumeration Detection
- Scanning behavior identification
- Reconnaissance attempt visualization
- Port enumeration activity monitoring

#### Internal Lateral Movement
- East-west traffic mapping
- Source-to-destination internal communication
- Rare internal port monitoring

---

## Key Concepts Learned

### Detection Engineering Fundamentals
- KQL filtering for SIEM optimization
- Traffic baselining methodology
- False positive reduction techniques
- Signal-to-noise optimization
- Threat hunting workflow design

### SOC Engineering Concepts
- SIEM dashboard architecture
- Suricata alert analysis and tuning
- Anomaly visualization techniques
- Network traffic categorization
- Telemetry interpretation

---

## Biggest Realization
A functional SOC dashboard is not about showing all traffic.
It is about reducing noise until suspicious behavior
becomes visible.

Filtering normal enterprise traffic — Microsoft telemetry,
standard web ports, known infrastructure — dramatically
improves the ability to identify:
- Unusual destination ports
- Suspicious outbound connections
- Scanning and reconnaissance behavior
- Beaconing and C2 callback patterns
- Potential data exfiltration activity

This is the core methodology of professional detection
engineering. Build the baseline. Filter the noise.
Surface the signal.

---

## Current Stack
- Raspberry Pi 5 8GB SOC server
- Elasticsearch + Kibana (SIEM)
- Suricata IDS
- Filebeat log shipping
- Alfa AWUS036ACS wireless monitor
- TP-Link TL-SG108E managed switch
- Kali Linux VM (attacker)
- Windows host system

---

## Skills Practiced
- KQL query development
- SIEM tuning and optimization
- False positive reduction
- Threat hunting methodology
- Detection engineering
- Dashboard architecture
- Suricata alert analysis
- Traffic baselining
- Anomaly detection design
- Investigative workflow development

---

## Day 8 Plan — Attack Simulation & Detection Validation
Now that the detection environment is tuned, validate it
against real attack traffic.

Planned simulations:
- Nmap port scanning and reconnaissance
- SSH brute force attempts
- Reverse shell traffic
- Beaconing simulation
- Suspicious PowerShell traffic
- DNS tunneling
- Fake malware C2 callbacks
- Data exfiltration tests

Goal: Generate realistic attack telemetry and confirm
that tuned dashboards and detection logic correctly
surface malicious behavior in real time.

This validation step transforms the platform from a
monitoring environment into a proven detection platform
with documented attack-to-detection evidence.
