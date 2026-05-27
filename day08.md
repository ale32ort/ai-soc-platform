# Day 8 — Endpoint Telemetry + Windows SIEM Integration

## Objective
Expand the SOC platform beyond network-layer visibility
into endpoint-layer detection by deploying Sysmon and
Winlogbeat on a Windows host and integrating live
endpoint telemetry into Elasticsearch and Kibana.

---

## Major Accomplishments

### 1. Deployed Sysmon on Windows Endpoint
Installed Sysmon using SwiftOnSecurity configuration —
the industry-standard Sysmon config used by SOC teams
worldwide.

Validated endpoint telemetry generation:
- Event ID 1 → Process Creation
- Event ID 3 → Network Connections
- Event ID 11 → File Creation

Confirmed advanced endpoint visibility functioning
correctly before forwarding into SIEM stack.

---

### 2. Installed and Configured Winlogbeat
Deployed Winlogbeat 9.4.1 on Windows host.

Configured to collect:
- Application logs
- System logs
- Security logs
- Sysmon Operational logs
- PowerShell logs

Configured output to Elasticsearch over HTTPS with
TLS authentication and credential management.

---

### 3. Diagnosed and Resolved Real Infrastructure Problems
Encountered and solved multiple production-level
troubleshooting scenarios:

Problems hit:
- Connection timeouts
- EOF errors on Elasticsearch connection
- Empty server reply errors
- TLS handshake failures
- Authentication failures
- YAML syntax errors
- PowerShell execution policy restrictions
- Windows file blocking restrictions

Diagnostic methodology used:
- Verified Elasticsearch service status before
  touching configuration
- Isolated network reachability using curl and
  Test-NetConnection separately from application issues
- Validated TLS separately from authentication
- Edited elasticsearch.yml: network.host and http.port
- Resolved PowerShell execution policy via
  Set-ExecutionPolicy
- Unblocked downloaded files causing script restrictions

Key lesson: Isolate each layer independently before
assuming the whole system is broken. The same
methodology applied on Day 3 with SSL — validate
what works before changing what might not.

---

### 4. Enabled Secure Endpoint-to-SIEM Communication
Configured full encrypted pipeline from Windows
endpoint to Elasticsearch:

- TLS connectivity established
- Authentication credentials configured
- SSL verification settings applied
- TLS handshake validated
- Elasticsearch authentication confirmed

Windows endpoint now communicates securely with the
Pi-based SIEM over the local network.

---

### 5. Installed Winlogbeat as Windows Service
Resolved all blocking issues and successfully:
- Installed Winlogbeat as persistent Windows service
- Started service and confirmed running state
- Validated service surviving system events

---

### 6. Verified Live Telemetry in Elasticsearch
Confirmed live ingestion of Windows endpoint data:
- DNS queries
- Network connection telemetry
- Endpoint process metadata
- Windows Security event logs
- Sysmon behavioral telemetry

---

### 7. Created Kibana Data View — winlogbeat-*
Created dedicated Kibana data view for endpoint data.

Verified:
- Live event ingestion visible in Discover
- Searchable telemetry across all fields
- Timestamp parsing correct
- Real-time endpoint activity visible

---

## What This Changes About the Lab

### Before Day 8 — Network-layer only
Suricata sees packets crossing the wire.
Detects: port scans, known signatures, protocol anomalies.
Blind to: what process made the connection, what it
created, what commands were run inside the machine.

### After Day 8 — Network + Endpoint
Sysmon sees inside the Windows machine.
Detects: process creation chains, network connections
by specific processes, file creation, registry changes,
PowerShell execution, credential access attempts.

Combined visibility now covers:
- Living-off-the-land attacks invisible to Suricata
- PowerShell abuse via Event ID 4104
- Process injection via unusual parent-child chains
- Lateral movement via unexpected process connections
- Credential dumping via LSASS access (Event ID 10)
- Persistence via registry modifications (Event ID 12/13)

---

## Detection Scenarios Now Unlocked

| Attack Technique | MITRE ATT&CK | Detection Source |
|-----------------|--------------|-----------------|
| PowerShell encoded commands | T1059.001 | Sysmon EID 4104 |
| Process injection | T1055 | Sysmon EID 1 |
| Unusual parent-child process | T1059 | Sysmon EID 1 |
| Unexpected network connection | T1071 | Sysmon EID 3 |
| Credential dumping (LSASS) | T1003 | Sysmon EID 10 |
| Registry persistence | T1547.001 | Sysmon EID 12/13 |
| Lateral movement | T1021 | Sysmon EID 3 |
| File creation by malware | T1105 | Sysmon EID 11 |

---

## Current Detection Stack — Three Layers

### Layer 1 — Wireless (Alfa AWUS036ACS)
- Monitor mode passive capture
- 802.11 frame visibility
- Probe request monitoring
- Wireless device tracking

### Layer 2 — Network (Suricata IDS)
- Packet-level traffic inspection
- Signature-based detection
- Protocol anomaly detection
- Alert generation to Elasticsearch

### Layer 3 — Endpoint (Sysmon + Winlogbeat) ← NEW
- Process creation and execution chains
- Network connections by process
- File system activity
- Registry modifications
- PowerShell logging
- Windows Security event forwarding

All three layers feed into single Elasticsearch backend.
All three visible in unified Kibana dashboard.

---

## Key Concepts Learned

### Detection Architecture
- Network visibility vs endpoint visibility — what each
  layer sees and what each layer misses
- Why endpoint telemetry catches living-off-the-land
  attacks that evade network IDS
- Sysmon event ID taxonomy and what each event means
- How process chains reveal attacker behavior

### SOC Engineering
- Multi-source SIEM ingestion pipeline design
- Winlogbeat module configuration and output routing
- TLS certificate management across Windows and Linux
- Elasticsearch network binding and access control
- PowerShell execution policy management in enterprise
  contexts

### Troubleshooting Methodology
- Layer isolation: validate each pipeline stage
  independently
- Test connectivity before testing authentication
- Test authentication before testing data flow
- Read error messages precisely — EOF vs timeout vs
  auth failure are fundamentally different problems

---

## Skills Practiced
- Sysmon deployment and configuration
- Winlogbeat installation and service management
- Elasticsearch connectivity troubleshooting
- TLS/HTTPS configuration across OS boundaries
- PowerShell execution policy management
- YAML configuration editing
- Windows event log analysis
- Multi-source SIEM ingestion
- Endpoint detection engineering concepts
- Cross-platform security tool integration

---

## Current Full Stack
- Raspberry Pi 5 8GB — SOC server
- Elasticsearch + Kibana — SIEM backend and visualization
- Suricata IDS — network layer detection
- Filebeat — Linux log shipping
- Zeek — network protocol analysis
- Alfa AWUS036ACS — wireless monitoring
- TP-Link TL-SG108E — managed switch with port mirroring
- Sysmon (SwiftOnSecurity config) — endpoint telemetry
- Winlogbeat — Windows log shipping
- Kali Linux VM — attack simulation
- Windows host — monitored endpoint

---

## Biggest Win
Added endpoint-layer visibility to a network-layer
SOC platform. The lab now sees both sides of an attack
simultaneously — the network connection Suricata detects
AND the process that initiated it Sysmon captures.

That combination is what enterprise SOC teams spend
significant budget achieving. Built on a Raspberry Pi
in one session.

---

## Day 9 Plan — Attack Simulation + Claude AI Triage
With endpoint visibility now operational:

Attack simulations planned:
- PowerShell encoded command execution
- Unusual process spawning chains
- Metasploit payload — watch full process chain
- Credential access simulation
- Persistence via registry modification
- Lateral movement detection

Claude AI triage engine:
- Python script polling Elasticsearch for alerts
- Sends Suricata + Sysmon alerts to Claude API
- Claude returns: verdict, explanation, ATT&CK mapping,
  response recommendation
- Flask dashboard displays AI triage in real time
- Full kill chain: attack → detection → AI analysis

Day 9 is when the lab becomes genuinely unique.
