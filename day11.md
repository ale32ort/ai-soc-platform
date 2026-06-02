# Day 11 - Attack Simulation & Detection Validation

## Overview

Day 11 focused on validating the SOC environment through a multi-stage attack simulation. Rather than building new infrastructure, the objective was to test existing detections, validate alert generation, and confirm visibility across multiple stages of the attack lifecycle.

The simulation covered Reconnaissance, Execution, Persistence, and Privilege Escalation techniques while generating alerts that were analyzed through Elastic SIEM dashboards and custom detection content.

---

## Activities Completed

### Reconnaissance Simulation

Performed network reconnaissance against the monitored Windows endpoint using Nmap.

Activities included:

* Host discovery
* Service discovery
* Open port enumeration

Open ports identified:

* TCP 135 (MSRPC)
* TCP 139 (NetBIOS-SSN)
* TCP 445 (SMB)

Reconnaissance activity generated network telemetry visible within the Threat Hunting Dashboard, SOC Dashboard, and Attack Chain Correlation Dashboard.

---

### Execution Validation

Simulated attacker execution activity through Windows Scheduled Task creation.

Detection validated:

* Suspicious Scheduled Task Creation

The alert was successfully generated and surfaced within Elastic Security.

---

### Persistence Validation

Simulated attacker persistence through Windows Registry Run Key modification.

MITRE ATT&CK:

* T1547.001 – Registry Run Keys / Startup Folder

Detection validated:

* Registry Run Key Persistence

The alert was generated and confirmed through Elastic Security during validation testing.

---

### Privilege Escalation Validation

Simulated privilege escalation through local account creation and administrative group membership modification.

Commands executed:

```powershell
net user labuser Password123! /add
net localgroup Administrators labuser /add
```

Detections validated:

* New Local User Created
* User Added to Administrator Group

Both alerts were successfully generated and correlated within the SOC environment.

---

## Detection Rules Validated

Successfully validated:

* Suspicious Scheduled Task Creation
* Malicious Service Creation Detection
* Registry Run Key Persistence
* New Local User Created
* User Added to Administrator Group

---

## Dashboards Validated

The following dashboards were tested and confirmed operational:

### SOC Dashboard

Validated:

* Alert visibility
* Severity distribution
* Host activity monitoring
* Security event monitoring

### Threat Hunting Dashboard

Validated:

* Network anomaly detection
* Beaconing visibility
* Suricata alert visibility
* Service discovery activity

### Attack Chain Correlation Dashboard

Validated:

* Alert correlation
* Attack timeline visibility
* Detection tracking
* Multi-stage attack visualization

### SOC Detection & Rule Monitoring Dashboard

Validated:

* Rule health monitoring
* Rule execution tracking
* Detection performance visibility

---

## MITRE ATT&CK Coverage

| Attack Phase         | Technique                          | MITRE ID  |
| -------------------- | ---------------------------------- | --------- |
| Reconnaissance       | Network Service Discovery          | T1046     |
| Execution            | Scheduled Task Creation            | T1053.005 |
| Execution            | Create or Modify System Process    | T1543.003 |
| Persistence          | Registry Run Keys / Startup Folder | T1547.001 |
| Privilege Escalation | Account Manipulation               | T1098     |

---

## Key Outcomes

* Successfully executed a multi-stage attack simulation.
* Validated multiple custom detection rules.
* Confirmed Elastic SIEM alert generation and correlation.
* Demonstrated end-to-end visibility from attacker activity to analyst investigation.
* Verified dashboard functionality across multiple SOC workflows.
* Produced investigation artifacts and attack documentation for portfolio review.

---

## Skills Demonstrated

* Elastic SIEM
* Detection Engineering
* Threat Hunting
* Windows Event Analysis
* Sysmon
* Suricata
* MITRE ATT&CK
* Security Monitoring
* Incident Analysis
* Attack Simulation
* Attack Chain Correlation

## Status

Day 11 marked the transition from SOC construction to operational validation, demonstrating the ability to detect, investigate, and analyze attacker activity across multiple stages of the intrusion lifecycle.
