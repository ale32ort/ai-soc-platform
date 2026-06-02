# Privilege Escalation Phase

## Objective

Simulate a privilege escalation event by creating a new local user account and adding that account to the local Administrators group. The objective was to generate Windows security events that would be ingested by Elastic SIEM and detected by custom detection rules.

## MITRE ATT&CK Mapping

* T1078 – Valid Accounts
* T1098 – Account Manipulation
* T1068 – Privilege Escalation

## Actions Performed

### 1. Baseline Collection

A baseline screenshot was captured before executing any privilege escalation activity to document the initial alert state within the environment.

### 2. Account Creation and Privilege Escalation

A new local user account was created and immediately added to the local Administrators group using Windows command-line utilities.

Commands executed:

```powershell
net user labuser Password123! /add
net localgroup Administrators labuser /add
```

### 3. Alert Generation

Elastic SIEM successfully detected the administrative group modification event and generated a high-severity alert associated with the privilege escalation activity.

### 4. Alert Validation

Alert details were reviewed to confirm the detection rule triggered correctly and correlated with the activity performed on the endpoint.

## Evidence Collected

### 00_Baseline_Before_PrivEsc.png

Baseline alert state before privilege escalation activity.

### 01_Account_Creation_And_Privilege_Escalation.png

Successful creation of a local user account and addition to the Administrators group.

### 02_User_Added_To_Admin_Group_Alert.png

Elastic SIEM alert generated from the administrative group membership modification event.

### 03_Alerts_After_PrivEsc.png

Alert dashboard showing the increased alert count following privilege escalation activity.

## Results

The privilege escalation simulation successfully generated Windows security telemetry and corresponding Elastic SIEM detections. The activity demonstrated the ability of the monitoring environment to identify administrative privilege assignment events and provide visibility into potentially malicious account manipulation techniques.

