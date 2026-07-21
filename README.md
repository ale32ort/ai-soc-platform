# 🛡️ AI-Assisted SOC Platform

> An autonomous security operations platform built on the Elastic Stack that continuously detects, investigates, and documents security alerts using AI.

---

## Overview

This project began as a Raspberry Pi 5–based SOC home lab and evolved into a production-inspired AI investigation platform that automates many of the repetitive tasks performed by security analysts during the early stages of incident response.

Instead of stopping at alert generation, the platform automatically:

- Detects security events using Elastic Security
- Collects related endpoint and network evidence
- Builds chronological investigation timelines
- Uses AI to analyze the collected evidence
- Produces structured investigation reports
- Stores completed investigations in Elasticsearch
- Continuously monitors for new detections through an autonomous Investigation Manager
- Safely resumes processing after restarts using persistent checkpoints

The project demonstrates practical skills across Security Operations (SOC), Detection Engineering, Incident Response, Threat Hunting, AI Engineering, and Security Automation.

---

## Architecture

https://github.com/ale32ort/ai-soc-platform/blob/main/docs/images/dac23bf5-b395-4505-8889-c5e7f88aa94a.png

# Why This Project?

Modern Security Operations Centers generate thousands of security alerts every day.

Analysts often spend significant time performing repetitive investigation tasks before they can determine whether an alert represents legitimate malicious activity.

Typical analyst workflow includes:

- Reviewing detection alerts
- Collecting surrounding endpoint telemetry
- Correlating related events
- Building investigation timelines
- Mapping activity to MITRE ATT&CK
- Assessing severity
- Writing investigation summaries

This platform automates much of that investigative workflow while preserving the analyst as the final decision maker.

Rather than replacing analysts, the goal is to reduce repetitive investigative work so analysts can spend more time making high-value security decisions.

---

# Key Capabilities

## Autonomous Investigation Manager

A continuously running service that monitors Elastic Security detections and automatically launches investigations for eligible alerts.

Features include:

- Continuous polling
- Incremental alert retrieval
- Persistent checkpoint recovery
- Duplicate investigation prevention
- Graceful shutdown and restart support

---

## AI Investigation Engine

Automatically performs structured investigations using a pluggable Large Language Model (LLM) architecture.

Current implementation:

- Anthropic Claude

Future providers can be added without changing investigation logic.

---

## Related Evidence Collection

Automatically gathers contextual endpoint telemetry surrounding the original detection including:

- Process creation
- Parent-child relationships
- Service creation
- User activity
- Additional correlated Windows events

---

## Timeline Construction

Builds chronological investigation timelines from collected evidence, making analyst review significantly faster.

---

## Investigation Persistence

Completed investigations are stored back into Elasticsearch where they can be searched, visualized, and correlated with future incidents.

---

## Multi-Sensor Security Monitoring

The platform combines telemetry from multiple detection layers:

### Layer 1 — Wireless Monitoring

- Alfa AWUS036ACS
- Passive 802.11 monitoring
- Wireless device discovery

### Layer 2 — Network Detection

- Suricata IDS
- Zeek
- SPAN Port Monitoring
- Network Intrusion Detection

### Layer 3 — Endpoint Detection

- Sysmon
- Windows Security Auditing
- Winlogbeat
- Elastic Security

---

# Investigation Pipeline

```text
Windows Endpoint / Network

            │

            ▼

Elastic Security Detection

            │

            ▼

Investigation Manager

            │

            ▼

Alert Monitor

            │

            ▼

Deduplicator

            │

            ▼

Investigation Case

            │

            ▼

Related Event Collection

            │

            ▼

Timeline Builder

            │

            ▼

AI Investigation Engine

            │

            ▼

Structured Investigation Report

            │

            ▼

Elasticsearch

            │

            ▼

Kibana Dashboard
```

---

# Technology Stack

## SIEM & Security Monitoring

- Elasticsearch
- Kibana
- Elastic Security
- Splunk

## Network Security

- Suricata
- Zeek
- Filebeat

## Endpoint Detection

- Sysmon
- Winlogbeat
- Windows Advanced Auditing

## AI & Automation

- Python
- Anthropic Claude
- Modular LLM Provider Architecture
- Investigation Manager
- Telegram Bot API

## Infrastructure

- Raspberry Pi 5
- Windows Endpoint
- Kali Linux
- Managed Switch (SPAN Port Mirroring)

---

# Repository Structure

```
clients/
```

External integrations including Elasticsearch.

```
models/
```

Shared investigation models.

```
services/
```

Long-running services including the autonomous Investigation Manager.

```
tools/
```

Evidence collection, AI investigation, persistence, timeline generation, and provider implementations.

```
tests/
```

Unit and integration tests.

---

# Key Skills Demonstrated

- Security Operations (SOC)
- Detection Engineering
- Threat Hunting
- Incident Response
- AI Engineering
- LLM Integration
- Security Automation
- Elastic Security
- Elasticsearch
- Splunk Integration
- MITRE ATT&CK Mapping
- Timeline Construction
- Endpoint Detection & Response (EDR)
- Network Security Monitoring
- Python Development
- Software Architecture
- Investigation Orchestration

---

# Roadmap

## Completed

- ✅ Elastic Security Integration
- ✅ Multi-Sensor Telemetry Collection
- ✅ AI Investigation Engine
- ✅ Related Event Collection
- ✅ Timeline Construction
- ✅ Investigation Persistence
- ✅ Autonomous Investigation Manager
- ✅ Persistent Checkpoint Recovery
- ✅ Pluggable LLM Provider Architecture

## Planned

- ⏳ Multi-alert correlation
- ⏳ Threat Intelligence enrichment
- ⏳ VirusTotal integration
- ⏳ MITRE ATT&CK scoring improvements
- ⏳ Investigation dashboard
- ⏳ Analyst feedback loop
- ⏳ Agentic investigation workflows

---

# Lessons Learned

Building this platform reinforced several important software engineering and security engineering principles:

- Design AI systems as modular components rather than tightly coupled pipelines.
- Separate orchestration, investigation, and persistence into independent services.
- Use checkpoints and idempotent processing to build resilient long-running automation.
- Treat AI as an investigation assistant rather than a replacement for analyst judgment.
- Build security tooling that emphasizes transparency, repeatability, and maintainability.

---

# License

This project is intended for educational, research, and portfolio purposes.
