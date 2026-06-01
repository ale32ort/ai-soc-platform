# Day 4 — Suricata Interface Diagnosis + Pipeline Validation

## Accomplishments
- Verified Filebeat indices inside Elasticsearch
- Confirmed filebeat, alert, observability, and security indices
- Accessed Kibana Discover with thousands of fields loaded
- Diagnosed "no results" problem despite indices existing
- Identified Suricata listening on wrong network interface
- Discovered traffic split across eth0 and wlan0
- Generated test traffic: Nmap scans, browser traffic,
  ping tests, HTTP requests
- Observed raw Suricata events via eve.json tail
- Validated complete end-to-end SOC pipeline

## Key Concepts Learned
- Complete SOC pipeline flow:
  Network Traffic → Suricata → eve.json →
  Filebeat → Elasticsearch → Kibana → Dashboard
- SIEM troubleshooting methodology: isolate each stage
  independently before assuming full failure
- Interface selection critical for IDS visibility
- Running does not equal healthy — validated at every layer
- eve.json structure and Suricata JSON output format
- How to isolate pipeline failures at each stage:
  capture, generation, ingestion, indexing, visualization

## Test Traffic Generated
- nmap 10.0.0.1
- Browser HTTP traffic
- ICMP ping tests
- DNS queries

## Biggest Win
Diagnosed why dashboards showed no data despite Elastic
working correctly. Fixed interface routing. Validated
complete pipeline end to end. Lab transitioned from
infrastructure setup into live defensive monitoring.

