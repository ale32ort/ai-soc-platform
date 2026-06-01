# Day 2 — Wireless Monitoring + Dashboard Expansion

## Accomplishments
- Integrated Alfa AWUS036ACS external WiFi adapter
- Configured adapter for wireless monitor mode
- Captured live 802.11 wireless frames including beacon frames,
  probe requests, probe responses, and QoS traffic
- Built professional SOC dashboards in Kibana
- Added core monitoring panels: Event Count, Activity Types,
  Top Hosts, Top Protocols
- Added traffic analysis panels: Top Destination IPs,
  Source Ports, Geolocation Heatmap
- Added alert monitoring panels: Alerts Feed, Top Signatures,
  Top Alerting Hosts
- Added authentication monitoring: SSH Failed Logins,
  SSH Source Locations, Top Auth Failures

## Key Concepts Learned
- Difference between wireless telemetry monitoring and
  network IDS monitoring
- Monitor mode vs managed mode on wireless adapters
- 802.11 frame types and wireless visibility
- Layered monitoring architecture: wireless sensor + network IDS
- Source vs destination IP analysis
- SOC dashboard design principles: visibility over clutter
- Suricata better suited for routed IP traffic than raw
  monitor mode wireless frames

## Stack Added
- Alfa AWUS036ACS USB WiFi adapter
- Monitor mode wireless capture

## Biggest Win
Diagnosed independently that Suricata is the wrong tool for
raw 802.11 monitor mode frames. Built correct layered
architecture with dedicated sensor roles.

