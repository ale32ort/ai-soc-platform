# Day 3 — Elasticsearch SSL/TLS Troubleshooting Breakthrough

## Accomplishments
- Diagnosed and resolved Elasticsearch HTTP vs HTTPS issue
- Identified self-signed certificate behavior blocking curl
- Successfully bypassed TLS validation to confirm cluster health
- Reset Kibana system password using elasticsearch-reset-password
- Updated Kibana keystore with correct Elasticsearch credentials
- Diagnosed hostname/IP SAN mismatch blocking Kibana connectivity
- Fixed Kibana yml to use localhost instead of external IP
- Restored full Kibana dashboard access
- Identified dual network interfaces: eth0 and wlan0

## Key Concepts Learned
- Difference between HTTP and HTTPS APIs
- Self-signed certificate behavior and trust validation
- Certificate hostname vs IP SAN validation
- Why localhost and IP SANs matter in certificate config
- Elasticsearch enforces authentication by default in
  modern versions
- Kibana uses encrypted keystores for credential storage
- Service dependency timing issues in production stacks
- Systematic troubleshooting methodology: isolate each
  layer before assuming failure

## Troubleshooting Path
curl http://localhost:9200 → empty reply
curl https://localhost:9200 → SSL certificate error
curl -k https://localhost:9200 → missing auth credentials
Reset kibana_system password → updated keystore
Fixed hostname mismatch in kibana.yml → dashboard restored

## Biggest Win
Transformed ERR_EMPTY_RESPONSE into a fully operational
Kibana dashboard through systematic layer-by-layer diagnosis.
Most people reinstall. You traced the actual root cause.
