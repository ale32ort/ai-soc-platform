#!/usr/bin/env python3
"""
AI-Assisted SOC Triage Engine — Production Hardened
=====================================================
Architecture:
  Suricata / Sysmon / Winlogbeat
        -> Elasticsearch
        -> Python AI Triage Engine  (this file)
        -> Claude API
        -> Elasticsearch soc-triage-results
        -> Splunk HEC ai-soc index
        -> Optional Telegram (HIGH / CRITICAL only)

Upgrades in this version:
  - Splunk retry queue  (splunk_retry_queue.jsonl)
  - Claude pre-filtering / cost controls
  - Claude response caching  (claude_cache.json, 24-hour TTL)
  - Risk scoring  (0-100)
  - Executive summary field
  - Safer deduplication  (mark seen only after full success)
  - Configurable settings via .env
  - Improved structured logging

Usage:
  python3 triage_engine.py           # Normal polling mode
  python3 triage_engine.py --test    # Test Splunk, risk score, fields -- no Claude
"""

import os
import sys
import json
import time
import logging
import argparse
import hashlib
import requests
import urllib3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
import anthropic

urllib3.disable_warnings()
load_dotenv()

# -------------------------------------------------
# LOGGING
# -------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

# -------------------------------------------------
# ENVIRONMENT -- all settings configurable via .env
# -------------------------------------------------
ANTHROPIC_KEY       = os.getenv("ANTHROPIC_API_KEY")
ELASTIC_URL         = os.getenv("ELASTIC_URL",         "https://localhost:9200")
ELASTIC_USER        = os.getenv("ELASTIC_USER",        "elastic")
ELASTIC_PASS        = os.getenv("ELASTIC_PASSWORD")
SPLUNK_HEC_URL      = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN    = os.getenv("SPLUNK_HEC_TOKEN")
SPLUNK_INDEX        = os.getenv("SPLUNK_INDEX",         "ai-soc")
TELEGRAM_BOT_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID    = os.getenv("TELEGRAM_CHAT_ID")

POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL",       "60"))
TRIAGE_INDEX        = os.getenv("TRIAGE_INDEX",            "soc-triage-results")
SEEN_INDEX          = os.getenv("SEEN_INDEX",              "soc-triage-seen")
SKIPPED_INDEX       = os.getenv("SOC_SKIPPED_INDEX",       "soc-triage-skipped")
SPLUNK_RETRY_FILE   = Path(os.getenv("SPLUNK_RETRY_QUEUE", "splunk_retry_queue.jsonl"))
CLAUDE_CACHE_FILE   = Path(os.getenv("CLAUDE_CACHE_FILE",  "claude_cache.json"))
CLAUDE_CACHE_TTL    = int(os.getenv("CLAUDE_CACHE_TTL_HOURS", "24"))
PIPELINE_VERSION    = os.getenv("PIPELINE_VERSION",        "1.0.0")

# Windows Event IDs worth triaging
ALLOWED_WIN_EVENTS  = {"4625", "4688", "4698", "4720", "4732", "7045"}

# Severities that trigger Telegram notifications
TELEGRAM_THRESHOLD  = {"CRITICAL", "HIGH"}

# -------------------------------------------------
# CLIENTS
# -------------------------------------------------
es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(ELASTIC_USER, ELASTIC_PASS),
    verify_certs=False,
    ssl_show_warn=False
)
claude_client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)


# =================================================
# CLAUDE RESPONSE CACHE
# =================================================

def _load_cache():
    if CLAUDE_CACHE_FILE.exists():
        try:
            return json.loads(CLAUDE_CACHE_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_cache(cache):
    try:
        CLAUDE_CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except Exception as e:
        log.warning(f"Cache write failed: {e}")


def _cache_key(alert):
    src = alert.get("_source", {})
    mod = src.get("event", {}).get("module", "unknown")
    if mod == "suricata":
        sig = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "")
        raw = f"suricata:{sig}"
    else:
        code   = src.get("event", {}).get("code", "")
        action = src.get("event", {}).get("action", "")
        raw    = f"windows:{code}:{action}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_cached_response(alert):
    cache = _load_cache()
    key   = _cache_key(alert)
    entry = cache.get(key)
    if not entry:
        return None
    cached_at = datetime.fromisoformat(entry["cached_at"])
    if datetime.now(timezone.utc) - cached_at > timedelta(hours=CLAUDE_CACHE_TTL):
        log.info(f"Cache expired for key {key[:12]}...")
        return None
    log.info(f"Cache HIT for key {key[:12]}... -- reusing previous Claude analysis")
    return entry["response"]


def store_cached_response(alert, response):
    cache = _load_cache()
    key   = _cache_key(alert)
    cache[key] = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "response":  response
    }
    _save_cache(cache)


# =================================================
# SPLUNK RETRY QUEUE
# =================================================

def _queue_for_retry(payload):
    try:
        with SPLUNK_RETRY_FILE.open("a") as f:
            f.write(json.dumps(payload) + "\n")
        log.warning(f"Splunk retry queue: saved event {payload.get('event',{}).get('original_alert_id','?')[:16]}...")
    except Exception as e:
        log.error(f"Failed to write to retry queue: {e}")


def _send_raw_to_splunk(payload):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return False
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type":  "application/json"
    }
    try:
        resp = requests.post(
            SPLUNK_HEC_URL, json=payload, headers=headers,
            timeout=10, verify=False
        )
        if resp.status_code == 200:
            return True
        log.error(f"Splunk HEC HTTP {resp.status_code}: {resp.text[:200]}")
        return False
    except requests.exceptions.ConnectionError:
        log.error("Splunk HEC: connection refused")
        return False
    except requests.exceptions.Timeout:
        log.error("Splunk HEC: request timed out")
        return False
    except Exception as e:
        log.error(f"Splunk HEC unexpected error: {e}")
        return False


def flush_retry_queue():
    if not SPLUNK_RETRY_FILE.exists():
        return
    lines = SPLUNK_RETRY_FILE.read_text().splitlines()
    if not lines:
        return
    log.info(f"Splunk retry queue: attempting {len(lines)} queued event(s)")
    remaining = []
    success   = 0
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _send_raw_to_splunk(payload):
            success += 1
            log.info(f"Splunk retry: resent {payload.get('event',{}).get('original_alert_id','?')[:16]}... ok")
        else:
            remaining.append(line)
    SPLUNK_RETRY_FILE.write_text("\n".join(remaining) + ("\n" if remaining else ""))
    log.info(f"Splunk retry queue: {success} sent, {len(remaining)} still pending")


def send_to_splunk(result):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        log.warning("Splunk HEC not configured -- skipping forward")
        return False

    payload = {
        "time":       time.time(),
        "host":       result.get("host", "soc-pi"),
        "source":     "ai-soc-triage-engine",
        "sourcetype": "ai_soc_verdict",
        "index":      SPLUNK_INDEX,
        "event": {
            "original_alert_id":         result.get("original_alert_id"),
            "timestamp":                 result.get("timestamp"),
            "source_index":              result.get("source_index"),
            "host":                      result.get("host"),
            "source_ip":                 result.get("source_ip"),
            "destination_ip":            result.get("destination_ip"),
            "alert_name":                result.get("alert_name"),
            "raw_alert_summary":         result.get("raw_alert_summary"),
            "ai_summary":                result.get("ai_summary"),
            "ai_severity":               result.get("ai_severity"),
            "ai_verdict":                result.get("ai_verdict"),
            "mitre_technique":           result.get("mitre_technique"),
            "recommended_action":        result.get("recommended_action"),
            "false_positive_likelihood": result.get("false_positive_likelihood"),
            "confidence":                result.get("confidence"),
            "mitre_tactic":              result.get("mitre_tactic"),
            "risk_score":                result.get("risk_score", 0),
            "executive_summary":         result.get("executive_summary", ""),
            "pipeline_version":          result.get("pipeline_version", PIPELINE_VERSION),
        }
    }

    if _send_raw_to_splunk(payload):
        log.info(f"Splunk HEC: forwarded {result.get('original_alert_id','?')[:16]}... ok")
        return True

    _queue_for_retry(payload)
    return False


# =================================================
# TELEGRAM
# =================================================

def send_telegram_alert(result):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    severity = result.get("ai_severity", "UNKNOWN")
    if severity not in TELEGRAM_THRESHOLD:
        return

    verdict   = result.get("ai_verdict", "UNKNOWN")
    alert     = result.get("alert_name", "Unknown")
    technique = result.get("mitre_technique", "Unknown")
    summary   = result.get("executive_summary") or result.get("ai_summary", "")
    action    = result.get("recommended_action", "")
    src_ip    = result.get("source_ip", "unknown")
    host      = result.get("host", "unknown")
    score     = result.get("risk_score", 0)
    emoji     = "🔴" if severity == "CRITICAL" else "🟠"

    message = (
        f"{emoji} *AI SOC -- {severity}* (Risk: {score}/100)\n\n"
        f"*Verdict:* {verdict}\n"
        f"*Alert:* {alert}\n"
        f"*Host:* {host}  |  *Src IP:* {src_ip}\n"
        f"*MITRE:* {technique}\n\n"
        f"*Summary:* {summary}\n\n"
        f"*Action:* {action}"
    )

    url     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            log.info(f"Telegram: alert sent ({severity})")
        else:
            log.warning(f"Telegram error {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        log.warning(f"Telegram send failed: {e}")


# =================================================
# RISK SCORING  (0-100)
# =================================================

def calculate_risk_score(result):
    score = 0

    score += {
        "CRITICAL":      35,
        "HIGH":          25,
        "MEDIUM":        15,
        "LOW":           5,
        "INFORMATIONAL": 0,
    }.get(result.get("ai_severity", ""), 0)

    score += {
        "TRUE_POSITIVE":       25,
        "NEEDS_INVESTIGATION": 15,
        "FALSE_POSITIVE":      0,
    }.get(result.get("ai_verdict", ""), 0)

    score += {
        "HIGH":   15,
        "MEDIUM": 8,
        "LOW":    3,
    }.get(result.get("confidence", ""), 0)

    score += {
        "LOW":    10,
        "MEDIUM": 5,
        "HIGH":   0,
    }.get(result.get("false_positive_likelihood", ""), 0)

    HIGH_VALUE_TECHNIQUES = {
        "T1003", "T1055", "T1059", "T1078",
        "T1110", "T1547", "T1543", "T1053",
    }
    technique_id = result.get("mitre_technique_id", "")
    if any(technique_id.startswith(t) for t in HIGH_VALUE_TECHNIQUES):
        score += 10

    if result.get("source_index", "").startswith("winlogbeat"):
        score += 5

    return min(score, 100)


# =================================================
# EXECUTIVE SUMMARY
# =================================================

def build_executive_summary(result):
    verdict   = result.get("ai_verdict", "UNKNOWN")
    severity  = result.get("ai_severity", "UNKNOWN")
    alert     = result.get("alert_name", "unknown activity")
    host      = result.get("host", "unknown host")
    src_ip    = result.get("source_ip", "unknown source")
    technique = result.get("mitre_technique_name", "unknown technique")
    score     = result.get("risk_score", 0)

    if verdict == "TRUE_POSITIVE":
        return (
            f"{severity} confirmed threat: {alert} detected on {host} "
            f"from {src_ip} via {technique} -- risk score {score}/100."
        )
    elif verdict == "FALSE_POSITIVE":
        return (
            f"False positive: {alert} on {host} was reviewed and "
            f"determined to be benign -- risk score {score}/100."
        )
    else:
        return (
            f"Needs investigation: {alert} on {host} from {src_ip} "
            f"requires analyst review -- risk score {score}/100."
        )


# =================================================
# ELASTICSEARCH HELPERS
# =================================================

def ensure_indices():
    for idx in [TRIAGE_INDEX, SEEN_INDEX, SKIPPED_INDEX]:
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx)
            log.info(f"Created Elasticsearch index: {idx}")


def already_triaged(alert_id):
    try:
        es.get(index=SEEN_INDEX, id=alert_id)
        return True
    except Exception:
        return False


def already_skipped(alert_id):
    try:
        es.get(index=SKIPPED_INDEX, id=alert_id)
        return True
    except Exception:
        return False


def mark_triaged(alert_id):
    es.index(
        index=SEEN_INDEX,
        id=alert_id,
        document={"triaged_at": datetime.now(timezone.utc).isoformat()}
    )


def write_skipped_alert(alert, skip_reason):
    """
    Write a lightweight record to soc-triage-skipped.
    Kept separate from soc-triage-seen so skipped alerts
    can be audited and reviewed independently.
    """
    src        = alert.get("_source", {})
    mod        = src.get("event", {}).get("module", "unknown")
    alert_name = (
        src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "")
        if mod == "suricata"
        else f"Windows Event {src.get('event', {}).get('code', 'unknown')}"
    )
    src_ip   = src.get("source", {}).get("ip", "unknown")
    dst_ip   = src.get("destination", {}).get("ip", "unknown")
    dst_port = src.get("destination", {}).get("port", "unknown")
    host     = src.get("host", {}).get("name", "unknown")

    if mod == "suricata":
        raw_summary = f"{alert_name} | {src_ip} -> {dst_ip}:{dst_port}"
    else:
        user        = src.get("user", {}).get("name", "unknown")
        proc        = src.get("process", {}).get("name", "")
        raw_summary = f"{alert_name} | Host: {host} | User: {user} | Process: {proc}"

    doc = {
        "original_alert_id": alert["_id"],
        "skipped_at":        datetime.now(timezone.utc).isoformat(),
        "source_index":      alert.get("_index", "unknown"),
        "host":              host,
        "alert_name":        alert_name,
        "skip_reason":       skip_reason,
        "raw_alert_summary": raw_summary,
        "pipeline_version":  PIPELINE_VERSION,
    }

    try:
        es.index(index=SKIPPED_INDEX, id=alert["_id"], document=doc)
        log.info(f"Skipped alert recorded: {alert['_id'][:16]}... | {skip_reason}")
    except Exception as e:
        log.warning(f"Failed to write skipped alert to ES: {e}")


# =================================================
# COST CONTROL -- PRE-FILTERING
# =================================================

def should_triage(alert):
    """
    Return (True, "") if the alert is worth sending to Claude.
    Return (False, reason) for noisy or low-value events.
    The reason string is written to soc-triage-skipped for audit.
    """
    src = alert.get("_source", {})
    mod = src.get("event", {}).get("module", "unknown")

    if mod == "suricata":
        sig      = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "")
        severity = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("severity")

        if not sig:
            return False, "No Suricata signature present"

        NOISY_PREFIXES = (
            "SURICATA DHCP",
            "SURICATA ARP",
            "SURICATA Parser",
            "SURICATA STREAM",
            "GPL MISC",
        )
        for prefix in NOISY_PREFIXES:
            if sig.startswith(prefix):
                return False, f"Noisy Suricata signature: {prefix}"

        if severity is not None:
            try:
                if int(severity) > 2:
                    return False, f"Low Suricata severity ({severity}) below threshold"
            except (ValueError, TypeError):
                pass

        return True, ""

    else:
        code = str(src.get("event", {}).get("code", ""))
        if code not in ALLOWED_WIN_EVENTS:
            return False, f"Windows Event {code} not in allowed list"
        return True, ""


# =================================================
# ALERT FETCHING
# =================================================

def fetch_new_alerts():
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    queries = [
        {
            "index": ".alerts-security.alerts-default",
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}}
                    ],
                    "must_not": [
                        {"term": {"kibana.alert.workflow_status": "closed"}}
                    ]
                }
            }
        }
    ]

    alerts = []
    for q in queries:
        try:
            res = es.search(
                index=q["index"],
                query=q["query"],
                size=50,
                sort=[{"@timestamp": "desc"}]
            )
            for hit in res["hits"]["hits"]:
                if not already_triaged(hit["_id"]):
                    alerts.append(hit)
        except Exception as e:
            log.warning(f"ES query failed on {q['index']}: {e}")

    return alerts

# =================================================
# PROMPT BUILDER
# =================================================

def build_prompt(alert):
    src  = alert.get("_source", {})
    ts   = src.get("@timestamp", "unknown")
    mod  = src.get("event", {}).get("module", "unknown")

    if "kibana.alert.rule.name" in src:
        rule_name = src.get("kibana.alert.rule.name", "Unknown")
        severity = src.get("kibana.alert.severity", "Unknown")
        risk = src.get("kibana.alert.risk_score", "Unknown")
        reason = src.get("kibana.alert.reason", "Unknown")
        description = src.get("kibana.alert.rule.description", "Unknown")
        host = src.get("host", {}).get("name", "unknown")
        user = src.get("user", {}).get("name", "unknown")
        src_ip = src.get("source", {}).get("ip", "unknown")
        event_code = src.get("event", {}).get("code", "unknown")

        context = (
            f"ALERT TYPE: Elastic Security Detection\n"
            f"RULE NAME: {rule_name}\n"
            f"ELASTIC SEVERITY: {severity}\n"
            f"ELASTIC RISK SCORE: {risk}\n"
            f"ALERT REASON: {reason}\n"
            f"RULE DESCRIPTION: {description}\n"
            f"HOST: {host}\n"
            f"USER: {user}\n"
            f"SOURCE IP: {src_ip}\n"
            f"ORIGINAL EVENT CODE: {event_code}\n"
            f"TIMESTAMP: {ts}"
        )

    elif mod == "suricata":
        sig      = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "unknown")
        severity = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("severity", "unknown")
        src_ip   = src.get("source", {}).get("ip", "unknown")
        dst_ip   = src.get("destination", {}).get("ip", "unknown")
        dst_port = src.get("destination", {}).get("port", "unknown")
        proto    = src.get("network", {}).get("transport", "unknown")
        context  = (
            f"ALERT TYPE: Suricata Network IDS\n"
            f"SIGNATURE: {sig}\nSEVERITY: {severity}\n"
            f"SOURCE IP: {src_ip}\nDESTINATION IP: {dst_ip}\n"
            f"DESTINATION PORT: {dst_port}\nPROTOCOL: {proto}\n"
            f"TIMESTAMP: {ts}"
        )
    else:
        code       = src.get("event", {}).get("code", "unknown")
        evt_action = src.get("event", {}).get("action", "unknown")
        host       = src.get("host", {}).get("name", "unknown")
        user       = src.get("user", {}).get("name", "unknown")
        proc       = src.get("process", {}).get("name", "")
        cmdline    = src.get("process", {}).get("command_line", "")
        task       = src.get("winlog", {}).get("event_data", {}).get("TaskName", "")
        context    = (
            f"ALERT TYPE: Windows Security Event\n"
            f"EVENT CODE: {code}\nEVENT ACTION: {evt_action}\n"
            f"HOST: {host}\nUSER: {user}\nPROCESS: {proc}\n"
            f"COMMAND LINE: {cmdline[:300] if cmdline else 'N/A'}\n"
            f"SCHEDULED TASK: {task if task else 'N/A'}\n"
            f"TIMESTAMP: {ts}"
        )

    return f"""You are an expert SOC analyst. Analyze this alert and respond ONLY with valid JSON -- no markdown, no preamble.

ALERT CONTEXT:
{context}

Respond with this exact JSON structure:
{{
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NEEDS_INVESTIGATION",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "INFORMATIONAL",
  "threat_explanation": "2-3 sentence plain English explanation.",
  "mitre_tactic": "ATT&CK tactic name",
  "mitre_technique_id": "T1XXX.XXX",
  "mitre_technique_name": "Technique name",
  "recommended_action": "1-2 sentence analyst response.",
  "false_positive_likelihood": "HIGH" or "MEDIUM" or "LOW",
  "false_positive_reason": "Reason if FALSE_POSITIVE, else empty string."
}}"""


# =================================================
# TRIAGE -- CLAUDE API (with cache)
# =================================================

def triage_alert(alert):
    src = alert.get("_source", {})
    mod = src.get("event", {}).get("module", "unknown")

    if mod == "suricata":
        alert_name  = src.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "Suricata Alert")
        src_ip      = src.get("source", {}).get("ip", "unknown")
        dst_ip      = src.get("destination", {}).get("ip", "unknown")
        dst_port    = src.get("destination", {}).get("port", "unknown")
        host        = src.get("host", {}).get("name", "unknown")
        raw_summary = f"{alert_name} | {src_ip} -> {dst_ip}:{dst_port}"
    else:
        code        = src.get("event", {}).get("code", "unknown")
        alert_name  = f"Windows Event {code}"
        src_ip      = src.get("source", {}).get("ip", "unknown")
        dst_ip      = src.get("destination", {}).get("ip", "unknown")
        host        = src.get("host", {}).get("name", "unknown")
        user        = src.get("user", {}).get("name", "unknown")
        proc        = src.get("process", {}).get("name", "")
        raw_summary = f"Event {code} | Host: {host} | User: {user} | Process: {proc}"

    cached = get_cached_response(alert)
    if cached:
        ai_result = cached
    else:
        prompt = build_prompt(alert)
        try:
            msg = claude_client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            raw       = msg.content[0].text.strip()
            ai_result = json.loads(raw)
            store_cached_response(alert, ai_result)
        except json.JSONDecodeError as e:
            log.error(f"Claude returned invalid JSON: {e}")
            return None
        except Exception as e:
            log.error(f"Claude API error: {e}")
            return None

    now    = datetime.now(timezone.utc).isoformat()
    result = dict(ai_result)
    result["original_alert_id"]  = alert["_id"]
    result["source_index"]       = alert.get("_index", "unknown")
    result["timestamp"]          = now
    result["alert_timestamp"]    = src.get("@timestamp", "")
    result["host"]               = host
    result["source_ip"]          = src_ip
    result["destination_ip"]     = dst_ip
    result["alert_name"]         = alert_name
    result["raw_alert_summary"]  = raw_summary
    result["ai_summary"]         = ai_result.get("threat_explanation", "")
    result["ai_severity"]        = ai_result.get("severity", "UNKNOWN")
    result["ai_verdict"]         = ai_result.get("verdict", "UNKNOWN")
    result["mitre_technique"]    = (
        f"{ai_result.get('mitre_technique_id','')} -- "
        f"{ai_result.get('mitre_technique_name','')}"
    )
    result["alert_source_raw"]   = src
    result["risk_score"]         = calculate_risk_score(result)
    result["executive_summary"]  = build_executive_summary(result)
    result["pipeline_version"]   = PIPELINE_VERSION

    return result


# =================================================
# TEST MODE
# =================================================

def run_test_mode():
    log.info("=" * 60)
    log.info("TEST MODE -- no Claude API calls")
    log.info("=" * 60)

    sample_ai = {
        "verdict":                   "TRUE_POSITIVE",
        "confidence":                "HIGH",
        "severity":                  "HIGH",
        "threat_explanation":        "An Nmap SYN scan was detected from an internal host targeting the SOC server. This reconnaissance activity suggests an attacker mapping open services prior to exploitation.",
        "mitre_tactic":              "Discovery",
        "mitre_technique_id":        "T1046",
        "mitre_technique_name":      "Network Service Discovery",
        "recommended_action":        "Investigate source host 192.168.1.100 for unauthorized tooling. Review recent user logins and running processes.",
        "false_positive_likelihood": "LOW",
        "false_positive_reason":     ""
    }

    result = dict(sample_ai)
    result["original_alert_id"] = "test-alert-000001"
    result["source_index"]      = "filebeat-test"
    result["timestamp"]         = datetime.now(timezone.utc).isoformat()
    result["alert_timestamp"]   = datetime.now(timezone.utc).isoformat()
    result["host"]              = "soclab"
    result["source_ip"]         = "192.168.1.100"
    result["destination_ip"]    = "10.0.0.50"
    result["alert_name"]        = "ET SCAN Nmap Scripting Engine User-Agent Detected"
    result["raw_alert_summary"] = "ET SCAN Nmap | 192.168.1.100 -> 10.0.0.50:22"
    result["ai_summary"]        = sample_ai["threat_explanation"]
    result["ai_severity"]       = sample_ai["severity"]
    result["ai_verdict"]        = sample_ai["verdict"]
    result["mitre_technique"]   = f"{sample_ai['mitre_technique_id']} -- {sample_ai['mitre_technique_name']}"
    result["alert_source_raw"]  = {}
    result["risk_score"]        = calculate_risk_score(result)
    result["executive_summary"] = build_executive_summary(result)
    result["pipeline_version"]  = PIPELINE_VERSION

    REQUIRED_FIELDS = [
        "original_alert_id", "timestamp", "source_index", "host",
        "source_ip", "destination_ip", "alert_name", "raw_alert_summary",
        "ai_summary", "ai_severity", "ai_verdict", "mitre_technique",
        "recommended_action", "false_positive_likelihood",
        "risk_score", "executive_summary", "pipeline_version"
    ]

    log.info("Field validation:")
    all_ok = True
    for field in REQUIRED_FIELDS:
        val    = result.get(field, "MISSING")
        status = "ok" if val and val != "MISSING" else "MISSING"
        if status == "MISSING":
            all_ok = False
        log.info(f"  [{status}]  {field}: {str(val)[:80]}")

    log.info(f"Risk score:        {result['risk_score']}/100")
    log.info(f"Executive summary: {result['executive_summary']}")

    if SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN:
        log.info("Testing Splunk HEC...")
        success = send_to_splunk(result)
        if success:
            log.info(f"TEST PASSED -- event delivered to Splunk index={SPLUNK_INDEX}")
            log.info(f"Verify: index=\"{SPLUNK_INDEX}\" source=\"ai-soc-triage-engine\"")
        else:
            log.error("TEST FAILED -- check SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN")
            all_ok = False
    else:
        log.warning("Splunk not configured -- HEC test skipped")

    if all_ok:
        log.info("TEST PASSED -- all fields present, risk score computed, executive summary generated")
    else:
        log.error("TEST FAILED -- see errors above")

    log.info("Test mode complete.")


# =================================================
# MAIN LOOP
# =================================================

def run():
    ensure_indices()
    log.info("=" * 60)
    log.info("AI SOC Triage Engine -- Production Mode")
    log.info(f"Pipeline version: {PIPELINE_VERSION}")
    log.info(f"Elasticsearch:   {ELASTIC_URL}")
    log.info(f"Triage index:    {TRIAGE_INDEX}")
    log.info(f"Seen index:      {SEEN_INDEX}")
    log.info(f"Skipped index:   {SKIPPED_INDEX}")
    log.info(f"Poll interval:   {POLL_INTERVAL}s")
    log.info(f"Splunk HEC:      {'configured' if SPLUNK_HEC_URL else 'NOT configured'}")
    log.info(f"Splunk index:    {SPLUNK_INDEX}")
    log.info(f"Retry queue:     {SPLUNK_RETRY_FILE}")
    log.info(f"Claude cache:    {CLAUDE_CACHE_FILE} (TTL {CLAUDE_CACHE_TTL}h)")
    log.info(f"Telegram:        {'configured' if TELEGRAM_BOT_TOKEN else 'NOT configured'}")
    log.info("=" * 60)

    while True:
        try:
            flush_retry_queue()

            alerts = fetch_new_alerts()
            log.info(f"Poll cycle: {len(alerts)} untriaged alert(s) found")

            for alert in alerts:
                alert_id = alert["_id"]

                # Skip alerts already processed or already recorded as skipped
                if already_skipped(alert_id):
                    continue

                triage_ok, skip_reason = should_triage(alert)
                if not triage_ok:
                    write_skipped_alert(alert, skip_reason)
                    continue

                log.info(f"Triaging {alert_id[:16]}...")

                result = triage_alert(alert)
                if not result:
                    log.warning(f"Triage failed for {alert_id[:16]} -- not marking as seen")
                    continue

                log.info(
                    f"  Verdict: {result['ai_verdict']} | "
                    f"Severity: {result['ai_severity']} | "
                    f"Risk: {result['risk_score']}/100 | "
                    f"MITRE: {result.get('mitre_technique_id','?')}"
                )

                try:
                    es.index(index=TRIAGE_INDEX, document=result)
                    es_ok = True
                except Exception as e:
                    log.error(f"Elasticsearch write failed: {e}")
                    es_ok = False

                if not es_ok:
                    log.warning(f"Skipping mark-seen for {alert_id[:16]} -- ES write failed")
                    continue

                send_to_splunk(result)
                send_telegram_alert(result)

                # Mark seen only after ES write succeeded
                mark_triaged(alert_id)

                time.sleep(2)

        except KeyboardInterrupt:
            log.info("Triage engine stopped.")
            break
        except Exception as e:
            log.error(f"Poll cycle error: {e}")

        time.sleep(POLL_INTERVAL)


# =================================================
# ENTRY POINT
# =================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI SOC Triage Engine")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Validate Splunk HEC, field structure, and risk score without calling Claude"
    )
    args = parser.parse_args()

    if args.test:
        run_test_mode()
    else:
        run()
