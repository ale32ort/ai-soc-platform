from tools.case_adapter import triage_result_to_case


sample_triage_result = {
    "original_alert_id": "test-alert-000001",
    "alert_name": "Windows Event 7045",
    "host": "tito",
    "ai_severity": "HIGH",
    "ai_verdict": "NEEDS_INVESTIGATION",
    "risk_score": 63,
    "confidence": "HIGH",
    "ai_summary": (
        "A new Windows service was created and may "
        "represent persistence."
    ),
    "mitre_technique": (
        "T1543.003 -- Windows Service"
    ),
    "recommended_action": (
        "Review the service binary and validate "
        "whether the service is authorized."
    ),
    "source_ip": "unknown",
    "destination_ip": "unknown",
    "alert_source_raw": {
        "@timestamp": "2026-07-10T19:00:00Z",
        "event": {
            "code": "7045",
        },
        "host": {
            "name": "tito",
        },
        "winlog": {
            "event_data": {
                "ServiceName": "SuspiciousService",
                "ImagePath": (
                    "C:\\Temp\\suspicious.exe"
                ),
            }
        },
    },
}


case = triage_result_to_case(
    sample_triage_result
)

assert case.alert_id == "test-alert-000001"
assert case.host == "tito"
assert case.status == "triaged"
assert case.severity == "HIGH"
assert case.risk_score == 63
assert len(case.evidence) == 1
assert len(case.tasks) == 3
assert len(case.findings) == 2
assert len(case.recommended_actions) == 1

print(case.model_dump_json(indent=2))
