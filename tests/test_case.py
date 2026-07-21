from models.case import InvestigationCase


case = InvestigationCase(
    alert_id="test-alert-7045",
    alert_type="windows_service_creation",
    host="tito",
    severity="high",
    risk_score=63,
    original_alert={
        "event_code": "7045",
        "service_name": "SuspiciousService",
        "service_path": "C:\\Temp\\suspicious.exe",
    },
)

case.add_task("collect_related_events")

case.add_evidence(
    source="winlogbeat",
    description="Windows service creation event detected",
    data={
        "event_code": "7045",
        "service_name": "SuspiciousService",
    },
)

case.complete_task(
    name="collect_related_events",
    result={
        "events_found": 12,
    },
)

case.add_finding(
    "A new Windows service was created from a temporary directory."
)

case.add_recommended_action(
    "Review the service binary before containment."
)

print(case.model_dump_json(indent=2))
