from __future__ import annotations

from typing import Any

from models.case import InvestigationCase


def triage_result_to_case(
    triage_result: dict[str, Any],
) -> InvestigationCase:
    """
    Convert a completed triage result into an InvestigationCase.

    This adapter keeps the existing triage engine separate from the
    investigation system.
    """

    if not triage_result:
        raise ValueError("Triage result cannot be empty.")

    alert_id = triage_result.get("original_alert_id")

    if not alert_id:
        raise ValueError(
            "Triage result is missing original_alert_id."
        )

    case = InvestigationCase(
        alert_id=str(alert_id),
        alert_type=triage_result.get(
            "alert_name",
            "unknown_alert",
        ),
        host=triage_result.get("host"),
        severity=triage_result.get("ai_severity"),
        risk_score=triage_result.get("risk_score"),
        original_alert=triage_result.get(
            "alert_source_raw",
            {},
        ),
    )

    case.status = "triaged"

    case.add_evidence(
        source="ai_triage_engine",
        description="AI triage analysis completed.",
        data={
            "verdict": triage_result.get("ai_verdict"),
            "severity": triage_result.get("ai_severity"),
            "risk_score": triage_result.get("risk_score"),
            "confidence": triage_result.get("confidence"),
            "summary": triage_result.get("ai_summary"),
            "mitre_technique": triage_result.get(
                "mitre_technique"
            ),
            "source_ip": triage_result.get("source_ip"),
            "destination_ip": triage_result.get(
                "destination_ip"
            ),
        },
    )

    explanation = triage_result.get("ai_summary")

    if explanation:
        case.add_finding(explanation)

    mitre_technique = triage_result.get("mitre_technique")

    if mitre_technique:
        case.add_finding(
            f"Mapped behavior to MITRE ATT&CK: "
            f"{mitre_technique}"
        )

    recommended_action = triage_result.get(
        "recommended_action"
    )

    if recommended_action:
        case.add_recommended_action(
            recommended_action
        )

    case.add_task("collect_related_events")
    case.add_task("build_event_timeline")
    case.add_task("enrich_indicators")

    case.touch()

    return case
