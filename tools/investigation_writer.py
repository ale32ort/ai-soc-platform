from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from models.case import InvestigationCase
from models.investigation_result import InvestigationResult


DEFAULT_RESULTS_INDEX = "soc-ai-investigations"


def save_investigation_result(
    case: InvestigationCase,
    result: InvestigationResult,
    es_client: Any,
    *,
    index_name: str = DEFAULT_RESULTS_INDEX,
) -> dict[str, Any]:
    """
    Save a completed AI investigation to Elasticsearch.
    """

    case.status = "completed"
    case.touch()

    document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case.case_id,
        "alert_id": case.alert_id,
        "alert_type": case.alert_type,
        "host": case.host,
        "case_status": case.status,
        "severity": case.severity,
        "risk_score": case.risk_score,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "summary": result.summary,
        "reasoning": result.reasoning,
        "mitre_techniques": result.mitre_techniques,
        "recommendations": result.recommendations,
        "evidence_count": len(case.evidence),
        "timeline_count": len(case.timeline),
        "original_alert_timestamp": case.original_alert.get(
            "@timestamp"
        ),
    }

    response = es_client.index(
        index=index_name,
        id=case.case_id,
        document=document,
        refresh="wait_for",
    )

    case.status = "completed"
    case.touch()

    return response
