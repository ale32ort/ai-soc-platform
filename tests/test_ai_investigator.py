from datetime import datetime, timezone

from models.case import InvestigationCase
from tools.ai_investigator import AIInvestigator
from tools.mock_provider import MockProvider
from tools.timeline_builder import build_timeline


def main() -> None:
    case = InvestigationCase(
        alert_id="test-alert-7045",
        alert_type="Windows Event 7045",
        host="tito",
        severity="HIGH",
        risk_score=63,
        original_alert={},
    )

    case.add_evidence(
        source="elastic",
        description="Windows service installed",
        timestamp=datetime.now(timezone.utc),
        data={
            "event_code": "7045",
            "process_name": "mc-dad.exe",
            "service_name": (
                "McAfee Scheduled Task - "
                "(McAfee-Dynamicappdownloader)"
            ),
            "image_path": (
                r"C:\Program Files\McAfee\wps"
                r"\1.40.161.1\dad\mc-dad.exe"
            ),
        },
    )

    build_timeline(case)

    investigator = AIInvestigator(
        provider=MockProvider(),
    )

    context = investigator.build_context(case)
    result = investigator.investigate(case)

    assert "Windows Event 7045" in context
    assert "tito" in context
    assert "mc-dad.exe" in context
    assert result.verdict == "Likely Benign"
    assert result.confidence == 95

    print("========== Investigation Context ==========")
    print(context)

    print()
    print(result.pretty_print())

    print()
    print("AI investigator provider test passed.")


if __name__ == "__main__":
    main()
