from datetime import datetime, timezone

from models.case import InvestigationCase
from tools.timeline_builder import build_timeline


def main():
    case = InvestigationCase(
        alert_id="test",
        alert_type="7045",
        host="tito",
        original_alert={},
    )

    case.add_evidence(
        source="elastic",
        description="Process Created",
        timestamp=datetime(
            2026,
            7,
            19,
            2,
            13,
            24,
            tzinfo=timezone.utc,
        ),
        data={
            "event_code": "4688",
            "process_name": "mc-dad.exe",
        },
    )

    case.add_evidence(
        source="elastic",
        description="Service Installed",
        timestamp=datetime(
            2026,
            7,
            19,
            2,
            13,
            25,
            tzinfo=timezone.utc,
        ),
        data={
            "event_code": "7045",
        },
    )

    build_timeline(case)

    print("\nTimeline\n")

    for event in case.timeline:
        print(
            event.timestamp,
            event.event_type,
            event.description,
        )


if __name__ == "__main__":
    main()
