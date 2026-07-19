from __future__ import annotations

from models.case import InvestigationCase


def build_timeline(case: InvestigationCase) -> InvestigationCase:
    """
    Build a simple chronological timeline from evidence.
    """

    case.timeline.clear()

    evidence = sorted(
        case.evidence,
        key=lambda item: (
            item.timestamp is None,
            item.timestamp,
        ),
    )

    for item in evidence:

        if item.timestamp is None:
            continue

        event_code = str(
            item.data.get(
                "event_code",
                "unknown",
            )
        )

        case.add_timeline_event(
            timestamp=item.timestamp,
            event_type=event_code,
            description=item.description,
            source=item.source,
            data=item.data,
        )

    return case
