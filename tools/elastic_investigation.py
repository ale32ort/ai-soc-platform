from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from models.case import InvestigationCase


DEFAULT_INDICES = [
    "winlogbeat-*",
    "filebeat-*",
]


def _parse_timestamp(value: str | None) -> datetime:
    """Convert an Elastic ISO timestamp into a timezone-aware datetime."""

    if not value:
        return datetime.now(timezone.utc)

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid alert timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _extract_event(hit: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Elasticsearch hit into useful investigation evidence."""

    source = hit.get("_source", {})

    return {
        "document_id": hit.get("_id"),
        "source_index": hit.get("_index"),
        "timestamp": source.get("@timestamp"),
        "host": source.get("host", {}).get("name"),
        "event_code": source.get("event", {}).get("code"),
        "event_action": source.get("event", {}).get("action"),
        "event_module": source.get("event", {}).get("module"),
        "user": source.get("user", {}).get("name"),
        "process_name": source.get("process", {}).get("name"),
        "command_line": source.get(
            "process",
            {},
        ).get("command_line"),
        "source_ip": source.get("source", {}).get("ip"),
        "destination_ip": source.get(
            "destination",
            {},
        ).get("ip"),
        "destination_port": source.get(
            "destination",
            {},
        ).get("port"),
        "message": source.get("message"),
        "winlog_event_data": source.get(
            "winlog",
            {},
        ).get("event_data", {}),
    }


def collect_related_events(
    case: InvestigationCase,
    es_client: Any,
    *,
    indices: list[str] | None = None,
    minutes_before: int = 15,
    minutes_after: int = 15,
    max_events: int = 100,
) -> InvestigationCase:
    """
    Query Elasticsearch for events surrounding the original alert.

    The function updates the same InvestigationCase and returns it.
    """

    if not case.host or case.host == "unknown":
        raise ValueError(
            "Cannot collect related events without a valid host."
        )

    alert_timestamp = _parse_timestamp(
        case.original_alert.get("@timestamp")
    )

    start_time = alert_timestamp - timedelta(
        minutes=minutes_before
    )
    end_time = alert_timestamp + timedelta(
        minutes=minutes_after
    )

    search_indices = indices or DEFAULT_INDICES

    query = {
        "bool": {
            "filter": [
                {
                    "term": {
                        "host.name": case.host
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat(),
                        }
                    }
                },
            ]
        }
    }

    response = es_client.search(
        index=",".join(search_indices),
        query=query,
        size=max_events,
        sort=[
            {
                "@timestamp": {
                    "order": "asc"
                }
            }
        ],
    )

    hits = response.get("hits", {}).get("hits", [])
    extracted_events = [
        _extract_event(hit)
        for hit in hits
    ]

    for event in extracted_events:
        event_timestamp = None

        if event.get("timestamp"):
            event_timestamp = _parse_timestamp(
                event["timestamp"]
            )

        case.add_evidence(
            source=event.get(
                "source_index",
                "elasticsearch",
            ),
            description=(
                f"Related event "
                f"{event.get('event_code') or 'unknown'} "
                f"found on host {case.host}."
            ),
            timestamp=event_timestamp,
            data=event,
        )

    case.complete_task(
        name="collect_related_events",
        result={
            "events_found": len(extracted_events),
            "indices_searched": search_indices,
            "host": case.host,
            "window_start": start_time.isoformat(),
            "window_end": end_time.isoformat(),
        },
    )

    case.status = "investigating"
    case.touch()

    return case
