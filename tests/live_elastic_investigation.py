from __future__ import annotations

from models.case import InvestigationCase
from tools.elastic_investigation import collect_related_events
from clients.elastic_client  import es


def find_latest_7045() -> dict:
    """Retrieve the newest real Windows Event 7045 from Elasticsearch."""

    response = es.search(
        index="winlogbeat-*",
        query={
            "bool": {
                "filter": [
                    {
                        "term": {
                            "event.code": "7045"
                        }
                    }
                ]
            }
        },
        size=1,
        sort=[
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
    )

    hits = response.get("hits", {}).get("hits", [])

    if not hits:
        raise RuntimeError(
            "No Windows Event 7045 was found in winlogbeat-*."
        )

    return hits[0]


def main() -> None:
    alert = find_latest_7045()
    source = alert.get("_source", {})

    host = source.get("host", {}).get("name")
    timestamp = source.get("@timestamp")

    if not host:
        raise RuntimeError(
            "The Event 7045 document is missing host.name."
        )

    print("Found real Event 7045")
    print(f"Document ID: {alert.get('_id')}")
    print(f"Host: {host}")
    print(f"Timestamp: {timestamp}")

    case = InvestigationCase(
        alert_id=str(alert.get("_id")),
        alert_type="Windows Event 7045",
        host=host,
        original_alert=source,
    )

    case.add_task("collect_related_events")
    case.add_task("build_event_timeline")
    case.add_task("enrich_indicators")

    updated_case = collect_related_events(
        case,
        es,
        indices=["winlogbeat-*"],
        minutes_before=15,
        minutes_after=15,
        max_events=100,
    )

    task = next(
        item
        for item in updated_case.tasks
        if item.name == "collect_related_events"
    )

    print("\nInvestigation completed")
    print(f"Case ID: {updated_case.case_id}")
    print(f"Case status: {updated_case.status}")
    print(f"Related events found: {task.result['events_found']}")

    print("\nCollected events:")

    for evidence in updated_case.evidence:
        data = evidence.data

        print(
            f"- {data.get('timestamp')} | "
            f"Event {data.get('event_code')} | "
            f"{data.get('process_name') or 'no process'}"
        )


if __name__ == "__main__":
    main()
