from __future__ import annotations
from tools.investigation_writer import save_investigation_result
from clients.elastic_client import es
from models.case import InvestigationCase
from tools.ai_investigator import AIInvestigator
from tools.providers.anthropic_provider import AnthropicProvider


def find_latest_7045() -> dict:
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
            "No Windows Event 7045 was found."
        )

    return hits[0]


def main() -> None:
    alert = find_latest_7045()
    source = alert.get("_source", {})

    host = source.get("host", {}).get("name")

    if not host:
        raise RuntimeError(
            "The alert is missing host.name."
        )

    case = InvestigationCase(
        alert_id=str(alert.get("_id")),
        alert_type="Windows Event 7045",
        host=host,
        severity="high",
        original_alert=source,
    )

    case.add_task("collect_related_events")
    case.add_task("build_event_timeline")

    provider = AnthropicProvider()

    investigator = AIInvestigator(
        provider=provider,
        es_client=es,
    )

    result = investigator.investigate(case)

    save_response = save_investigation_result(
    case,
    result,
    es,
)

    print("\n========== Real AI Investigation ==========")
    print(f"Host: {case.host}")
    print(f"Evidence collected: {len(case.evidence)}")
    print(f"Timeline events: {len(case.timeline)}")
    print(f"Saved index: {save_response.get('_index')}")
    print(f"Saved document ID: {save_response.get('_id')}")
    print(f"Save result: {save_response.get('result')}")
    print()
    print()
    print(result)


if __name__ == "__main__":
    main()
