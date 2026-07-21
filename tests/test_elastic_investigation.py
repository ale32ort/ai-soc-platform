from models.case import InvestigationCase
from tools.elastic_investigation import collect_related_events


class FakeElasticsearchClient:
    def search(
        self,
        *,
        index,
        query,
        size,
        sort,
    ):
        assert "winlogbeat-*" in index
        assert size == 100
        assert query["bool"]["filter"][0]["term"][
            "host.name"
        ] == "tito"

        return {
            "hits": {
                "hits": [
                    {
                        "_id": "event-7045",
                        "_index": "winlogbeat-test",
                        "_source": {
                            "@timestamp": (
                                "2026-07-10T19:00:00Z"
                            ),
                            "host": {
                                "name": "tito"
                            },
                            "event": {
                                "code": "7045",
                                "action": (
                                    "service-installed"
                                ),
                                "module": "system",
                            },
                            "user": {
                                "name": "SYSTEM"
                            },
                            "message": (
                                "A service was installed."
                            ),
                            "winlog": {
                                "event_data": {
                                    "ServiceName": (
                                        "SuspiciousService"
                                    ),
                                    "ImagePath": (
                                        "C:\\Temp\\"
                                        "suspicious.exe"
                                    ),
                                }
                            },
                        },
                    },
                    {
                        "_id": "event-4688",
                        "_index": "winlogbeat-test",
                        "_source": {
                            "@timestamp": (
                                "2026-07-10T18:58:30Z"
                            ),
                            "host": {
                                "name": "tito"
                            },
                            "event": {
                                "code": "4688",
                                "action": (
                                    "process-created"
                                ),
                                "module": "security",
                            },
                            "user": {
                                "name": "alex"
                            },
                            "process": {
                                "name": "sc.exe",
                                "command_line": (
                                    "sc.exe create "
                                    "SuspiciousService"
                                ),
                            },
                        },
                    },
                ]
            }
        }


case = InvestigationCase(
    alert_id="test-alert-000001",
    alert_type="Windows Event 7045",
    host="tito",
    severity="HIGH",
    risk_score=63,
    original_alert={
        "@timestamp": "2026-07-10T19:00:00Z",
        "event": {
            "code": "7045"
        },
        "host": {
            "name": "tito"
        },
    },
)

case.add_task("collect_related_events")
case.add_task("build_event_timeline")
case.add_task("enrich_indicators")

updated_case = collect_related_events(
    case,
    FakeElasticsearchClient(),
)

collect_task = next(
    task
    for task in updated_case.tasks
    if task.name == "collect_related_events"
)

assert updated_case.status == "investigating"
assert len(updated_case.evidence) == 2
assert collect_task.status == "completed"
assert collect_task.result["events_found"] == 2

print(updated_case.model_dump_json(indent=2))
