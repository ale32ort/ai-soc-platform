from services.alert_monitor import AlertMonitor, CHECKPOINT_FIELD


class FakeElasticsearchClient:
    def __init__(self, hits, checkpoint=None):
        self.hits = hits
        self.checkpoint = checkpoint
        self.request = None
        self.get_request = None
        self.index_request = None

    def get(self, **kwargs):
        self.get_request = kwargs
        if self.checkpoint is None:
            return {"found": False}
        return {
            "found": True,
            "_source": {
                CHECKPOINT_FIELD: self.checkpoint
            },
        }

    def index(self, **kwargs):
        self.index_request = kwargs
        return {"result": "updated"}

    def search(self, **kwargs):
        self.request = kwargs
        return {"hits": {"hits": self.hits}}


def test_get_alerts_retrieves_event_7045_newest_first():
    hits = [{"_id": "new"}, {"_id": "old"}]
    client = FakeElasticsearchClient(hits)

    alerts = AlertMonitor(client, batch_size=25).get_alerts()

    assert alerts == hits
    assert client.request["index"] == "winlogbeat-*"
    assert client.request["query"]["bool"]["filter"] == [
        {"term": {"event.code": "7045"}}
    ]
    assert client.request["size"] == 25
    assert client.request["sort"] == [
        {"@timestamp": {"order": "desc"}}
    ]


def test_get_latest_alert_returns_none_when_no_alert_exists():
    client = FakeElasticsearchClient([])

    assert AlertMonitor(client).get_latest_alert() is None


def test_get_alerts_only_requests_events_after_checkpoint():
    client = FakeElasticsearchClient([])
    monitor = AlertMonitor(client)
    monitor.update_checkpoint("2026-07-21T12:00:00Z")

    monitor.get_alerts()

    assert client.request["query"]["bool"]["filter"] == [
        {"term": {"event.code": "7045"}},
        {
            "range": {
                "@timestamp": {
                    "gt": "2026-07-21T12:00:00Z"
                }
            }
        },
    ]


def test_checkpoint_only_moves_forward():
    monitor = AlertMonitor(FakeElasticsearchClient([]))

    monitor.update_checkpoint("2026-07-21T12:00:00Z")
    monitor.update_checkpoint("2026-07-21T11:00:00Z")

    assert monitor.checkpoint == "2026-07-21T12:00:00Z"
    assert monitor.es.index_request["document"] == {
        CHECKPOINT_FIELD: "2026-07-21T12:00:00Z"
    }


def test_checkpoint_is_loaded_from_manager_state_index():
    checkpoint = "2026-07-21T12:00:00Z"
    client = FakeElasticsearchClient([], checkpoint=checkpoint)

    monitor = AlertMonitor(client)

    assert monitor.checkpoint == checkpoint
    assert client.get_request == {
        "index": "soc-ai-manager-state",
        "id": "default",
    }


def test_missing_checkpoint_falls_back_to_unfiltered_query():
    client = FakeElasticsearchClient([])
    monitor = AlertMonitor(client)

    monitor.get_alerts()

    assert monitor.checkpoint is None
    assert client.request["query"]["bool"]["filter"] == [
        {"term": {"event.code": "7045"}}
    ]


def test_checkpoint_is_persisted_for_default_manager():
    client = FakeElasticsearchClient([])
    monitor = AlertMonitor(client)

    monitor.update_checkpoint("2026-07-21T12:00:00Z")

    assert client.index_request == {
        "index": "soc-ai-manager-state",
        "id": "default",
        "document": {
            CHECKPOINT_FIELD: "2026-07-21T12:00:00Z"
        },
        "refresh": "wait_for",
    }
