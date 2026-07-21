from services.deduplicator import Deduplicator


class FakeElasticsearchClient:
    def __init__(self, total):
        self.total = total
        self.request = None

    def search(self, **kwargs):
        self.request = kwargs
        return {"hits": {"total": self.total}}


def test_exists_checks_alert_id_in_investigations_index():
    client = FakeElasticsearchClient({"value": 1, "relation": "eq"})

    assert Deduplicator(client).exists("alert-7045") is True
    assert client.request == {
        "index": "soc-ai-investigations",
        "ignore_unavailable": True,
        "query": {"term": {"alert_id.keyword": "alert-7045"}},
        "size": 0,
        "track_total_hits": True,
    }


def test_exists_returns_false_for_no_matching_alert_id():
    client = FakeElasticsearchClient(0)

    assert Deduplicator(client).exists("new-alert") is False
