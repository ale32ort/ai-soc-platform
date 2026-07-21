from models.investigation_result import InvestigationResult
from services.investigation_manager import InvestigationManager


class FakeMonitor:
    def __init__(self):
        self.checkpoint = None

    def update_checkpoint(self, timestamp):
        self.checkpoint = timestamp


class FakeDeduplicator:
    def exists(self, alert_id):
        return False


class FakeInvestigator:
    def investigate(self, case):
        return InvestigationResult(
            verdict="FALSE_POSITIVE",
            confidence=90,
            summary="test",
        )


ALERT = {
    "_id": "alert-7045",
    "_source": {
        "@timestamp": "2026-07-21T12:00:00Z",
        "host": {"name": "test-host"},
    },
}


def build_manager(writer):
    monitor = FakeMonitor()
    manager = InvestigationManager(
        monitor=monitor,
        deduplicator=FakeDeduplicator(),
        investigator=FakeInvestigator(),
        es_client=object(),
        writer=writer,
    )
    return manager, monitor


def test_checkpoint_advances_after_successful_write():
    manager, monitor = build_manager(lambda case, result, es: {})

    manager.process_alert(ALERT)

    assert monitor.checkpoint == "2026-07-21T12:00:00Z"


def test_checkpoint_does_not_advance_when_write_fails():
    def failing_writer(case, result, es):
        raise RuntimeError("write failed")

    manager, monitor = build_manager(failing_writer)

    try:
        manager.process_alert(ALERT)
    except RuntimeError:
        pass

    assert monitor.checkpoint is None
