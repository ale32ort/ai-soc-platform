"""Autonomous Event 7045 investigation service."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from clients.elastic_client import es
from models.case import InvestigationCase
from services.alert_monitor import AlertMonitor
from services.deduplicator import Deduplicator
from tools.ai_investigator import AIInvestigator
from tools.investigation_writer import save_investigation_result
from tools.providers.anthropic_provider import AnthropicProvider


LOGGER = logging.getLogger(__name__)
POLL_INTERVAL_SECONDS = 60


class InvestigationManager:
    """Coordinate monitoring, deduplication, investigation, and writing."""

    def __init__(
        self,
        monitor: AlertMonitor,
        deduplicator: Deduplicator,
        investigator: AIInvestigator,
        es_client: Any,
        *,
        writer: Callable[..., dict[str, Any]] = save_investigation_result,
        poll_interval: int = POLL_INTERVAL_SECONDS,
    ) -> None:
        self.monitor = monitor
        self.deduplicator = deduplicator
        self.investigator = investigator
        self.es = es_client
        self.writer = writer
        self.poll_interval = poll_interval
        self._in_progress: set[str] = set()

    @staticmethod
    def _build_case(alert: dict[str, Any]) -> InvestigationCase:
        source = alert.get("_source", {})
        host = source.get("host", {}).get("name")
        if not host:
            raise ValueError("The alert is missing host.name.")

        case = InvestigationCase(
            alert_id=str(alert.get("_id")),
            alert_type="Windows Event 7045",
            host=host,
            severity="high",
            original_alert=source,
        )
        case.add_task("collect_related_events")
        case.add_task("build_event_timeline")
        return case

    def process_alert(self, alert: dict[str, Any]) -> bool:
        """Investigate and persist one alert unless it is a duplicate."""

        alert_id = alert.get("_id")
        if alert_id is None:
            raise ValueError("The alert is missing _id.")
        alert_id = str(alert_id)

        if alert_id in self._in_progress or self.deduplicator.exists(alert_id):
            LOGGER.debug("Skipping previously investigated alert %s", alert_id)
            return False

        self._in_progress.add(alert_id)
        try:
            case = self._build_case(alert)
            result = self.investigator.investigate(case)
            self.writer(case, result, self.es)
            timestamp = case.original_alert.get("@timestamp")
            if timestamp:
                self.monitor.update_checkpoint(timestamp)
            else:
                LOGGER.warning(
                    "Alert %s has no timestamp; checkpoint was not advanced",
                    alert_id,
                )
            LOGGER.info("Completed investigation for alert %s", alert_id)
            return True
        finally:
            self._in_progress.discard(alert_id)

    def run_once(self) -> None:
        """Process one polling batch while isolating per-alert failures."""

        for alert in self.monitor.get_alerts():
            try:
                self.process_alert(alert)
            except Exception:
                LOGGER.exception(
                    "Failed to process alert %s",
                    alert.get("_id", "unknown"),
                )

    def run(self) -> None:
        LOGGER.info("Investigation manager started")
        try:
            while True:
                try:
                    self.run_once()
                except Exception:
                    LOGGER.exception("Alert polling failed")
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            LOGGER.info("Investigation manager stopped")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    investigator = AIInvestigator(
        provider=AnthropicProvider(),
        es_client=es,
    )
    InvestigationManager(
        monitor=AlertMonitor(es),
        deduplicator=Deduplicator(es),
        investigator=investigator,
        es_client=es,
    ).run()


if __name__ == "__main__":
    main()
