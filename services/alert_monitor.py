"""Retrieve Windows Event 7045 alerts from Elasticsearch."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from elasticsearch import NotFoundError

logger = logging.getLogger(__name__)

DEFAULT_STATE_INDEX = "soc-ai-manager-state"
DEFAULT_MANAGER_ID = "default"
CHECKPOINT_FIELD = "latest_successfully_processed_timestamp"


class AlertMonitor:
    """Read candidate alerts; investigation decisions live elsewhere."""

    def __init__(
        self,
        es_client: Any,
        *,
        index_name: str = "winlogbeat-*",
        batch_size: int = 100,
        state_index: str = DEFAULT_STATE_INDEX,
        manager_id: str = DEFAULT_MANAGER_ID,
    ) -> None:
        self.es = es_client
        self.index_name = index_name
        self.batch_size = batch_size
        self.state_index = state_index
        self.manager_id = manager_id
        self.checkpoint = self._load_checkpoint()

    def _load_checkpoint(self) -> str | None:
        """Load the persisted checkpoint, or start without one."""

        try:
            response = self.es.get(
                index=self.state_index,
                id=self.manager_id,
            )
        except NotFoundError:
            return None

        if not response.get("found", True):
            return None

        return response.get("_source", {}).get(CHECKPOINT_FIELD)

    @staticmethod
    def _timestamp_value(timestamp: str) -> datetime:
        """Convert an ISO timestamp into a datetime object."""
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    def update_checkpoint(self, timestamp: str) -> None:
        """Advance the checkpoint without allowing it to move backward."""

        if (
            self.checkpoint is None
            or self._timestamp_value(timestamp)
            > self._timestamp_value(self.checkpoint)
        ):
            self.checkpoint = timestamp

            self.es.index(
                index=self.state_index,
                id=self.manager_id,
                document={
                    CHECKPOINT_FIELD: timestamp
                },
                refresh="wait_for",
            )

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return all new Windows Event 7045 records."""

        filters: list[dict[str, Any]] = [
            {
                "term": {
                    "event.code": "7045"
                }
            }
        ]

        if self.checkpoint is not None:
            filters.append(
                {
                    "range": {
                        "@timestamp": {
                            "gt": self.checkpoint
                        }
                    }
                }
            )

        logger.info(
            "Searching %s for Event 7045 after checkpoint %s",
            self.index_name,
            self.checkpoint,
        )

        response = self.es.search(
            index=self.index_name,
            query={
                "bool": {
                    "filter": filters
                }
            },
            size=self.batch_size,
            sort=[
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
        )

        hits = response.get("hits", {}).get("hits", [])

        logger.info(
            "Found %d new Event 7045 record(s)",
            len(hits),
        )

        return hits

    def get_latest_alert(self) -> dict[str, Any] | None:
        """Return the newest Event 7045 alert, if one exists."""

        alerts = self.get_alerts()
        return alerts[0] if alerts else None
