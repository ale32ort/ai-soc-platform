"""Investigation-result deduplication."""

from __future__ import annotations

from typing import Any

from tools.investigation_writer import DEFAULT_RESULTS_INDEX


class Deduplicator:
    """Check whether an alert already has a persisted investigation."""

    def __init__(
        self,
        es_client: Any,
        *,
        index_name: str = DEFAULT_RESULTS_INDEX,
    ) -> None:
        self.es = es_client
        self.index_name = index_name

    def exists(self, alert_id: str) -> bool:
        response = self.es.search(
            index=self.index_name,
            ignore_unavailable=True,
            query={
                "term": {
                    "alert_id.keyword": alert_id
                }
            },
            size=0,
            track_total_hits=True,
        )

        total = response.get("hits", {}).get("total", 0)
        if isinstance(total, dict):
            total = total.get("value", 0)

        return bool(total)
