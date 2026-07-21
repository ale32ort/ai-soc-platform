"""
AlertMonitor

Responsible for retrieving the next alert that should be investigated.
"""

from tools.elastic_investigation import ElasticInvestigation


class AlertMonitor:

    def __init__(self, es_client):
        self.es = es_client
        self.elastic = ElasticInvestigation(es_client)

    def get_latest_alert(self):
        """
        Returns the newest Event 7045 alert.

        Returns:
            dict | None
        """

        return self.elastic.find_latest_event7045()
