# Elasticsearch client responsible for initializing the IDS indices,
# configuring them for the single-node cluster, and storing events and alerts.

from elasticsearch import Elasticsearch


class ElasticsearchClient:

    def __init__(
        self,
        host="elasticsearch",
        port=9200,
    ):
        self.client = Elasticsearch(
            f"http://{host}:{port}"
        )

    def initialize(self):
        self._create_index("ids-events")
        self._create_index("ids-alerts")

    def _create_index(self, index_name):
        if self.client.indices.exists(index=index_name):
            return

        self.client.indices.create(
            index=index_name,
            settings={
                "number_of_replicas": 0,
            },
        )

    def index_event(self, event):
        self.client.index(
            index="ids-events",
            document=event,
        )

    def index_alert(self, alert):
        self.client.index(
            index="ids-alerts",
            document=alert,
        )

    def close(self):
        self.client.close()