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