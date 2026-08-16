import json

from kafka import KafkaProducer


class EventBus:

    def __init__(self, host="kafka", port=9092):
        self.producer = KafkaProducer(
            bootstrap_servers=f"{host}:{port}",
            value_serializer=lambda event:
                json.dumps(event).encode("utf-8")
        )

    def publish(self, event):
        self.producer.send(
            "ids-events",
            value=event
        )

    def close(self):
        self.producer.flush()
        self.producer.close()