import json

from kafka import KafkaConsumer


class EventConsumer:

    def __init__(self, host="kafka", port=9092):
        self.consumer = KafkaConsumer(
            "ids-events",
            bootstrap_servers=f"{host}:{port}",
            value_deserializer=lambda message:
                json.loads(message.decode("utf-8")),
            group_id="ids-consumer",
            auto_offset_reset="earliest",
            enable_auto_commit=True
        )

    def consume(self):

        for message in self.consumer:

            event = message.value

            yield event

    def close(self):
        self.consumer.close()