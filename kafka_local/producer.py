from kafka import KafkaProducer
from shared.schema import Event
from .topics import RAW_EVENTS_TOPIC
import json

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    acks="all",
    linger_ms=10
)

def send_event(event: Event):
    if not isinstance(event, Event):
        raise TypeError("send_event expects Event object")

    producer.send(RAW_EVENTS_TOPIC, event.to_dict())


def flush():
    producer.flush()