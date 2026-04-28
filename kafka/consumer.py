from kafka import KafkaConsumer
from shared.schema import Event
from topics import RAW_EVENTS_TOPIC
import json

consumer = KafkaConsumer(
    RAW_EVENTS_TOPIC,
    bootstrap_servers="localhost:9092",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    auto_offset_reset="latest",
    enable_auto_commit=True,
    group_id="ids-consumer-group"
)

print("IDS Consumer started... listening for events")

for msg in consumer:
    # Convert dict → Event object
    event = Event.from_dict(msg.value)

    print("\n--- EVENT RECEIVED ---")
    print(f"id:       {event.event_id}")
    print(f"type:     {event.event_type}")
    print(f"source:   {event.source_type}")
    print(f"ip:       {event.source_ip}")
    print(f"severity: {event.severity}")
    print(f"raw:      {event.raw}")