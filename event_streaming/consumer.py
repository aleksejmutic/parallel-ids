from kafka import KafkaConsumer
from shared.schema import Event
from .topics import RAW_EVENTS_TOPIC
from storage import insert_event, init_db
import json

init_db()

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
    insert_event(event)

    print(
    f"[CONSUMED] "
    f"type={event.event_type:<20} "
    f"ip={event.source_ip:<15} "
    f"scenario={event.scenario_id or '-':<25} "
    f"user={event.metadata.get('user', '-'):<10} "
    f"time={event.timestamp}"
)

