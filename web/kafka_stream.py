"""
Background Kafka consumer that mirrors the live `ids-events` topic onto the
Hub so the dashboard can render it.

Two deliberate choices:
  - a UNIQUE consumer group per process (ids-web-<rand>), so this reader
    never competes with the detection consumer ("ids-consumer") for
    partitions -- every consumer group gets its own copy of the topic.
  - auto_offset_reset="latest", so a freshly opened dashboard shows live
    traffic from now on rather than replaying the whole backlog.

Exceptions are caught broadly (not by a specific class) so this works across
kafka-python versions, which move the broker-unavailable error around.
"""
import json
import threading
import time
import uuid

from kafka import KafkaConsumer


def start_kafka_stream(hub, host: str = "kafka", port: int = 9092, topic: str = "ids-events"):
    thread = threading.Thread(
        target=_run,
        args=(hub, host, port, topic),
        daemon=True,
    )
    thread.start()
    return thread


def _run(hub, host, port, topic):
    while True:
        consumer = None
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=f"{host}:{port}",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                group_id=f"ids-web-{uuid.uuid4().hex[:8]}",
                auto_offset_reset="latest",
                enable_auto_commit=False,
            )
        except Exception as exc:  # noqa: BLE001  (broker not up yet, bad host, etc.)
            hub.publish({"channel": "system", "data": {"kafka": "waiting"}})
            time.sleep(2)
            continue

        hub.publish({"channel": "system", "data": {"kafka": "connected"}})
        try:
            for message in consumer:
                hub.publish({"channel": "event", "data": message.value})
        except Exception as exc:  # noqa: BLE001
            hub.publish({"channel": "system", "data": {"kafka": f"lost: {exc}"}})
            time.sleep(2)
        finally:
            try:
                consumer.close()
            except Exception:  # noqa: BLE001
                pass