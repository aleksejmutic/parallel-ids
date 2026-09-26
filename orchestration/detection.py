from consumer.event_consumer import EventConsumer
from core.elasticsearch_client import ElasticsearchClient
from detection.alert_logger import log_alerts

from detection.rules.ssh.brute_force import BruteForceRule

from detection.rules.http.brute_force import HTTPBruteForceRule
from detection.rules.http.credential_stuffing import CredentialStuffingRule
from detection.rules.http.request_flood import RequestFloodRule

from detection.strategies.serial import SerialStrategy


RULE_SPECS = [
    (
        BruteForceRule,
        {
            "threshold": 5,
            "window_seconds": 60,
        },
    ),
    (
        HTTPBruteForceRule,
        {
            "threshold": 5,
            "window_seconds": 10,
        },
    ),
    (
        CredentialStuffingRule,
        {
            "threshold": 5,
            "window_seconds": 10,
        },
    ),
    (
        RequestFloodRule,
        {
            "threshold": 50,
            "window_seconds": 10,
        },
    ),
]


def run_detection():

    consumer = EventConsumer()
    strategy = SerialStrategy(RULE_SPECS)
    es = ElasticsearchClient()

    try:
        for event in consumer.consume():

            # Store every event in Elasticsearch
            es.index_event(event)

            alerts = strategy.process([event])

            if alerts:

                log_alerts(
                    alerts,
                    strategy.name
                )

                # Store every alert in Elasticsearch
                for alert in alerts:
                    es.index_alert(alert)

                print("ALERT:", alerts)

    finally:
        es.close()
        consumer.close()