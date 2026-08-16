import threading

from consumer.event_consumer import EventConsumer
from sources.ssh.ssh_runner import run_ssh
from detection.rules.brute_force import BruteForceRule
from detection.strategies.serial import SerialStrategy
from detection.alert_logger import log_alerts

RULE_SPECS = [(BruteForceRule, {"threshold": 5, "window_seconds": 60})]


def run_consumer():
    consumer = EventConsumer()
    strategy = SerialStrategy()
    try:
        for event in consumer.consume():
            alerts = strategy.process([event], RULE_SPECS)
            if alerts:
                log_alerts(alerts, strategy.name)
                print("ALERT:", alerts)
    finally:
        consumer.close()


def main():
    ssh_thread = threading.Thread(target=run_ssh, daemon=True)
    consumer_thread = threading.Thread(target=run_consumer, daemon=True)

    ssh_thread.start()
    consumer_thread.start()

    ssh_thread.join()
    consumer_thread.join()


if __name__ == "__main__":
    main()