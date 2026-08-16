import threading

from consumer.event_consumer import EventConsumer
from sources.ssh.ssh_runner import run_ssh


def run_consumer():

    consumer = EventConsumer()

    try:
        for event in consumer.consume():
            print("CONSUMED EVENT:")
            print(event)

    finally:
        consumer.close()


def main():

    ssh_thread = threading.Thread(
        target=run_ssh,
        daemon=True
    )

    consumer_thread = threading.Thread(
        target=run_consumer,
        daemon=True
    )

    ssh_thread.start()
    consumer_thread.start()

    ssh_thread.join()
    consumer_thread.join()


if __name__ == "__main__":
    main()