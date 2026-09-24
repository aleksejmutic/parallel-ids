import json

from core.event_bus import EventBus
from sources.http.attacks.brute_force import run_attack
from sources.http.http_collector import collect


def brute_force_worker(event_bus):

    for result in run_attack():

        event = collect(
            result,
            attack_type="brute_force"
        )

        event_bus.publish(event)

        print(json.dumps(event, indent=4))


def run_http():

    event_bus = EventBus()

    brute_force_worker(event_bus)

    event_bus.close()