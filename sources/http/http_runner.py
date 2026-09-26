# Runs all HTTP attacks concurrently using separate threads.
# Each worker executes its attack, converts the HTTP result into a normalized
# IDS event through the collector, and publishes the event to the shared EventBus.
# The request flood runs continuously, keeping the HTTP event stream active.

import json
import threading

from core.event_bus import EventBus
from sources.http.attacks.brute_force import run_attack as run_brute_force
from sources.http.attacks.credential_stuffing import run_attack as run_credential_stuffing
from sources.http.attacks.request_flood import run_attack as run_request_flood
from sources.http.http_collector import collect


def brute_force_worker(event_bus):

    for result in run_brute_force():

        event = collect(
            result,
            attack_type="brute_force"
        )

        event_bus.publish(event)

        print(json.dumps(event, indent=4))


def credential_stuffing_worker(event_bus):

    for result in run_credential_stuffing():

        event = collect(
            result,
            attack_type="credential_stuffing"
        )

        event_bus.publish(event)

        print(json.dumps(event, indent=4))


def request_flood_worker(event_bus):

    for result in run_request_flood():

        event = collect(
            result,
            attack_type="request_flood"
        )

        event_bus.publish(event)

        print(json.dumps(event, indent=4))


def run_http():

    event_bus = EventBus()

    brute_force_thread = threading.Thread(
        target=brute_force_worker,
        args=(event_bus,),
        daemon=True
    )

    credential_stuffing_thread = threading.Thread(
        target=credential_stuffing_worker,
        args=(event_bus,),
        daemon=True
    )

    request_flood_thread = threading.Thread(
        target=request_flood_worker,
        args=(event_bus,),
        daemon=True
    )

    brute_force_thread.start()
    credential_stuffing_thread.start()
    request_flood_thread.start()

    brute_force_thread.join()
    credential_stuffing_thread.join()
    request_flood_thread.join()

    event_bus.close()