import json
import threading
import time

from core.event_bus import EventBus
from sources.ssh.attacks.brute_force import run_attack
from sources.ssh.attacks.random_passwords_brute_force import run_attack as run_random_attack
from sources.ssh.ssh_collector import collect


def brute_force_worker(event_bus):
    # Lab mode: the wordlist brute force is a *finite* generator -- it ends when
    # the wordlist is exhausted, and returns early if it cracks the password.
    # Wrap it so it relaunches and keeps the pane live forever.
    while True:
        for result in run_attack():
            event = collect(result, attack_type="brute_force")
            event_bus.publish(event)
            print(json.dumps(event, indent=4))
        time.sleep(2)


def random_attack_worker(event_bus):
    # run_random_attack() is already an infinite generator (while True inside),
    # so this loop never exhausts -- no outer restart wrapper needed.
    for result in run_random_attack():
        event = collect(result, attack_type="random_password")
        event_bus.publish(event)
        print(json.dumps(event, indent=4))


def run_ssh():

    event_bus = EventBus()

    brute_force_thread = threading.Thread(
        target=brute_force_worker,
        args=(event_bus,),
        daemon=True
    )

    random_attack_thread = threading.Thread(
        target=random_attack_worker,
        args=(event_bus,),
        daemon=True
    )

    brute_force_thread.start()
    random_attack_thread.start()

    brute_force_thread.join()
    random_attack_thread.join()

    event_bus.close()