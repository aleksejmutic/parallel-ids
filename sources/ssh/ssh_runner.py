import json
import threading

from sources.ssh.attacks.brute_force import run_attack
from sources.ssh.attacks.random_passwords_brute_force import run_attack as run_random_attack
from sources.ssh.ssh_collector import collect


def brute_force_worker():

    for result in run_attack():

        event = collect(
            result,
            attack_type="brute_force"
        )

        print(json.dumps(event, indent=4))


def random_attack_worker():

    for result in run_random_attack():

        event = collect(
            result,
            attack_type="random_password"
        )

        print(json.dumps(event, indent=4))


def run_ssh():

    brute_force_thread = threading.Thread(
        target=brute_force_worker,
        daemon=True
    )

    random_attack_thread = threading.Thread(
        target=random_attack_worker,
        daemon=True
    )

    brute_force_thread.start()
    random_attack_thread.start()

    brute_force_thread.join()
    random_attack_thread.join()