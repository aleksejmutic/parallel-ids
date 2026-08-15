import json
import threading
import time

from sources.ssh.attacks.brute_force import run_attack
from sources.ssh.attacks.random_passwords_brufe_force import run_attack as run_random_attack
from sources.ssh.ssh_collector import collect


def brute_force_worker():
    run_attack()


def random_attack_worker():
    run_random_attack()


def main():

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

    while True:

        print("Collecting SSH activity")

        event = collect()

        print(json.dumps(event, indent=4))

        time.sleep(5)


if __name__ == "__main__":
    main()