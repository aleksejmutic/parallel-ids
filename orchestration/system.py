import threading

from orchestration.attacks import run_attacks
from orchestration.detection import run_detection


def run_system():

    detection_thread = threading.Thread(
        target=run_detection,
        daemon=True
    )

    detection_thread.start()

    ssh_thread, http_thread = run_attacks()

    ssh_thread.join()
    http_thread.join()