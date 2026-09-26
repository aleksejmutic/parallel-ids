import threading

from sources.ssh.ssh_runner import run_ssh
from sources.http.http_runner import run_http


def run_attacks():

    ssh_thread = threading.Thread(
        target=run_ssh,
        daemon=True
    )

    http_thread = threading.Thread(
        target=run_http,
        daemon=True
    )

    ssh_thread.start()
    http_thread.start()

    return ssh_thread, http_thread