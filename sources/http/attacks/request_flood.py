import time
import requests

from config import HTTP_HOST, HTTP_PORT


def run_attack():
    url = f"http://{HTTP_HOST}:{HTTP_PORT}/api/health"

    while True:

        print(f"Requesting: GET {url}")

        result = requests.get(url)

        yield result

        time.sleep(0.1)


if __name__ == "__main__":
    for result in run_attack():
        print(f"Response: {result.status_code} | {result.text}")