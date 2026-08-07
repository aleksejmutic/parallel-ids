import json
import time

from sources.ssh.ssh_collector import collect


def main():

    while True:

        print("Collecting SSH activity")

        event = collect()

        print(json.dumps(event, indent=4))

        # later:
        # send_to_elasticsearch(event)

        time.sleep(5)


if __name__ == "__main__":
    main()