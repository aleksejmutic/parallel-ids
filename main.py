import json

from sources.ssh.ssh_simulator import collect


def main():
    event = collect()
    print(json.dumps(event, indent=4))


if __name__ == "__main__":
    main()