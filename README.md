# IDS — Intrusion Detection System

A containerized Intrusion Detection System with a built-in Network Telemetry
Simulator. It generates SSH and HTTP attack traffic against target services,
normalizes every result into a unified event format, streams those events
through Kafka, runs detection rules over them, and stores both events and
alerts in Elasticsearch. A web dashboard and a Kibana data view provide two
different live views of the system.

## Architecture
 
The system is a pipeline with five stages. Attack workers run real SSH and HTTP
attacks against the target services. Collectors convert each raw result into a
common event schema and publish it to the `ids-events` Kafka topic. The
detection service consumes that topic, runs the rule set over each event,
indexes every event and alert into Elasticsearch (`ids-events` and
`ids-alerts`), and logs alerts to `logs/alerts.jsonl`. Elasticsearch is the
storage layer, and Kibana reads from it as a data view so events and alerts can
be browsed as logs.
 
The web dashboard sits alongside this. It reads the same `ids-events` topic
through its own Kafka consumer group, so it sees live traffic without competing
with the detection service, and streams it to the browser over SSE on port 5000.


## Services

Brought up with `docker compose`. All services share the `ids-network`.

| Service         | Container       | Port(s)        | Role |
|-----------------|-----------------|----------------|------|
| `ids`           | `ids`           | —              | Runs the attack simulators + detection pipeline (`main.py`) |
| `web`           | `ids-web`       | `5000`         | Live web dashboard (benchmark control + live attack streams) |
| `ssh-server`    | `ssh-server`    | `2222`         | Target OpenSSH server for the SSH attacks |
| `http-server`   | `http-server`   | `8000`         | Target FastAPI server for the HTTP attacks |
| `kafka`         | `kafka`         | `9092`         | Message bus carrying the `ids-events` topic |
| `elasticsearch` | `elasticsearch` | `9200`         | Stores every event (`ids-events`) and alert (`ids-alerts`) |
| `kibana`        | `kibana`        | `5601`         | Data view over the Elasticsearch indices |

## Docker

### Build and run

Start the full pipeline (attacks + detection) and the dashboard:

```bash
docker compose up --build ids web
```

The dashboard is then available at `http://localhost:5000`.

### Rebuilding after code changes

The `ids` and `web` images copy the source in at build time (`COPY . .` in the
`Dockerfile`); the source is **not** bind-mounted. That means **any change to
the Python code requires rebuilding the image** — a plain `docker compose up`
or restart will keep running the previously built code.

Normal rebuild (uses Docker's layer cache — fast, reuses unchanged layers):

```bash
docker compose up --build ids web
```

Force a full rebuild (ignores the cache — use this when a change isn't being
picked up, e.g. edited source still running the old version):

```bash
docker compose build --no-cache ids web
docker compose up ids web
```

Verify the running container actually has your latest code:

```bash
docker compose exec ids grep -n "while True" sources/http/http_runner.py sources/ssh/ssh_runner.py
```

Stop and remove everything:

```bash
docker compose down
```

## Web dashboard

Served by the `web` service at `http://localhost:5000`. It holds one live
Server-Sent Events connection to the backend and shows two things:

- **Parallelization benchmark** — a *Start benchmark* button that runs the
  detection benchmark and streams the results into live throughput, processing
  time, and alert-count charts, plus a results table.
- **Live attack streams** — one console pane per attack worker, read from the
  `ids-events` Kafka topic and split by source and attack type (SSH brute
  force, SSH random password, HTTP brute force, HTTP credential stuffing, HTTP
  request flood, plus an *Unmatched* catch-all). Failed attempts render dim;
  a successful credential attempt renders as a highlighted green
  **✔ PASSWORD CRACKED / ACCESS GRANTED** line in that pane.

The dashboard's Kafka consumer uses its own unique consumer group and reads
from the latest offset, so it never competes with the detection consumer and
shows only live traffic from the moment the page is opened. The `ids` service
must be running for the panes to receive traffic.

## Attacks

The simulator runs five attack workers concurrently against the target
services:

| Source | Attack | Description |
|--------|--------|-------------|
| SSH  | `brute_force`         | Tries each password from `wordlists/passwords.txt` against the SSH user |
| SSH  | `random_password`     | Continuously tries randomly generated passwords |
| HTTP | `brute_force`         | Tries each wordlist password for a single username against `/api/auth/login` |
| HTTP | `credential_stuffing` | Tries the wordlist across several usernames against `/api/auth/login` |
| HTTP | `request_flood`       | Continuously floods `/api/health` with requests |

## Detection

Every event is evaluated against the active rule set. Each rule tracks
per-source-IP activity inside a time window and raises an alert when a
threshold is exceeded.

| Rule | Source | Fires when |
|------|--------|-----------|
| `brute_force`         | SSH  | Too many failed SSH auth attempts from one IP within the window |
| `http_brute_force`    | HTTP | Too many failed logins for one IP within the window |
| `credential_stuffing` | HTTP | Too many failed logins (across usernames) from one IP within the window |
| `request_flood`       | HTTP | Request rate from one IP exceeds the threshold within the window |

## HTTP API

The `http-server` service is a FastAPI application used as the target for the
HTTP attacks. Available on port `8000`.

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/`                | Returns basic API service information |
| `GET`  | `/api/health`      | Health check endpoint |
| `GET`  | `/api/data`        | Returns mock resource data |
| `POST` | `/api/auth/login`  | Authenticates a user using a username and password |

### Authentication

The `/api/auth/login` endpoint accepts a JSON request body:

```json
{
  "username": "admin",
  "password": "password"
}
```

It returns `200` on a valid username/password pair and `401` otherwise.

## Kibana

A Kibana **data view** connected to the IDS Elasticsearch indices is available
at `http://localhost:5601`. It surfaces the events and alerts the pipeline
writes to Elasticsearch (`ids-events` and `ids-alerts`) as browsable, filterable
**logs**, giving a persistent, queryable view of the traffic and detections to
complement the live web dashboard.

## Benchmark

The project includes a benchmark suite that compares the detection strategies
against a serial baseline across increasing event volumes.

### Running the benchmark

From the command line:

```bash
docker compose run --rm --no-deps ids python -m detection.benchmark
```

`--no-deps` skips starting the SSH/HTTP simulator and infrastructure
containers, since the benchmark runs against a generated synthetic corpus
rather than live traffic.

The benchmark can also be started from the web dashboard's *Start benchmark*
button, which streams the same results into live charts.

### What it measures

For each strategy, the benchmark replays synthetic event volumes
(1,000 → 100,000 events) and reports:

- **volume** — number of events processed in the run
- **time** — wall-clock time to process the batch (seconds)
- **throughput** — events processed per second (`volume / time`)
- **alerts** — number of alerts raised by that strategy

The synthetic corpus is fully seed-determined, so runs are reproducible. The
parallel strategies reuse a single process pool that is warmed before timing,
so measurements reflect detection work rather than pool-startup cost.

### Strategies compared

| Strategy | Description |
|---|---|
| `serial`         | Baseline: processes events one at a time, in order, with no parallelism. Ground truth for alert counts. |
| `batch`          | Partitions events by source IP and processes the partitions in parallel across a process pool. |
| `sliding_window` | Splits the event timeline into fixed-size, non-overlapping (tumbling) windows and processes each window in parallel. |