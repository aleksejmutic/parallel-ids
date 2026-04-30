# parallel-ids

A parallelized intrusion detection system built in Python. Simulates realistic network attack scenarios across multiple protocols and log sources, detects threats using six detection rules, and benchmarks four different processing strategies — serial, parallel by rule type, parallel batch, and parallel time windows — to compare detection performance at scale.

## What it does

The system has two main parts. The **simulator** generates realistic log traffic across SSH authentication logs, HTTP access logs, Linux syscall traces, Windows event logs, and network flow data. It includes seven attack scenarios: brute force, distributed brute force, invalid user enumeration, credential stuffing, port scanning, slow-and-low evasion, and normal background traffic.

The **detection engine** reads those events and applies six rules across four processing strategies simultaneously, measuring throughput and alert accuracy for each. A Flask dashboard visualizes the results live, streams pipeline output as it runs, and displays scaling charts showing where parallelism becomes advantageous over sequential processing.

## Stack

Python · SQLite · Flask · Docker · Kafka  · Elasticsearch

## Run with Docker (Kafka + Zookeeper)

First start Docker:

```bash
docker-compose up -d
```

This will start:
- Zookeeper
- Kafka broker

Kafka will be available on:
- `localhost:9092` (host access)
- `kafka:9092` (inside Docker network)

---

## Running the Simulation (SSH Attack Generator)

The SSH simulator is a standalone script that publishes events into Kafka.

### 1. Start the Kafka consumer (run first)

```bash
python3 -m kafka_local.consumer
```

> This must be run as a module (`-m`) because `kafka_local` is a Python package and relies on package imports (e.g. `shared.schema`, `topics`, etc.).

---

### 2. Start the SSH simulator (run second)

```bash
python3 simulator/ssh_simulator.py
```

> This is run as a direct script because it is designed as an executable entrypoint and already uses local imports relative to the project structure.

---

## What happens

- Simulator generates SSH attack + normal traffic logs
- Producer sends events to Kafka topic `raw-events`
- Consumer reads events and prints them in real-time

## Running the app

```bash
pip3 install flask
python3 app.py
```

Open `http://localhost:5000` and click **Run full IDS pipeline**
