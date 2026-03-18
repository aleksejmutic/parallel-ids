# parallel-ids

A parallelized intrusion detection system built in Python. Simulates realistic network attack scenarios across multiple protocols and log sources, detects threats using six detection rules, and benchmarks four different processing strategies — serial, parallel by rule type, parallel batch, and parallel time windows — to compare detection performance at scale.

## What it does

The system has two main parts. The **simulator** generates realistic log traffic across SSH authentication logs, HTTP access logs, Linux syscall traces, Windows event logs, and network flow data. It includes seven attack scenarios: brute force, distributed brute force, invalid user enumeration, credential stuffing, port scanning, slow-and-low evasion, and normal background traffic.

The **detection engine** reads those events and applies six rules across four processing strategies simultaneously, measuring throughput and alert accuracy for each. A Flask dashboard visualizes the results live, streams pipeline output as it runs, and displays scaling charts showing where parallelism becomes advantageous over sequential processing.

## Stack

Python · SQLite · Flask · Docker · Kafka  · Elasticsearch

## Run it

```bash
pip3 install flask
python3 app.py
```

Open `http://localhost:5000` and click **Run full IDS pipeline**
