# IDS - Intrusion Detection System

IDS including a Network Telemetry Simulator that generates SSH, HTTP, and system call events, and normalizes them into a unified structured format for use in data pipelines, streaming systems, and security analysis.

## Docker

### Build and run

```bash
docker compose up --build ids


## Benchmark

The project includes a benchmark suite that compares detection strategies against a serial baseline across increasing event volumes.

### Running the benchmark

```bash
docker compose run --rm --no-deps ids python -m detection.benchmark
```

`--no-deps` skips starting the SSH/HTTP simulator containers, since the benchmark runs against generated/replayed event data rather than live traffic.

### What it measures

For each strategy, the benchmark replays synthetic event volumes (1,000 → 100,000 events) and reports:

- **volume** — number of events processed in the run
- **time** — wall-clock time to process the batch (seconds)
- **alerts** — number of alerts raised by that strategy
- **throughput** — events processed per second (`volume / time`)

### Strategies compared

| Strategy | Description |
|---|---|
| `serial` | Baseline: processes events one at a time, in order, no parallelism |
| `batch` | Partitions events (e.g. by IP) and processes partitions in parallel |
| `sliding_window` | Maintains overlapping time windows for stateful detection, processed with some parallelism |