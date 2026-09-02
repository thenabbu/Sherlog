# 05 — Streaming, parallelism, and adaptive runtime contract

## 1. Goal

Large runs must use the host assertively without retaining an entire multi-million-alert dataset in RAM. SAT-SA combines disk-backed parquet row groups, bounded queues, temporary binary statistics, and a host-local controller that changes future work admission as conditions change.

No telemetry leaves the host. No `psutil`, cloud metrics agent, network request, or external service is used.

## 2. System profile collection

`detect_system()` returns:

```text
logical_cpus          max(1, os.cpu_count() or 1)
available_memory_mb   available physical bytes / 1,048,576
total_memory_mb       total physical bytes / 1,048,576
platform              os.name
```

On Windows, available and total physical memory are obtained via `GlobalMemoryStatusEx`. CPU load is derived from deltas of `GetSystemTimes` idle/kernel/user counters. On POSIX systems, memory uses `SC_AVPHYS_PAGES`, `SC_PHYS_PAGES`, and `SC_PAGE_SIZE`; CPU counter sampling is currently unavailable and is represented as null.

## 3. Aggressive initial policy

`0` means automatic for `--batch-size` and `--workers`.

| Available physical memory | Initial automatic batch size |
|---:|---:|
| under 1,024 MB | 10,000 |
| 1,024–4,095 MB | 50,000 |
| 4,096–8,191 MB | 100,000 |
| 8,192 MB or higher | 200,000 |

Automatic workers are one below 768 MB free, otherwise `min(12, max(2, logical_cpus - 2))`. This intentionally favours throughput. Available RAM alone is not a reliable indicator of safe demand because Windows file cache and reclaimable pages reduce the reported number during I/O-heavy work.

Explicit positive values override the initial policy. `--no-adaptive` makes them fixed for the entire command.

## 4. Adaptive controller state and interval

`AdaptiveController` owns `batch_size`, `workers`, `min_batch_size`, `check_every_batches`, a previous CPU sample, and a high-water throughput estimate.

- It is called after every completed batch but takes action only every `healthcheck_interval` batches (default 4).
- It receives records completed and elapsed seconds. Throughput is `records / elapsed_seconds`.
- It retains the highest observed throughput. A new sample is called regressed only when it is below 60% of this high-water value.
- High CPU alone is productive work and is not a reason to reduce demand.

### Backoff rule

Back off when either condition is true:

```text
available_memory_mb < 512
```

or:

```text
available_memory_mb < 1024
AND cpu_pct > 98
AND throughput < 60% of the previous high-water mark
```

Backoff applies:

```text
batch_size = max(min_batch_size, floor(batch_size / 2))
workers = max(1, workers - 1)
```

`min_batch_size = min(1000, initial_batch_size)`. Thus an initial 50,000-row run may shrink as far as 1,000 rows; an explicit 500-row run never drops below 500.

### Growth rule

When no backoff condition applies, free RAM is at least 768 MB, and CPU is either unavailable or below 98%, the controller grows if batch or workers are below the current ceiling:

```text
batch_size = min(ceiling, max(batch_size + 1000, floor(batch_size × 1.25)))
workers = min(worker_ceiling, workers + 1)
```

Batch ceiling by current available RAM:

| Available RAM | Ceiling |
|---:|---:|
| under 1,024 MB | 50,000 |
| 1,024–4,095 MB | 100,000 |
| 4,096–8,191 MB | 200,000 |
| 8,192 MB or higher | 500,000 |

Worker ceiling is one below 768 MB, otherwise `min(12, max(2, logical_cpus - 2))`.

Every adjustment is printed with reason, available RAM, CPU percentage, old/new batch sizes, and old/new workers.

## 5. Synthetic generation memory behaviour

Generation creates a DataFrame for the current alert batch only. `_BatchWriter` appends it to `alerts.csv` and to an Arrow `ParquetWriter` using a fixed alert schema, then releases the previous batch. Entity metadata, asset metadata, and ground truth are small lists proportional to CSE count.

The callback after each batch returns the controller's current batch size, so the next synthetic batch uses it. Output writing is single-writer to maintain a valid CSV and parquet file.

## 6. CSV ingestion memory and parallelism

The CSV reader is a `csv.DictReader`. It fills a list of at most `controller.batch_size` rows, makes one DataFrame, and submits it to `_normalize_chunk`.

- The worker function row-validates that batch using Pydantic and returns accepted DataFrame plus rejects.
- Accepted data is immediately written as a parquet row group by `_ParquetAppender`.
- At most the currently admitted worker count of work items is pending.
- Adaptive mode creates a process pool with four available processes, while the controller controls how many batches are admitted concurrently. Fixed mode creates exactly the requested worker count.
- In adaptive mode, a future increase in admitted worker count can use previously idle processes without restarting the pool.

The main process writes parquet and `rejects.json` so file output remains ordered by submitted chunks. A slow first submitted chunk can therefore hold later completed chunks until it is written; this is intentional to preserve source order.

## 7. Detection memory and parallelism

`alerts.parquet` is scanned by Arrow row group. At the start of each row group, the current controller batch size is read; that size is used for Arrow batches in that row group.

Pass 1 appends only float64 closure durations to per-severity temporary binary files. Quantiles are computed with NumPy memory maps, so the multi-million-duration data remains disk-backed.

Pass 2 has one pandas alert batch resident. When worker admission is above one, D1 and D2 execute through a two-thread executor over the same immutable batch, avoiding a second process copy. D3 retains only a `Counter[(entity_id, asset_id)]`; it runs after the scan from that compact aggregate.

## 8. Operational expectations

For a 16 logical CPU host with 1–4 GB currently free, automatic mode starts at 50,000 rows and 12 workers. It can grow sequential generation/detection chunks toward 100,000 rows. The observed workload remains subject to disk performance, antivirus scanning, concurrent desktop workload, page-file pressure, and source data shape.

An operator SHOULD watch adjustment messages. Repeated backoff indicates that a lower fixed `--batch-size`/`--workers` setting may be more predictable. For a reproducible benchmark, use explicit values plus `--no-adaptive`.
