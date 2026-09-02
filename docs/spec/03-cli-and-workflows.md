# 03 — CLI and operating workflows

## 1. Invocation

The installed entry point is `satsa`, mapped to `sat_sa.cli:app`. From an activated Windows virtual environment, use `satsa ...`. Without activating it, use `& .\.venv\Scripts\satsa.exe ...`.

All operational examples below are intentionally one-line PowerShell commands.

## 2. `system-info`

```powershell
satsa system-info
```

Optional `--batch-size N` and `--workers N` show how those requested values would be used. The command prints JSON containing logical CPU count, total/available RAM in MB, platform name, selected batch size, and selected workers.

## 3. `generate-synth`

```powershell
satsa generate-synth --entities 40 --alerts-per-entity 50000 --seed 42 --anomaly-rate 0.15 --batch-size 0 --adaptive --healthcheck-interval 4 --out large_run\synth
```

Arguments:

| Option | Default | Meaning |
|---|---:|---|
| `--entities` | 25 | minimum 4; number of CSEs |
| `--alerts-per-entity` | 400 | minimum 1; baseline alerts per CSE |
| `--seed` | 42 | NumPy random seed |
| `--anomaly-rate` | 0.15 | 0.01–1.0; CSE share injected per anomaly type |
| `--batch-size` | 0 | 0 selects runtime policy; positive is initial row count |
| `--adaptive/--no-adaptive` | adaptive | turn health-based resizing on or off |
| `--healthcheck-interval` | 4 | completed batches between health checks |
| `--out` | `data/synth` | output directory |

The total alerts written are `entities × alerts_per_entity + 2 × round(entities × anomaly_rate)` (with the rounded anomaly count at least one). The two additions per selected entity are fast-closure and no-escalation injections; low coverage changes asset selection and does not add an alert.

## 4. `ingest`

```powershell
satsa ingest --input large_run\synth --format csv --batch-size 0 --workers 0 --adaptive --healthcheck-interval 4 --out large_run\normalized
```

`--input` is required and may be a table file or directory. `--format` defaults to CSV. CSV is incrementally parsed and validated. JSON is accepted but loaded as one document. `--workers` is the initial number of process-pool validation workers; automatic selection is 0. Results and rejects follow the storage contract.

## 5. `detect`

```powershell
satsa detect --data large_run\normalized --detectors execution_gaps,negative_space --config detector_config.yaml --batch-size 0 --workers 0 --adaptive --healthcheck-interval 4 --out large_run\results\flags.json
```

`--data` must contain normalized `alerts.parquet`, `assets.parquet`, and `entities.parquet`. Valid detector group names are `execution_gaps` and `negative_space`; comma-separate them. Invalid names produce an argument error.

The command writes `flags.json` and an adjacent `alert_volumes.json`. Its input configuration defaults are `fast_closure_k=1.5`, `coverage_window_days=30`, and `coverage_threshold_pct=0.25`; schema-compatible relationship/peer rules additionally use `investigation_duration_k=1.5`, `low_entity_activity_pct=0.25`, `recurrence_min_alerts=3`, `workload_deviation_pct=0.5`, and `min_peer_sample=4`. Keys supplied by YAML override those defaults. Detection streams alert batches while loading compact cases and escalations and retaining bounded counters for recurrence and workload analysis.

## 6. Score, report, explain, and validate

```powershell
satsa score --flags large_run\results\flags.json --config detector_config.yaml --out large_run\results\entity_scores.csv
```

`score` reads adjacent `alert_volumes.json` when it exists; otherwise every entity has volume zero. YAML `weights` overrides default scoring weights.

```powershell
satsa report --scores large_run\results\entity_scores.csv --flags large_run\results\flags.json --format table --out large_run\results\report.json
```

`--format` accepts `table` or `json`. Both modes write report JSON; table mode additionally prints rank, risk, and the first two reasons per entity.

```powershell
satsa explain --entity-id CSE-001 --flags large_run\results\flags.json
```

`explain` writes all matching findings and their evidence to the console. It exits with code 1 if no matching finding exists.

```powershell
satsa validate --flags large_run\results\flags.json --synth-ground-truth large_run\synth\ground_truth.parquet
```

`validate` accepts parquet or CSV ground truth and prints injected count, detected count, precision, recall, and F1 by detector.

## 7. Fixed versus adaptive workflow

Adaptive mode is the default and should be used for unknown or changing workloads. `--no-adaptive` preserves the chosen initial batch size and worker count for the whole command.

```powershell
satsa ingest --input large_run\synth --format csv --batch-size 50000 --workers 12 --no-adaptive --out large_run\normalized
```

Use a new `--out` directory or ensure no process is using old outputs before repeating a run. The implementation overwrites named parquet/reject output files; it is not a resumable pipeline.
