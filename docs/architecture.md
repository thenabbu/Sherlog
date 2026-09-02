# SAT-SA MVP architecture (two-page design note)

## Purpose

SAT-SA is a deployable, offline supervisory analytics capability for periodic SOC submissions. It supports examiner judgement; it is not a SOC, SIEM, real-time monitor, central log collector, or automated enforcement system.

## Flow and controls

```text
CSV / JSON submission → validation + rejects audit → normalized local parquet
                                             ↓
                 peer benchmarks → execution-gap / negative-space detectors
                                             ↓
                  self-contained flags → entity risk rank → JSON/table/explain
```

`sat_sa/schema.py` is the single data contract. Pydantic validates every row before it reaches analytics; malformed records are retained in `rejects.json` with their original content and error reason. Detector functions are pure and do not access files, the network, or CLI state. `cli.py` is orchestration only, enabling a future GUI to reuse the same logic without duplication.

## MVP analytics and explainability

| Signal | Supervisory question | Method | Evidence |
|---|---|---|---|
| Fast closure | Are high-impact alerts being closed without meaningful investigation? | Severity-specific Q1 − 1.5×IQR lower fence | alert ID, closure time, Q1, IQR, sample size |
| No escalation | Was a critical true-positive closed without recorded escalation? | Direct deterministic rule | alert ID, disposition, closed time |
| Low coverage | Does a critical asset show a possible monitoring blind spot? | 30-day observed count <25% of peer critical-asset median | asset ID, window, observed count, cohort median |

The reusable peer module returns cohort median, Q1/Q3/IQR and percentile ranks. Findings contain a plain-English rationale, source IDs, baselines, generated time, and compact source rows, allowing report-to-record drill down. Entity score is `Σ(weight × flags) / log(1 + alert volume)`; ties favour detector diversity. Default weights are 2, 3, and 2 respectively.

## Deployment and operating requirements

The MVP runs local Python, pandas, Pydantic, Typer, Rich, PyArrow, NumPy and PyYAML. It requires no database, cloud identity, SaaS, hosted model, or runtime Internet access. For an air-gapped environment, dependencies are staged as a vetted wheelhouse and installed with `pip --no-index`. `satsa system-info` detects logical CPUs, total RAM, and available RAM locally; automatic batch sizing starts at 10,000–200,000 records and bounded validation concurrency uses up to 12 workers (CPU count minus two). Adaptive mode checks available RAM, host CPU, and recent throughput every four batches: it halves batches/reduces admitted workers only on critically low memory or a sustained throughput collapse under saturation, and cautiously grows batches/increases admission when headroom is sustained. `--no-adaptive` fixes the chosen batch and worker values. CSV ingestion and parquet detection are batch-streamed: raw records are never all resident in memory. Detection stores only temporary closure-duration values on local disk plus small counters and findings. Parquet maintains local, portable intermediate datasets.

## Validation

In the absence of an official dataset, the deterministic synthetic generator injects known fast-closure, no-escalation and low-coverage conditions at a controlled entity rate. Ground truth is saved separately and detectors are blind to it. `satsa validate` calculates precision, recall and F1 by exact alert/asset key. Before deployment, replay anonymised samples independently assessed by NCIIPC examiners; compare detector prioritisation and false-positive rates against the expert findings, tune documented thresholds, and retain each configuration with resulting reports for audit.
