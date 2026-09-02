# 01 — Product and architecture

## 1. Objective

SAT-SA (Supervisory Analytics Tool for SOC Assessment) analyses periodic, structured submissions from multiple Critical Sector Entities (CSEs). It helps a supervisor decide which entity, asset, alert, or process merits manual inspection. It provides evidence for the decision; it does not make supervisory decisions on its own.

The MVP identifies three deliberately explainable signals:

- unusually fast closure of high/critical alerts;
- a critical true-positive closed with no recorded escalation;
- unusually low alert activity from a critical asset relative to its peer cohort.

The tool ranks entities using the findings and produces a compact, portable evidence trail.

## 2. Architectural rules

1. All analytics MUST be local and make no runtime network call.
2. Data MAY be large; generation, CSV ingestion, and parquet detection MUST use bounded batches rather than loading all alerts in memory.
3. Every invalid input row MUST be preserved in a rejects audit file with its source, row index, raw values, and validation failure.
4. Every flag MUST stand on its own: detector, entity, rationale, source IDs, measurements, baseline, and generation time are stored in the flag JSON.
5. The CLI only orchestrates work. Detector, scoring, benchmark, evidence, schema, and runtime modules remain independently importable.
6. The normal output is advisory. A flag is a prioritisation signal, never proof of misconduct or an automatic enforcement outcome.

## 3. Component flow

```text
periodic CSV / JSON submissions
            |
            v
schema validation + rejects audit -----> rejects.json
            |
            v
normalized parquet tables
            |
            +--> pass 1: closure-duration baselines on temporary disk
            +--> pass 2: execution-gap findings and asset counters
            |                         |
            +-------------------------v
                    evidence-attached flags.json
                               |
                               v
               risk scoring / priority ranking / report / explain
```

## 4. Package and source layout

```text
pyproject.toml                   packaging and `satsa` entry point
requirements.txt                 deployable runtime requirements
detector_config.yaml             default detector weights and thresholds
sat_sa/
  schema.py                      Pydantic contracts and Flag object
  cli.py                         Typer commands and IO orchestration
  runtime.py                     resource detection and adaptive controller
  ingestion/core.py              loader and row-validation functions
  synth/generator.py             deterministic, batched test-data generator
  peer/benchmark.py              reusable cohort statistics
  detectors/execution_gaps.py    D1 and D2
  detectors/negative_space.py    D3
  evidence/core.py               source-row attachment
  scoring/core.py                entity ranking formula
tests/test_core.py               regression tests
docs/spec/                       this specification set
```

## 5. Technology requirements

| Role | Required package |
|---|---|
| command interface | `typer` |
| tabular processing | `pandas`, `numpy` |
| parquet read/write and batched scanning | `pyarrow` |
| validation / serialisation | `pydantic` v2 |
| terminal reporting / progress | `rich` |
| YAML configuration | `PyYAML` |
| tests | `pytest` |

Python 3.10 or later is required. The reference project specifies pandas 2+, NumPy 1.24+, Pydantic 2+, Typer 0.12+, Rich 13+, PyArrow 14+, and PyYAML 6+.

## 6. Boundary conditions and known constraints

- CSV is the scalable input format. The normal JSON reader loads a complete JSON document and is therefore unsuitable for huge JSON arrays. NDJSON is not yet implemented.
- `ingest` requires all five input tables, even if `cases` and `escalations` are valid empty files.
- The synthetic generator is deterministic for the same parameters and seed.
- The detector result list is held in memory. This is safe for the intended sparse supervisory signals; a future high-flag-rate deployment SHOULD stream flags to a newline-delimited or parquet result store.
- The generator has one parquet/CSV writer and generates alert rows in Python; adaptive sizing changes its memory envelope, not its number of generator processes.
