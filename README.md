# SAT-SA CLI MVP

An offline-first Python library and CLI for supervising SOC alert/case-management submissions. It identifies execution gaps and negative space, ranks CSEs for manual review, and preserves the evidence that produced every finding.

For a replication-grade description of the implemented program, see [the specification set](docs/spec/README.md). It defines the data contracts, all command behaviour, detector equations, evidence/report formats, streaming/adaptive runtime policy, deployment, and test protocol.

## Air-gapped installation

Build/download dependency wheels on an approved connected build machine, transfer the source and wheelhouse into the NCIIPC environment, then install without an index:

```powershell
pip install --no-index --find-links=./wheelhouse -r requirements.txt
pip install --no-index --find-links=./wheelhouse -e .
```

There are no network calls, cloud services, SaaS dependencies, databases, or external models in SAT-SA.

## Demo pipeline

```powershell
satsa system-info
satsa generate-synth --entities 25 --alerts-per-entity 400 --seed 42 --batch-size 0 --out data/synth
satsa ingest --input data/synth --format csv --batch-size 0 --workers 0 --out data/normalized
satsa detect --data data/normalized --detectors execution_gaps,negative_space --config detector_config.yaml --batch-size 0 --workers 0 --out results/flags.json
satsa score --flags results/flags.json --config detector_config.yaml --out results/entity_scores.csv
satsa report --scores results/entity_scores.csv --flags results/flags.json --format table --out results/report.json
satsa validate --flags results/flags.json --synth-ground-truth data/synth/ground_truth.parquet
```

## Supervisory workbench UI

The optional Streamlit interface is a presentation layer over the same local artifacts and CLI implementation; it does not duplicate analytics. Install the declared dependencies, then run:

```powershell
streamlit run app.py
```

The UI keeps each showcase in `runs/<run-name>/`. On its **Run assessment** page, choose either a synthetic preset or upload the five CSV exports; one Start action automatically validates, analyses, ranks, and publishes the local result set for review.

`generate-synth` produces both CSV (for the explicit ingestion stage) and parquet. Ground truth is only used by `validate`; detectors never read it.

## Large submissions

`generate-synth`, CSV `ingest`, and `detect` process alerts in bounded batches and display progress plus elapsed time. Passing `--batch-size 0 --workers 0` (the default) detects local CPU count and currently available RAM, then starts aggressively: 10,000 rows below 1 GB free RAM, 50,000 below 4 GB, 100,000 below 8 GB, otherwise 200,000. It uses up to 12 workers (CPU count minus two) whenever at least 768 MB is available. Run `satsa system-info` to inspect the choice before starting a large job.

Adaptive mode is enabled by default. Every four completed batches (`--healthcheck-interval`) SAT-SA checks currently available RAM, host CPU, and recent throughput locally. Under pressure it halves the next batch and reduces admitted workers; with sustained headroom it grows the next batch by up to 25% and increases parallel admission. Use `--no-adaptive` for fixed, previous-style batch and worker settings. Explicit `--batch-size`/`--workers` values are initial values; adaptive mode may change them. Its lower batch bound is `min(1,000, initial batch size)`.

The CLI does **not** hold the complete alert dataset in memory: generation writes each batch directly to CSV/parquet; ingestion validates and writes each CSV chunk as a parquet row group, with a bounded process pool; detection makes two parquet scans and retains only closure-duration statistics on temporary disk, per-entity/asset counters, and resulting flags. Independent execution-gap detectors run concurrently within each batch when more than one worker is selected. For very large data, use CSV inputs (standard JSON arrays are still loaded as one document; NDJSON support is a future enhancement).

## Data contract

The CSV/JSON table files are named `entities`, `assets`, `alerts`, `cases`, and `escalations`, and use the fields defined in `sat_sa/schema.py`. Every input row is Pydantic-validated. Invalid rows appear, with source, row number, original record, and validation error, in `rejects.json` rather than being silently ignored.

## Included MVP signals

- Fast closure: IQR lower-fence outliers among high/critical alerts.
- Critical true-positive without escalation: direct, explainable rule.
- Low critical-asset coverage: recent alert counts under 25% of the peer-cohort median.
- Peer benchmarking: reusable median, Q1/Q3/IQR, and percentile calculations.

Each flag has its detector, entity, rationale, exact source IDs, baseline values, and embedded source rows. Entity risk is weighted flag count divided by `log(1 + alert volume)`; ties prefer broader weakness across detector types.

## Quality checks

```powershell
pytest
rg -n "requests|urllib|socket" sat_sa
```

The second check is the proposed offline-deployment lint gate: it should return no results.
