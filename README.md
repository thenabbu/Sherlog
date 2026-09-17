# Sherlog

**Supervisory Analytics Tool for SOC Assessment** — an offline-first Python toolkit for auditing SOC alert and case-management submissions. Sherlog identifies execution gaps and negative space in security operations, ranks entities for manual review, and preserves full evidence trails for every finding.

## Features

- **13 detection rules** across two engines — execution gaps (D1–E11) and negative space (N1–N4)
- **Offline & air-gapped** — zero network calls, no cloud services, no external dependencies
- **Bounded-memory streaming** — processes millions of alerts without loading them into RAM
- **Adaptive runtime** — auto-tunes batch size and worker count based on available CPU/RAM
- **Evidence-attached findings** — every flag carries rationale, baselines, and source rows
- **Interactive Streamlit workbench** — portfolio triage, entity profiles, peer benchmarking, review queue, report generation
- **CLI + library** — `satsa` console script or `python -m sat_sa.cli` for pipeline automation

## Quick Start

```bash
# Install
pip install -r requirements.txt
pip install -e .

# Run the CLI
satsa generate-synth --entities 25 --alerts-per-entity 400 --seed 42
satsa ingest --input runs/synth/source --format csv
satsa detect --data runs/synth/normalized --detectors execution_gaps,negative_space
satsa score --flags runs/synth/results/flags.json
satsa report --scores runs/synth/results/entity_scores.csv --flags runs/synth/results/flags.json

# Launch the workbench
streamlit run app.py
```

## Docker

```bash
docker build -t sherlog .
docker run --rm -p 8501:8501 -v sherlog-runs:/app/runs sherlog
```

Or with Docker Compose:

```bash
docker compose up --build -d
```

The `runs/` volume persists assessment artifacts across container restarts. The image has no runtime network dependency — only the browser needs access to port 8501.
## Vercel (Demo)

The Streamlit UI is also deployed as a read-only demo on Vercel:

- **https://sherlog-sih.vercel.app/**

The Vercel build uses `api.py` → `streamlit.starlette.App("app.py")` as an ASGI entrypoint. The demo renders the full workbench UI but cannot run assessments (no persistent filesystem in serverless). Use the Docker or local install for full functionality.


## Supervisory Workbench

The Streamlit UI (`app.py`) is a presentation layer over the CLI — it never duplicates analytics. Pages include:

- **Run assessment** — Generate synthetic data or upload CSV submissions
- **Portfolio overview** — Cross-entity triage with risk scores, sparklines, filters
- **Entity profile** — Deep-dive into one entity — alerts, coverage, findings, history
- **Findings feed** — All flagged findings split by engine (EG / NS), with filters
- **Peer benchmarking** — Sector-scoped box plots and percentile rankings
- **Review queue** — Examiner's prioritized to-do list
- **Data health** — Submission completeness matrix and ingestion quality
- **Rules in effect** — Read-only view of all detector rules and thresholds
- **Report center** — Markdown/HTML/CSV/JSON report generation with export
- **How it works** — Pipeline diagram, host profile, synthetic validation

Deep links: `?page=findings&run=<name>&entity=CSE-003&finding=fg_00012`

## Air-Gapped Installation

On an approved connected build machine, download dependency wheels, then transfer source + wheelhouse:

```bash
pip download -r requirements.txt -d wheelhouse/
# Transfer wheelhouse/ and repo to the air-gapped host
pip install --no-index --find-links=./wheelhouse -r requirements.txt
pip install --no-index --find-links=./wheelhouse -e .
```

## Architecture

```
app.py (Streamlit UI)
  └── sat_sa/
        ├── cli.py          — Typer CLI orchestration
        ├── schema.py       — Pydantic data contracts
        ├── ingestion/      — CSV/JSON → Parquet normalization
        ├── detectors/
        │   ├── execution_gaps.py  — D1 fast closure, D2 no escalation, E1–E11
        │   ├── negative_space.py  — D3 low coverage, N1–N4
        │   └── registry.py        — Detector registry + grouping
        ├── evidence/       — Source row attachment
        ├── peer/           — Peer cohort statistics
        ├── scoring/        — Entity risk scoring + ranking
        ├── synth/          — Deterministic synthetic data generator
        └── runtime.py      — Adaptive batch/worker tuning
```

For a detailed specification set, see [docs/spec/](docs/spec/).

## Data Contract

Input CSV/JSON files: `entities`, `assets`, `alerts`, `cases`, `escalations`. Every row is Pydantic-validated; invalid rows go to `rejects.json` with source, row number, and error message.

## Large Submissions

Pass `--batch-size 0 --workers 0` (the default) to auto-detect optimal settings based on CPU count and available RAM. Adaptive mode (default) adjusts batch size and worker count dynamically under memory pressure. Use `--no-adaptive` for reproducible fixed settings.

## Testing

```bash
pytest
```

## License

MIT
