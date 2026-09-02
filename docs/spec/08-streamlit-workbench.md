# 08 — Streamlit demonstration workbench

## Purpose

`app.py` is the native Streamlit demonstration layer for the SAT-SA CLI. It does not duplicate analytics: it invokes `sys.executable -m sat_sa.cli` and reads the same ordinary local artifacts produced by the CLI. Its job is to show an examiner, SIH evaluator, or stakeholder the complete periodic supervisory workflow from source files to evidence-led results.

Start it with one command:

```powershell
streamlit run app.py
```

## Demonstration flow

Streamlit's built-in navigation contains these pages in order:

1. **Run assessment:** has two routes—synthetic multi-CSE presets or five uploaded CSV exports—and one Start action that automatically validates, analyses, scores, and publishes.
2. **Review results:** presents the priority queue, enhanced risk/signal charts, record-level evidence, and optional synthetic validation.
3. **How it works:** gives the concise supervisory/process explanation for demos.

The sidebar holds only the run name, workflow status, refresh action, and navigation. Every run writes inside `runs/<sanitised run name>/` with `source`, `normalized`, and `results` children so separate demos cannot overwrite one another.

## Synthetic presets

| Preset | CSEs | Baseline alerts | Intended use |
|---|---:|---:|---|
| Default — small demonstration | 8 | 8,000 | live presentation |
| Medium — departmental assessment | 20 | 200,000 | multi-CSE assessment |
| Large — supervisory batch | 40 | 2,000,000 | scalability demonstration |
| Gigantic — national-scale rehearsal | 100 | 10,000,000 | capacity rehearsal |

The user may alter CSE count, alerts per CSE, anomaly rate, seed, and adaptive runtime setting after selecting a preset. The controls execute `generate-synth`; analytics remain unchanged.

## Native Streamlit controls

The workbench relies on Streamlit's built-in navigation, metrics, radio/segmented choice, expander, toggle, file uploader, button, status container, progress-capable CLI log, tabs, multi-select filters, dataframe, bar chart, JSON viewer, and bordered containers. It relies on Streamlit's own light/dark theme rather than forcing light information cards, so text contrast remains correct in dark mode. There is no separate custom frontend framework or remote asset.

## Intake and analytics

The intake page requires `entities.csv`, `assets.csv`, `alerts.csv`, `cases.csv`, and `escalations.csv`. It copies uploaded files to the current run and only enables validation after every logical table is present. Validation launches the original CSV `ingest` command.

The analytics page exposes the three signal descriptions, an adaptive-runtime toggle, then runs `detect`, `score`, and JSON `report` in sequence. Status containers show live captured CLI output and final elapsed time/error state.

## Results page

The results page loads current-run `flags.json` and `entity_scores.csv`. It shows native metrics, the ranked CSE queue, detector-volume chart, filters, and expandable finding evidence. Each finding exposes its rationale, evidence summary, and exact source row attached by the CLI. Synthetic runs also provide the CLI `validate` action; real submissions explain that validation must be against independent examiner findings.

## Safety constraints

- Pipeline invocation uses argument lists, never shell interpolation.
- The UI is periodic and manually refreshed; it does not poll or imply real-time monitoring.
- No remote fonts, API calls, cloud services, or hosted models are required by `app.py`.
- User-created run names are sanitised to 64-character `A–Z`, `a–z`, `0–9`, underscore, and hyphen names before any filesystem path is created.
