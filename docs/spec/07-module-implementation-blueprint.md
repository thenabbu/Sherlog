# 07 — Module implementation blueprint

This is the code-level map needed to recreate compatible modules.

## `sat_sa/schema.py`

Define string enums `Criticality`, `Severity`, and `Disposition` with the exact values listed in the data contract. Define Pydantic models `Entity`, `Asset`, `Alert`, `Case`, `Escalation`, and `Flag`.

All record models inherit a base configured as `extra="ignore"` and `use_enum_values=True`. `Alert` uses an after-model validator for chronology. `Flag.generated_at` defaults to UTC `datetime.now(timezone.utc)`. Export `SCHEMAS` mapping plural table names to models.

## `sat_sa/ingestion/core.py`

Expose:

```text
RawTable(frame: DataFrame, source: str, table_name: str | None)
FieldMapping(table_name: str, columns: dict[str, str])
load_csv(path, entity_hint=None) -> RawTable
load_json(path) -> RawTable
normalize(raw, mapping) -> (DataFrame, list[dict])
normalize_table(path, input_format, table_name=None) -> (DataFrame, list[dict])
```

`normalize` renames mapping columns, converts null/blank values to `None`, JSON-decodes CSV case `alert_ids`, validates every row, and returns serialised validated records plus reject dictionaries. It must not raise for ordinary bad rows; it raises only for an unsupported table.

## `sat_sa/synth/generator.py`

Expose in-memory `generate(...) -> dict[str, DataFrame]` for tests and disk-streaming `write_synthetic(...) -> dict[str, int]` for CLI use. The disk writer accepts an `on_progress(count) -> optional_next_batch_size` callback.

Generate entity IDs as `CSE-001` upward and asset IDs as `AST-001-1` upward. Give even zero-based entity indices peer group `finserv-tier2`/sector `financial`; odd indices `energy-tier2`/`energy`. Each CSE has two critical assets and one high asset. Use the exact probability distributions in source: severity `[.35,.35,.22,.08]`, disposition `[.22,.35,.35,.08]`, and category uniform over malware/intrusion/phishing/DoS. Reference time is 2026-08-30 12:00 UTC and regular created times are uniform over preceding 29 days.

Choose `max(1, round(n_entities × anomaly_rate))` distinct entity index sets independently for D1, D2, D3. Inject one 2-minute high true-positive escalated D1 alert and one eight-hour critical true-positive un-escalated D2 alert per selected entity. For D3-selected entities, exclude their first critical asset from normal alert asset selection. Save truth records separately.

## `sat_sa/peer/benchmark.py`

Implement the reusable `benchmark` function exactly as section 4 describes. It checks required columns and raises `ValueError` naming missing columns.

## `sat_sa/detectors/execution_gaps.py`

Implement `closure_baselines`, `detect_fast_closure`, and `detect_critical_no_escalation`. Construct local IDs first if useful, but `cli.detect` MUST renumber the combined flag list globally. Format durations as integer minutes below 60, otherwise one decimal hours.

## `sat_sa/detectors/negative_space.py`

Implement both a convenience data-frame detector and `detect_low_critical_asset_coverage_from_counts(counts, assets, reference, peer_stats=None, window_days=30, threshold_pct=.25)`. The latter permits the streaming CLI to avoid carrying alerts into memory.

## `sat_sa/evidence/core.py`

`attach_evidence(flag, source_records)` copies the evidence dictionary, resolves `alert_ids` against optional `alerts` DataFrame and `asset_ids` against optional `assets` DataFrame, and stores matching records in `evidence.source_rows`. Convert values with `isoformat` when available. Return a copied Flag rather than mutating the original.

## `sat_sa/scoring/core.py`

Export `DEFAULT_WEIGHTS` and `score_entities(flags, alert_volume_by_entity, weights=None)`. The entity universe is the union of volume-map keys and flagged entity IDs. JSON-encode the detector-count dictionary with sorted keys. Sort/rank exactly as section 4 states.

## `sat_sa/runtime.py`

Implement `SystemProfile`, `RuntimeSettings`, `RuntimeAdjustment`, `detect_system`, `_cpu_times`, `choose_runtime_settings`, `settings_dict`, and `AdaptiveController` per section 5. All dataclasses are frozen except the controller, whose changing state is intentional.

## `sat_sa/cli.py`

Create a Typer application with commands `generate-synth`, `ingest`, `detect`, `system-info`, `score`, `report`, `explain`, and `validate`. It owns output paths, console rendering, progress, process/thread executors, temporary directories, parquet appending, and JSON/CSV file writes. It must not embed detector/scoring calculations that belong in their own modules.

Use Rich progress only when console encoding is UTF-8; disable progress rendering for legacy encodings to avoid terminal failures. Preserve console status lines and elapsed timing to make large-run operations observable.
