# 02 — Data and storage contract

## 1. Submission file set

An input directory for CSV ingestion MUST contain exactly these logical tables, named with these stems:

```text
entities.csv       assets.csv       alerts.csv
cases.csv          escalations.csv
```

The matching parquet form uses `.parquet` instead. Extra files are skipped with a warning. `ground_truth.csv` and `ground_truth.parquet` are deliberately ignored by ingestion; they are reserved for synthetic validation.

The CLI accepts `--format csv` or `--format json`. A single file is accepted only if its filename stem matches a supported logical table.

## 2. Entity table

| Field | Required | Type | Rules |
|---|---:|---|---|
| `entity_id` | yes | string | CSE identifier; used as join/ranking key |
| `name` | yes | string | human-readable CSE name |
| `peer_group` | yes | string | benchmarking cohort, such as sector/size group |
| `sector` | no | string/null | optional metadata |

## 3. Asset table

| Field | Required | Type | Rules |
|---|---:|---|---|
| `asset_id` | yes | string | asset identifier |
| `entity_id` | yes | string | logical FK to entities |
| `criticality` | yes | enum | `critical`, `high`, `medium`, or `low` |
| `asset_type` | no | string/null | descriptive asset class |

## 4. Alert table

| Field | Required | Type | Rules |
|---|---:|---|---|
| `alert_id` | yes | string | alert identifier |
| `entity_id` | yes | string | logical FK to entity |
| `asset_id` | no | string/null | logical FK to asset |
| `category` | yes | string | e.g. malware, intrusion, phishing, DoS |
| `severity` | yes | enum | `critical`, `high`, `medium`, or `low` |
| `created_at` | yes | ISO datetime | alert creation time |
| `first_ack_at` | no | ISO datetime/null | acknowledgement time |
| `closed_at` | no | ISO datetime/null | closure time |
| `disposition` | yes | enum | `true_positive`, `false_positive`, `benign`, or `unresolved` |
| `escalated` | yes | boolean | accepts Pydantic boolean coercion for CSV strings |
| `escalated_at` | no | ISO datetime/null | escalation time |
| `case_id` | no | string/null | logical FK to case |

For a valid alert, `closed_at`, when present, MUST not be earlier than `created_at`; the same rule applies to `escalated_at`.

## 5. Case and escalation tables

### Cases

| Field | Required | Type |
|---|---:|---|
| `case_id` | yes | string |
| `entity_id` | yes | string |
| `opened_at` | yes | ISO datetime |
| `closed_at` | no | ISO datetime/null |
| `alert_ids` | yes | array of strings |
| `root_cause_documented` | yes | boolean |

In CSV, `alert_ids` MUST be a JSON array string, for example `"[\"AL-000001\", \"AL-000002\"]"`.

### Escalations

| Field | Required | Type |
|---|---:|---|
| `escalation_id` | yes | string |
| `alert_id` | yes | string |
| `escalated_at` | yes | ISO datetime |
| `escalated_to_tier` | yes | string |

## 6. Validation semantics

Pydantic v2 models validate each row. Unknown input columns are ignored, not rejected. Empty cells, whitespace-only strings, and pandas missing values become null before validation. An invalid row is not included in the normalized table.

Each reject entry is:

```json
{
  "source": "submission/alerts.csv",
  "table": "alerts",
  "row": 41,
  "reason": [{"loc": ["closed_at"], "msg": "...", "type": "..."}],
  "record": {"alert_id": "AL-041", "...": "original cleaned values"}
}
```

The `row` value is the zero-based index within the processed DataFrame chunk. For very large CSV inputs it is therefore chunk-local, not an absolute source line number; `source`, the record body, and reason make the rejection auditable. A strict replica MUST preserve this current behaviour.

## 7. Normalized storage layout

`ingest --out data/normalized` writes:

```text
data/normalized/entities.parquet
data/normalized/assets.parquet
data/normalized/alerts.parquet
data/normalized/cases.parquet
data/normalized/escalations.parquet
data/normalized/rejects.json
```

Parquet files use Snappy compression. CSV ingestion appends each accepted input batch as a parquet row group. This is important: later detection can scan a row group without reading all alerts.

The synthetic generator writes both CSV and parquet copies under its output path, plus `ground_truth`:

```text
data/synth/alerts.csv / alerts.parquet
data/synth/entities.csv / entities.parquet
data/synth/assets.csv / assets.parquet
data/synth/cases.csv / cases.parquet
data/synth/escalations.csv / escalations.parquet
data/synth/ground_truth.csv / ground_truth.parquet
```

Starting a synthetic generation deletes these named previous artifacts in that output directory before writing new artifacts. An interrupted generation can therefore leave a partial set; do not use it as a completed submission.
