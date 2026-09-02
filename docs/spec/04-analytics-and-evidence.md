# 04 — Analytics, evidence, and reporting contract

## 1. Common terms

All detector timestamps are converted with `pandas.to_datetime(..., utc=True)`. Durations are minutes as floating-point values. A detector emits one `Flag` per matching alert or asset.

## 2. D1: fast-closure execution gap

### Purpose

Find high- or critical-severity alerts that appear to have been closed extraordinarily quickly compared with the overall submission's closure distribution for that severity.

### Exact calculation

1. Select every alert with non-null `closed_at`.
2. Compute `time_to_close_minutes = (closed_at - created_at).total_seconds / 60`.
3. Group all closed alerts by `severity` (not peer group).
4. For each severity calculate `Q1`, `Q3`, `IQR = Q3 - Q1`, and count `n`.
5. Consider only `high` and `critical` alert records.
6. Emit a flag when:

```text
time_to_close_minutes < Q1(severity) - fast_closure_k × IQR(severity)
```

The default `fast_closure_k` is 1.5. Equality does not flag. The severity baseline includes all alert dispositions and all entities.

### Evidence

```json
{
  "alert_ids": ["AL-000001"],
  "observed_value": "2m",
  "baseline_value": "7.5h (Q1)",
  "baseline_source": "severity=high, n=40000 alerts",
  "time_to_close_minutes": 2.0,
  "baseline_q1_minutes": 450.0,
  "baseline_iqr_minutes": 58.0
}
```

The rationale is: `Alert {id} (severity={severity}) closed in {duration}, vs baseline Q1 of {q1} for this severity — {factor}x faster than typical.` The factor is `Q1 / max(observed_minutes, 0.01)`.

## 3. D2: critical true-positive without escalation

### Exact condition

```text
severity == "critical"
AND disposition == "true_positive"
AND escalated == false
```

No statistical baseline is used. `closed_at` is not part of the condition, despite being included in the evidence.

### Evidence and rationale

Evidence contains `alert_ids`, `disposition`, `closed_at` and `escalated: false`. Rationale: `Critical true-positive alert {id} was closed without any recorded escalation.`

## 4. D3: low critical-asset coverage (negative space)

### Exact calculation

1. Select assets where `criticality == "critical"`; join their entity's `peer_group`.
2. Find the greatest alert `created_at` across the entire submission. This is the reference time.
3. Count each alert for each `(entity_id, asset_id)` whose creation time falls in `[reference - window_days, reference]`.
4. Missing asset counts are set to zero.
5. For each peer group, compute the median observed count across that group's critical assets. The reusable `benchmark` function is called with `group_col="asset_id"`; because generated asset IDs are globally unique, each asset contributes one value to its peer group.
6. Flag a critical asset when:

```text
observed_count < coverage_threshold_pct × peer_median
```

Default window is 30 days and default threshold is 0.25. A zero peer median cannot flag an asset.

### Evidence and rationale

Evidence contains asset ID, `window_days`, observed count, peer median, peer group, threshold, and reference window end. Rationale: `Critical asset {asset_id} generated {count} alerts in the last {window} days vs a peer median of {median} — possible monitoring gap.`

## 5. Streaming detection implementation

Detection uses two scans of `alerts.parquet`.

1. **Pass 1:** count alerts per entity, find maximum creation time, and append all closure duration values by severity to temporary binary files. Quantiles are computed from memory-mapped float64 arrays after this pass.
2. **Pass 2:** run D1 and D2 per alert batch; attach the corresponding alert source row immediately. Count recent `(entity, asset)` observations for D3.
3. Run D3 after pass 2 from small aggregate counters and assets metadata; attach the corresponding asset source row.
4. Renumber all flags globally as `fg_00001`, `fg_00002`, and so on in detector execution order.

## 6. Generic peer benchmark function

`benchmark(df, group_col, metric_col, peer_group_col)` MUST:

1. retain the three named columns and remove nulls;
2. reduce duplicate `(group_col, peer_group_col)` values using their metric median;
3. calculate peer-group median, Q1, Q3, IQR and average-tie percentile rank;
4. return one row per group value with columns `group_col`, `peer_group_col`, metric, `peer_median`, `q1`, `q3`, `iqr`, and `percentile_rank`.

## 7. Flag JSON contract

Every flag serialises as:

```json
{
  "flag_id": "fg_00001",
  "detector": "fast_closure",
  "entity_id": "CSE-001",
  "severity_weight": 2.0,
  "rationale": "...",
  "evidence": {"...": "...", "source_rows": [{"...": "..."}]},
  "generated_at": "2026-08-30T00:00:00Z"
}
```

`source_rows` contains the source alert row for D1/D2 or source asset row for D3. Datetime-like source values are emitted as ISO strings. `flags.json` is a JSON array of these objects.

## 8. Scoring and ranking

Default weights are `fast_closure=2`, `no_escalation=3`, and `low_coverage=2`. For entity `e`:

```text
risk_score(e) = sum(weight(detector) × count_of_flags_for_detector) / log(1 + alert_volume(e))
```

If volume is zero, denominator correction is skipped and the score is the numerator. Sort descending by risk score, then descending by number of distinct detector types, then ascending `entity_id`. `priority_rank` is one-based sequential rank after this sort.

`entity_scores.csv` has: `entity_id`, `risk_score` (four decimal places), `priority_rank`, `flag_count_by_detector` (JSON object string), `distinct_detectors_triggered`, and `alert_volume`.

## 9. Report and validation

`report.json` has `generated_at`, `entities`, and `summary`. Each entity has its score, rank, and complete flag objects. Summary includes analysed entity count, total flag count, and detector counts.

Synthetic validation creates an exact key set for each detector: `(entity_id, alert_id)` for D1/D2, `(entity_id, asset_id)` for D3. It compares that to IDs stored in flag evidence. Precision is `TP / predicted`, recall is `TP / expected`, and F1 is `2PR / (P+R)`; zero denominators produce zero.
