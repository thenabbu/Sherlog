"""Reusable peer cohort statistics with no detector-specific state."""
from __future__ import annotations

import pandas as pd


def benchmark(df: pd.DataFrame, group_col: str, metric_col: str, peer_group_col: str) -> pd.DataFrame:
    """Attach group median/IQR and within-cohort percentile to every input row.

    ``group_col`` identifies the entity whose metric is being compared; duplicate entity
    rows are reduced to one median metric before peer statistics are calculated.
    """
    needed = {group_col, metric_col, peer_group_col}
    missing = needed - set(df.columns)
    if missing:
        raise ValueError(f"benchmark missing columns: {sorted(missing)}")
    base = df[[group_col, peer_group_col, metric_col]].dropna().copy()
    if base.empty:
        return pd.DataFrame(columns=[group_col, peer_group_col, metric_col, "peer_median", "q1", "q3", "iqr", "percentile_rank"])
    entities = base.groupby([group_col, peer_group_col], as_index=False)[metric_col].median()
    grouped = entities.groupby(peer_group_col)[metric_col]
    entities["peer_median"] = grouped.transform("median")
    entities["q1"] = grouped.transform(lambda series: series.quantile(0.25))
    entities["q3"] = grouped.transform(lambda series: series.quantile(0.75))
    entities["iqr"] = entities["q3"] - entities["q1"]
    entities["percentile_rank"] = entities.groupby(peer_group_col)[metric_col].rank(pct=True, method="average")
    return entities
