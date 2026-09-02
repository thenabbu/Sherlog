from __future__ import annotations

import pandas as pd

from sat_sa.peer import benchmark
from sat_sa.schema import Flag


def detect_low_critical_asset_coverage(alerts: pd.DataFrame, assets: pd.DataFrame, peer_stats: pd.DataFrame | None = None,
                                       window_days: int = 30, threshold_pct: float = .25) -> list[Flag]:
    """Detect critical assets whose recent observed alert count is unusually low in cohort."""
    critical = assets[assets["criticality"] == "critical"].copy()
    if critical.empty:
        return []
    if "peer_group" not in critical:
        critical["peer_group"] = "all"
    dates = pd.to_datetime(alerts.get("created_at", pd.Series(dtype="object")), utc=True)
    reference = dates.max() if not dates.empty else pd.Timestamp.now(tz="UTC")
    window_start = reference - pd.Timedelta(days=window_days)
    recent = alerts.copy()
    if not recent.empty:
        recent["created_at"] = pd.to_datetime(recent["created_at"], utc=True)
        recent = recent[(recent.created_at >= window_start) & (recent.created_at <= reference)]
        counts = recent.groupby(["entity_id", "asset_id"]).size().rename("observed_count").reset_index()
    else:
        counts = pd.DataFrame(columns=["entity_id", "asset_id", "observed_count"])
    return detect_low_critical_asset_coverage_from_counts(counts, critical, reference, peer_stats, window_days, threshold_pct)


def detect_low_critical_asset_coverage_from_counts(
    counts: pd.DataFrame,
    assets: pd.DataFrame,
    reference: pd.Timestamp,
    peer_stats: pd.DataFrame | None = None,
    window_days: int = 30,
    threshold_pct: float = .25,
) -> list[Flag]:
    """Coverage detector variant for streaming callers with pre-aggregated counts."""
    critical = assets[assets["criticality"] == "critical"].copy()
    if critical.empty:
        return []
    if "peer_group" not in critical:
        critical["peer_group"] = "all"
    coverage = critical.merge(counts, on=["entity_id", "asset_id"], how="left")
    coverage["observed_count"] = coverage["observed_count"].fillna(0).astype(int)
    stats = peer_stats if peer_stats is not None else benchmark(coverage, "asset_id", "observed_count", "peer_group")
    merged = coverage.merge(stats[["asset_id", "peer_median"]], on="asset_id", how="left")
    flags: list[Flag] = []
    for _, row in merged.iterrows():
        median = float(row.peer_median) if pd.notna(row.peer_median) else 0.0
        if median > 0 and float(row.observed_count) < threshold_pct * median:
            flags.append(Flag(flag_id=f"fg_coverage_{len(flags)+1:05d}", detector="low_coverage", entity_id=row.entity_id,
                severity_weight=2, rationale=(f"Critical asset {row.asset_id} generated {int(row.observed_count)} alerts in the last {window_days} days "
                f"vs a peer median of {median:.1f} — possible monitoring gap."),
                evidence={"asset_ids": [row.asset_id], "window_days": window_days, "observed_count": int(row.observed_count),
                "peer_median": median, "peer_group": row.peer_group, "threshold_pct": threshold_pct,
                "window_end": reference.isoformat()}))
    return flags
