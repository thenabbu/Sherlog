from __future__ import annotations

from datetime import datetime, timezone
from itertools import count

import pandas as pd

from sat_sa.schema import Flag


def _flag_number(prefix: str, index: int) -> str:
    return f"fg_{prefix}_{index:05d}"


def _minutes(value: float) -> str:
    return f"{value:.0f}m" if value < 60 else f"{value / 60:.1f}h"


def closure_baselines(alerts: pd.DataFrame) -> pd.DataFrame:
    closed = alerts.dropna(subset=["closed_at"]).copy()
    if closed.empty:
        return pd.DataFrame(columns=["severity", "q1", "iqr", "sample_size"])
    closed["created_at"] = pd.to_datetime(closed["created_at"], utc=True)
    closed["closed_at"] = pd.to_datetime(closed["closed_at"], utc=True)
    closed["time_to_close_minutes"] = (closed["closed_at"] - closed["created_at"]).dt.total_seconds() / 60
    grouped = closed.groupby("severity")["time_to_close_minutes"]
    return grouped.agg(q1=lambda s: s.quantile(.25), q3=lambda s: s.quantile(.75), sample_size="size").assign(iqr=lambda f: f.q3 - f.q1).reset_index()[["severity", "q1", "iqr", "sample_size"]]


def detect_fast_closure(alerts: pd.DataFrame, peer_stats: pd.DataFrame | None = None, k: float = 1.5) -> list[Flag]:
    """Find high/critical alerts that fall below severity-specific Tukey lower fences."""
    stats = peer_stats if peer_stats is not None else closure_baselines(alerts)
    lookup = stats.set_index("severity").to_dict("index") if not stats.empty else {}
    frame = alerts.dropna(subset=["closed_at"]).copy()
    if frame.empty:
        return []
    frame["created_at"] = pd.to_datetime(frame["created_at"], utc=True)
    frame["closed_at"] = pd.to_datetime(frame["closed_at"], utc=True)
    frame["time_to_close_minutes"] = (frame["closed_at"] - frame["created_at"]).dt.total_seconds() / 60
    flags: list[Flag] = []
    for idx, row in frame.iterrows():
        if row["severity"] not in {"critical", "high"} or row["severity"] not in lookup:
            continue
        baseline = lookup[row["severity"]]
        threshold = float(baseline["q1"]) - k * float(baseline["iqr"])
        if row.time_to_close_minutes < threshold:
            factor = float(baseline["q1"]) / max(float(row.time_to_close_minutes), 0.01)
            flags.append(Flag(flag_id=_flag_number("fast", len(flags) + 1), detector="fast_closure", entity_id=row.entity_id,
                severity_weight=2, rationale=(f"Alert {row.alert_id} (severity={row.severity}) closed in {_minutes(row.time_to_close_minutes)}, "
                f"vs baseline Q1 of {_minutes(float(baseline['q1']))} for this severity — {factor:.1f}x faster than typical."),
                evidence={"alert_ids": [row.alert_id], "observed_value": _minutes(row.time_to_close_minutes),
                "baseline_value": f"{_minutes(float(baseline['q1']))} (Q1)", "baseline_source": f"severity={row.severity}, n={int(baseline['sample_size'])} alerts",
                "time_to_close_minutes": round(float(row.time_to_close_minutes), 3), "baseline_q1_minutes": round(float(baseline["q1"]), 3), "baseline_iqr_minutes": round(float(baseline["iqr"]), 3)}))
    return flags


def detect_critical_no_escalation(alerts: pd.DataFrame) -> list[Flag]:
    matches = alerts[(alerts["severity"] == "critical") & (alerts["disposition"] == "true_positive") & (~alerts["escalated"].astype(bool))]
    flags: list[Flag] = []
    for _, row in matches.iterrows():
        flags.append(Flag(flag_id=_flag_number("noesc", len(flags) + 1), detector="no_escalation", entity_id=row.entity_id,
            severity_weight=3, rationale=f"Critical true-positive alert {row.alert_id} was closed without any recorded escalation.",
            evidence={"alert_ids": [row.alert_id], "disposition": row.disposition, "closed_at": str(row.closed_at), "escalated": False}))
    return flags
