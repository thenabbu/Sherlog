from __future__ import annotations

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


def _case_index(cases: pd.DataFrame) -> dict:
    if cases is None or cases.empty:
        return {}
    return cases.set_index("case_id").to_dict("index")


def detect_ack_without_meaningful_investigation(alerts: pd.DataFrame, cases: pd.DataFrame) -> list[Flag]:
    """Acknowledged high-impact alerts linked to cases without root-cause evidence."""
    index = _case_index(cases)
    matches = alerts[(alerts["severity"].isin(["high", "critical"])) & alerts["first_ack_at"].notna() & alerts["case_id"].notna()]
    flags = []
    for _, row in matches.iterrows():
        case = index.get(row.case_id)
        if not case or bool(case.get("root_cause_documented")):
            continue
        flags.append(Flag(flag_id=_flag_number("ackinvest", len(flags) + 1), detector="ack_without_meaningful_investigation", entity_id=row.entity_id,
            severity_weight=2, rationale=f"High/critical alert {row.alert_id} was acknowledged, but its linked case lacks documented root-cause evidence.",
            evidence={"alert_ids": [row.alert_id], "case_ids": [row.case_id], "severity": row.severity, "first_ack_at": str(row.first_ack_at), "root_cause_documented": False}))
    return flags


def detect_investigation_closure_mismatch(alerts: pd.DataFrame, cases: pd.DataFrame) -> list[Flag]:
    index = _case_index(cases)
    matches = alerts[(alerts["severity"].isin(["high", "critical"])) & (alerts["disposition"] == "true_positive") & alerts["closed_at"].notna() & alerts["case_id"].notna()]
    flags = []
    for _, row in matches.iterrows():
        case = index.get(row.case_id)
        if not case or bool(case.get("root_cause_documented")):
            continue
        flags.append(Flag(flag_id=_flag_number("rootcause", len(flags) + 1), detector="investigation_closure_mismatch", entity_id=row.entity_id,
            severity_weight=2, rationale=f"True-positive {row.severity} alert {row.alert_id} was closed through a case without documented root cause.",
            evidence={"alert_ids": [row.alert_id], "case_ids": [row.case_id], "disposition": row.disposition, "closed_at": str(row.closed_at), "root_cause_documented": False}))
    return flags


def detect_high_risk_no_escalation(alerts: pd.DataFrame) -> list[Flag]:
    matches = alerts[(alerts["severity"] == "high") & (alerts["disposition"] == "true_positive") & (~alerts["escalated"].astype(bool))]
    flags = []
    for _, row in matches.iterrows():
        flags.append(Flag(flag_id=_flag_number("highnoesc", len(flags) + 1), detector="high_risk_no_escalation", entity_id=row.entity_id,
            severity_weight=2, rationale=f"High-severity true-positive alert {row.alert_id} has no recorded escalation.",
            evidence={"alert_ids": [row.alert_id], "severity": row.severity, "disposition": row.disposition, "escalated": False}))
    return flags


def case_duration_baselines(cases: pd.DataFrame, entities: pd.DataFrame) -> pd.DataFrame:
    if cases is None or cases.empty:
        return pd.DataFrame(columns=["peer_group", "q1", "iqr", "sample_size"])
    frame = cases.copy()
    frame["opened_at"] = pd.to_datetime(frame["opened_at"], utc=True)
    frame["closed_at"] = pd.to_datetime(frame["closed_at"], utc=True)
    frame = frame.dropna(subset=["closed_at"])
    frame["duration_minutes"] = (frame["closed_at"] - frame["opened_at"]).dt.total_seconds() / 60
    frame = frame.merge(entities[["entity_id", "peer_group"]], on="entity_id", how="left")
    if frame.empty:
        return pd.DataFrame(columns=["peer_group", "q1", "iqr", "sample_size"])
    return frame.groupby("peer_group")["duration_minutes"].agg(q1=lambda s: s.quantile(.25), q3=lambda s: s.quantile(.75), sample_size="size").assign(iqr=lambda x: x.q3 - x.q1).reset_index()[["peer_group", "q1", "iqr", "sample_size"]]


def detect_short_investigation(alerts: pd.DataFrame, cases: pd.DataFrame, entities: pd.DataFrame, k: float = 1.5, min_peer_sample: int = 4) -> list[Flag]:
    if cases is None or cases.empty:
        return []
    index = _case_index(cases)
    baselines = case_duration_baselines(cases, entities).set_index("peer_group").to_dict("index")
    entity_peer = entities.set_index("entity_id")["peer_group"].to_dict()
    matches = alerts[(alerts["severity"].isin(["high", "critical"])) & alerts["case_id"].notna()]
    flags = []
    for _, row in matches.iterrows():
        case = index.get(row.case_id)
        peer = entity_peer.get(row.entity_id)
        if not case or not case.get("closed_at") or peer not in baselines:
            continue
        base = baselines[peer]
        if base["sample_size"] < min_peer_sample:
            continue
        opened, closed = pd.to_datetime(case["opened_at"], utc=True), pd.to_datetime(case["closed_at"], utc=True)
        duration = (closed - opened).total_seconds() / 60
        threshold = float(base["q1"]) - k * float(base["iqr"])
        if duration < threshold:
            flags.append(Flag(flag_id=_flag_number("shortinv", len(flags) + 1), detector="short_investigation", entity_id=row.entity_id,
                severity_weight=2, rationale=f"Case {row.case_id} for {row.severity} alert {row.alert_id} closed in {_minutes(duration)}, below the peer investigation-duration fence.",
                evidence={"alert_ids": [row.alert_id], "case_ids": [row.case_id], "duration_minutes": round(duration, 3), "peer_q1_minutes": float(base["q1"]), "peer_iqr_minutes": float(base["iqr"]), "threshold_minutes": threshold, "peer_group": peer, "sample_size": int(base["sample_size"]) }))
    return flags


def detect_recurrence_without_root_cause(alerts: pd.DataFrame, cases: pd.DataFrame, min_alerts: int = 3) -> list[Flag]:
    if alerts.empty or "asset_id" not in alerts:
        return []
    index = _case_index(cases)
    frame = alerts.dropna(subset=["asset_id"]).copy()
    flags = []
    for (entity, asset), group in frame.groupby(["entity_id", "asset_id"]):
        if len(group) < min_alerts:
            continue
        case_ids = [str(x) for x in group["case_id"].dropna().tolist()]
        if any(bool(index.get(case_id, {}).get("root_cause_documented")) for case_id in case_ids):
            continue
        alert_ids = [str(x) for x in group["alert_id"].tolist()]
        flags.append(Flag(flag_id=_flag_number("recurrence", len(flags) + 1), detector="recurrence_without_root_cause", entity_id=entity,
            severity_weight=2, rationale=f"Asset {asset} generated {len(alert_ids)} repeated alerts without documented root-cause evidence in associated cases.",
            evidence={"alert_ids": alert_ids, "asset_ids": [asset], "case_ids": case_ids, "repeat_count": len(alert_ids), "minimum_repeat_count": min_alerts}))
    return flags


def detect_workload_severity_mismatch(alert_counts: pd.DataFrame, cases: pd.DataFrame, entities: pd.DataFrame, deviation_pct: float = .5, min_peer_sample: int = 4) -> list[Flag]:
    if alert_counts.empty:
        return []
    cases_by_entity = cases.groupby("entity_id").size() if cases is not None and not cases.empty else pd.Series(dtype=float)
    frame = entities[["entity_id", "peer_group"]].copy()
    frame["high_critical_tp"] = frame["entity_id"].map(alert_counts.set_index("entity_id")["high_critical_tp"]).fillna(0)
    frame["cases"] = frame["entity_id"].map(cases_by_entity).fillna(0)
    frame["ratio"] = frame["cases"] / frame["high_critical_tp"].replace(0, pd.NA)
    flags = []
    for _, row in frame.dropna(subset=["ratio"]).iterrows():
        peer = frame[frame["peer_group"] == row.peer_group]["ratio"].dropna()
        if len(peer) < min_peer_sample:
            continue
        median = float(peer.median())
        if median > 0 and float(row.ratio) < median * (1 - deviation_pct):
            flags.append(Flag(flag_id=_flag_number("workload", len(flags) + 1), detector="workload_severity_mismatch", entity_id=row.entity_id,
                severity_weight=2, rationale=f"High/critical true-positive workload for {row.entity_id} has a lower case-coverage ratio than its peer baseline.",
                evidence={"high_critical_true_positive_count": int(row.high_critical_tp), "case_count": int(row.cases), "entity_ratio": float(row.ratio), "peer_median_ratio": median, "deviation_pct": deviation_pct, "peer_group": row.peer_group, "peer_sample_size": len(peer)}))
    return flags
