"""Embed compact, JSON-safe source rows referenced by a finding for drill-down."""
from __future__ import annotations

import pandas as pd

from sat_sa.schema import Flag


def build_lookups(source_records: dict[str, pd.DataFrame]) -> dict[str, dict[str, dict]]:
    """Pre-build {id: row_dict} lookups for all source DataFrames.

    Call once per batch, then pass via ``_lookups`` in ``attach_evidence``.
    """
    lookups: dict[str, dict[str, dict]] = {}
    key_cols = {"alerts": "alert_id", "assets": "asset_id", "cases": "case_id",
                "escalations": "escalation_id"}
    for name, key_col in key_cols.items():
        df = source_records.get(name)
        if isinstance(df, pd.DataFrame) and not df.empty and key_col in df.columns:
            lookups[name] = {str(row[key_col]): row for row in df.to_dict("records")}
    return lookups


def attach_evidence(
    flag: Flag,
    source_records: dict[str, pd.DataFrame],
    _lookups: dict[str, dict[str, dict]] | None = None,
) -> Flag:
    """Embed compact, JSON-safe source rows referenced by a finding for drill-down.

    Parameters
    ----------
    _lookups : optional pre-built lookups from :func:`build_lookups`.
        When provided (same object across all flags in a batch), avoids
        rebuilding the DataFrame → dict conversion on every call.
    """
    evidence = dict(flag.evidence)
    rows: list[dict] = []
    # Use sorted lists (not sets) to guarantee deterministic source_rows order,
    # which is critical for reproducible pipeline output.
    alert_ids = sorted(set(evidence.get("alert_ids", [])))
    asset_ids = sorted(set(evidence.get("asset_ids", [])))
    case_ids = sorted(set(evidence.get("case_ids", [])))
    escalation_ids = sorted(set(evidence.get("escalation_ids", [])))
    if _lookups:
        if alert_ids and "alerts" in _lookups:
            alert_lookup = _lookups["alerts"]
            rows.extend(alert_lookup[str(aid)] for aid in alert_ids if str(aid) in alert_lookup)
        if asset_ids and "assets" in _lookups:
            asset_lookup = _lookups["assets"]
            rows.extend(asset_lookup[str(aid)] for aid in asset_ids if str(aid) in asset_lookup)
        if case_ids and "cases" in _lookups:
            case_lookup = _lookups["cases"]
            rows.extend(case_lookup[str(cid)] for cid in case_ids if str(cid) in case_lookup)
        if escalation_ids and "escalations" in _lookups:
            esc_lookup = _lookups["escalations"]
            rows.extend(esc_lookup[str(eid)] for eid in escalation_ids if str(eid) in esc_lookup)
    else:
        if alert_ids and "alerts" in source_records:
            lookup = {str(row["alert_id"]): row for row in source_records["alerts"].to_dict("records")}
            rows.extend(lookup[str(aid)] for aid in alert_ids if str(aid) in lookup)
        if asset_ids and "assets" in source_records:
            lookup = {str(row["asset_id"]): row for row in source_records["assets"].to_dict("records")}
            rows.extend(lookup[str(aid)] for aid in asset_ids if str(aid) in lookup)
        if case_ids and "cases" in source_records:
            lookup = {str(row["case_id"]): row for row in source_records["cases"].to_dict("records")}
            rows.extend(lookup[str(cid)] for cid in case_ids if str(cid) in lookup)
        if escalation_ids and "escalations" in source_records:
            lookup = {str(row["escalation_id"]): row for row in source_records["escalations"].to_dict("records")}
            rows.extend(lookup[str(eid)] for eid in escalation_ids if str(eid) in lookup)
    if rows:
        def json_safe(value):
            if hasattr(value, "isoformat"):
                return value.isoformat()
            if hasattr(value, "tolist"):
                return value.tolist()
            return value.item() if hasattr(value, "item") else value
        evidence["source_rows"] = [{key: json_safe(value) for key, value in row.items()} for row in rows]
    return flag.model_copy(update={"evidence": evidence})
